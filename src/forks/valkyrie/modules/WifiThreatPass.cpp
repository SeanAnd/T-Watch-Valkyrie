#include "WifiThreatPass.h"

#if defined(ARCH_ESP32) && defined(VALKYRIE_FORK)

#include "BleThreatDetectorModule.h"
#include "FlockOuiTable.h"
#include "WifiFrameClassifier.h"
#include "WifiThreatPassPolicy.h"
#include "configuration.h"
#include "mesh/Throttle.h"
#include "prefs/ValkyriePrefs.h"

#if HAS_WIFI

#include <WiFi.h>
#include <esp_wifi.h>
#include <freertos/FreeRTOS.h>
#include <freertos/queue.h>

#include <cstdio>
#include <cstring>

#if HAS_SCREEN && defined(VALKYRIE_FORK)
#include "graphics/Screen.h"
#include "main.h"
#endif

namespace valkyrie
{

struct PendingWifiThreat {
    uint8_t type_u8;
    uint8_t mac[6];
    char name[32];
    int32_t rssi;
    char detail[48];
    uint8_t channel; // 1/6/11; 0 if unknown
};

static QueueHandle_t s_queue;
static BleThreatDetectorModule *s_mod;
static ValkyriePrefs s_prefs;

enum class WifiPassPhase : uint8_t {
    Idle,
    InitDisconnectWait,
    InitModeStaWait,
    Scan,
    TeardownWait,
};

/// Duty pass classifies + emits threats. Heartbeat pass filters for one MAC and
/// reports RSSI to the module.
enum class WifiPassMode : uint8_t {
    Duty,
    Heartbeat,
};

static constexpr uint32_t kDisconnectSettleMs = 10;
static constexpr uint32_t kStaModeSettleMs = 50;
static constexpr uint32_t kTeardownSettleMs = 20;
static constexpr uint8_t kCh[] = {1, 6, 11};

static WifiPassPhase s_phase = WifiPassPhase::Idle;
static WifiPassMode s_mode = WifiPassMode::Duty;
static uint32_t s_waitUntilMs = 0;
static uint32_t s_t0 = 0;
static uint32_t s_budgetMs = 0;
static uint8_t s_chIdx = 0;
static uint32_t s_hopEndMs = 0;
/// Heartbeat-only: target MAC filter and locked channel (1/6/11; 0 = hop). Seen
/// by promiscCb.
static uint8_t s_hbMac[6] = {0};
static uint8_t s_hbLockCh = 0;
// Sticky once true: arduino-esp32's WIFI_OFF path calls esp_wifi_deinit()
// internally, and each esp_wifi_init/deinit pair leaks ~48 bytes of
// ESP-IDF event-handler bookkeeping. We pay the WIFI_STA init cost on the
// first pass and then keep the *driver* alive between passes; the radio
// itself is powered down via esp_wifi_stop() at teardown and brought back
// up via esp_wifi_start() at the next hot-path begin to save the modem
// idle current (~15-20 mA) without re-init'ing. The cold/hot decision is
// formalised in WifiThreatPassPolicy.h and locked in by
// test_wifi_threat_pass_policy/test_main.cpp.
static bool s_wifiStaInitialised = false;
#if HAS_SCREEN && defined(VALKYRIE_FORK)
static uint32_t s_lastUiPumpMs = 0;
#endif

static bool qSend(const PendingWifiThreat &p)
{
    if (!s_queue)
        return false;
    return xQueueSend(s_queue, &p, 0) == pdTRUE;
}

static void drainQueue(BleThreatDetectorModule *mod)
{
    if (!mod || !s_queue)
        return;
    PendingWifiThreat it;
    while (xQueueReceive(s_queue, &it, 0) == pdTRUE) {
        ClassificationResult cr{};
        cr.type = static_cast<ThreatType>(it.type_u8);
        strncpy(cr.detail, it.detail, sizeof(cr.detail) - 1);
        cr.detail[sizeof(cr.detail) - 1] = '\0';
        mod->emitWifiThreat(cr, it.mac, it.name[0] ? it.name : nullptr, it.rssi, it.channel);
    }
}

// --- Multi-SSID (Marauder-style): distinct SSID hashes per BSSID in one pass
// ---
struct MsisSlot {
    uint8_t bssid[6];
    uint16_t hashes[6];
    uint8_t nhash;
    bool emitted;
};

static MsisSlot g_msis[16];
static int g_msisN;

static void msisReset()
{
    g_msisN = 0;
    memset(g_msis, 0, sizeof(g_msis));
}

static void msisFeed(const uint8_t bssid[6], uint16_t ssidHash, int8_t rssi, uint8_t channel)
{
    int idx = -1;
    for (int i = 0; i < g_msisN; ++i) {
        if (memcmp(g_msis[i].bssid, bssid, 6) == 0) {
            idx = i;
            break;
        }
    }
    if (idx < 0) {
        if (g_msisN >= (int)(sizeof(g_msis) / sizeof(g_msis[0])))
            return;
        idx = g_msisN++;
        memcpy(g_msis[idx].bssid, bssid, 6);
        g_msis[idx].hashes[0] = ssidHash;
        g_msis[idx].nhash = 1;
        return;
    }
    for (unsigned j = 0; j < g_msis[idx].nhash; ++j) {
        if (g_msis[idx].hashes[j] == ssidHash)
            return;
    }
    if (g_msis[idx].nhash >= sizeof(g_msis[idx].hashes) / sizeof(g_msis[idx].hashes[0]))
        return;
    g_msis[idx].hashes[g_msis[idx].nhash++] = ssidHash;
    if (g_msis[idx].nhash >= 2 && !g_msis[idx].emitted) {
        g_msis[idx].emitted = true;
        PendingWifiThreat p{};
        p.type_u8 = (uint8_t)ThreatType::WifiMultiSsid;
        memcpy(p.mac, bssid, 6);
        p.rssi = rssi;
        p.channel = channel;
        strncpy(p.detail, "multi_ssid_beacon", sizeof(p.detail) - 1);
        qSend(p);
    }
}

// --- False-positive guard: AP context + pair-aware burst state for
// deauth/EAPOL ---
static constexpr uint32_t kWifiDeauthBurstWindowMs = 2500;
static constexpr uint8_t kWifiDeauthBurstMinFrames = 3;
static constexpr uint8_t kWifiBroadcastDeauthBurstMinFrames = 2;
static constexpr uint32_t kWifiEapolBurstWindowMs = 5000;
static constexpr uint32_t kWifiEapolDeauthCorrelationMs = 7000;
static constexpr uint8_t kWifiEapolRepeatedMinFrames = 6;

static bool macEq(const uint8_t a[6], const uint8_t b[6]) { return a && b && memcmp(a, b, 6) == 0; }

static bool wifiMacIsUsableUnicast(const uint8_t mac[6])
{
    return mac && !wifi80211IsZeroMac(mac) && !wifi80211IsMulticastMac(mac);
}

struct WifiApContext {
    uint8_t bssid[6];
    char ssid[33];
    uint32_t lastSeenMs;
    uint8_t channel;
    bool used;
    bool hasSsid;
    bool privacyKnown;
    bool privacyOn;
};

static WifiApContext g_apCtx[16];
static uint8_t g_apCtxNext;

static void apContextReset()
{
    memset(g_apCtx, 0, sizeof(g_apCtx));
    g_apCtxNext = 0;
}

static WifiApContext *apContextFind(const uint8_t bssid[6])
{
    if (!bssid)
        return nullptr;
    for (WifiApContext &ctx : g_apCtx) {
        if (ctx.used && macEq(ctx.bssid, bssid))
            return &ctx;
    }
    return nullptr;
}

static void apContextFeed(const uint8_t bssid[6], const char *ssid, bool privacyOn, uint8_t channel)
{
    if (!wifiMacIsUsableUnicast(bssid))
        return;

    WifiApContext *ctx = apContextFind(bssid);
    if (!ctx) {
        ctx = &g_apCtx[g_apCtxNext];
        g_apCtxNext = static_cast<uint8_t>((g_apCtxNext + 1) % (sizeof(g_apCtx) / sizeof(g_apCtx[0])));
        memset(ctx, 0, sizeof(*ctx));
        memcpy(ctx->bssid, bssid, 6);
        ctx->used = true;
    }

    ctx->lastSeenMs = millis();
    ctx->channel = channel;
    ctx->privacyKnown = true;
    ctx->privacyOn = privacyOn;
    if (ssid && ssid[0]) {
        strncpy(ctx->ssid, ssid, sizeof(ctx->ssid) - 1);
        ctx->ssid[sizeof(ctx->ssid) - 1] = '\0';
        ctx->hasSsid = true;
    }
}

static void copyApName(PendingWifiThreat &p, const WifiApContext *ctx)
{
    if (!ctx || !ctx->hasSsid)
        return;
    strncpy(p.name, ctx->ssid, sizeof(p.name) - 1);
    p.name[sizeof(p.name) - 1] = '\0';
}

static void setWifiDetail(PendingWifiThreat &p, const char *base, const WifiApContext *ctx)
{
    if (ctx && ctx->privacyKnown)
        snprintf(p.detail, sizeof(p.detail), "%s_%s", base, ctx->privacyOn ? "priv" : "open");
    else
        strncpy(p.detail, base, sizeof(p.detail) - 1);
    p.detail[sizeof(p.detail) - 1] = '\0';
}

struct DeauthBurstSlot {
    uint8_t tx[6];
    uint8_t rx[6];
    uint8_t bssid[6];
    uint32_t firstMs;
    uint32_t lastMs;
    uint8_t count;
    uint8_t channel;
    int8_t rssi;
    bool used;
    bool emitted;
    bool receiverIsGroup;
    bool sawDeauth;
    bool sawDisassoc;
};

static DeauthBurstSlot g_deauthBurst[16];
static uint8_t g_deauthBurstNext;

static void deauthBurstReset()
{
    memset(g_deauthBurst, 0, sizeof(g_deauthBurst));
    g_deauthBurstNext = 0;
}

static DeauthBurstSlot *findOrAllocDeauthBurstSlot(const uint8_t tx[6], const uint8_t rx[6], const uint8_t bssid[6])
{
    for (DeauthBurstSlot &slot : g_deauthBurst) {
        if (slot.used && macEq(slot.tx, tx) && macEq(slot.rx, rx) && macEq(slot.bssid, bssid))
            return &slot;
    }

    DeauthBurstSlot *slot = &g_deauthBurst[g_deauthBurstNext];
    g_deauthBurstNext =
        static_cast<uint8_t>((g_deauthBurstNext + 1) % (sizeof(g_deauthBurst) / sizeof(g_deauthBurst[0])));
    memset(slot, 0, sizeof(*slot));
    memcpy(slot->tx, tx, 6);
    memcpy(slot->rx, rx, 6);
    memcpy(slot->bssid, bssid, 6);
    slot->used = true;
    return slot;
}

static uint8_t deauthMinFramesForSlot(const DeauthBurstSlot &slot)
{
    return slot.receiverIsGroup ? kWifiBroadcastDeauthBurstMinFrames : kWifiDeauthBurstMinFrames;
}

static bool deauthSlotIsBurst(const DeauthBurstSlot &slot)
{
    return slot.used && slot.count >= deauthMinFramesForSlot(slot);
}

static void feedDeauthBurst(const uint8_t rx[6], const uint8_t tx[6], const uint8_t bssid[6], uint8_t subtype,
                            int8_t rssi, uint8_t channel)
{
    if (!wifiMacIsUsableUnicast(tx))
        return;

    const bool receiverIsGroup = wifi80211IsBroadcastMac(rx) || wifi80211IsMulticastMac(rx);
    DeauthBurstSlot *slot = findOrAllocDeauthBurstSlot(tx, rx, bssid);
    if (!slot)
        return;

    const uint32_t now = millis();
    if (slot->firstMs == 0 || !Throttle::isWithinTimespanMs(slot->firstMs, kWifiDeauthBurstWindowMs)) {
        slot->firstMs = now;
        slot->count = 0;
        slot->emitted = false;
        slot->sawDeauth = false;
        slot->sawDisassoc = false;
    }

    if (slot->count < 255)
        ++slot->count;
    slot->lastMs = now;
    slot->receiverIsGroup = receiverIsGroup;
    slot->channel = channel;
    slot->rssi = rssi;
    if (subtype == 0x0C)
        slot->sawDeauth = true;
    if (subtype == 0x0A)
        slot->sawDisassoc = true;

    if (slot->emitted || !deauthSlotIsBurst(*slot))
        return;

    PendingWifiThreat p{};
    p.type_u8 = (uint8_t)ThreatType::WifiDeauth;
    memcpy(p.mac, tx, 6);
    p.rssi = rssi;
    p.channel = channel;
    const WifiApContext *ctx = apContextFind(bssid);
    copyApName(p, ctx);
    setWifiDetail(p, slot->sawDeauth ? "deauth_burst" : "disassoc_burst", ctx);
    slot->emitted = qSend(p);
}

struct EapolBurstSlot {
    uint8_t bssid[6];
    uint8_t station[6];
    uint32_t firstMs;
    uint32_t lastMs;
    uint8_t count;
    uint8_t phaseMask;
    uint8_t channel;
    int8_t rssi;
    bool used;
    bool emitted;
    bool deauthCorrelated;
};

static EapolBurstSlot g_eapolBurst[16];
static uint8_t g_eapolBurstNext;

static void eapolBurstReset()
{
    memset(g_eapolBurst, 0, sizeof(g_eapolBurst));
    g_eapolBurstNext = 0;
}

static EapolBurstSlot *findOrAllocEapolBurstSlot(const uint8_t bssid[6], const uint8_t station[6])
{
    for (EapolBurstSlot &slot : g_eapolBurst) {
        if (slot.used && macEq(slot.bssid, bssid) && macEq(slot.station, station))
            return &slot;
    }

    EapolBurstSlot *slot = &g_eapolBurst[g_eapolBurstNext];
    g_eapolBurstNext = static_cast<uint8_t>((g_eapolBurstNext + 1) % (sizeof(g_eapolBurst) / sizeof(g_eapolBurst[0])));
    memset(slot, 0, sizeof(*slot));
    memcpy(slot->bssid, bssid, 6);
    memcpy(slot->station, station, 6);
    slot->used = true;
    return slot;
}

static uint8_t eapolPhaseBit(WifiEapolKeyPhase phase)
{
    const uint8_t p = static_cast<uint8_t>(phase);
    return (p >= 1 && p <= 4) ? static_cast<uint8_t>(1u << (p - 1)) : 0;
}

static uint8_t countBits(uint8_t v)
{
    uint8_t n = 0;
    while (v) {
        n += v & 1u;
        v >>= 1;
    }
    return n;
}

static bool hasRecentDeauthBurstForPair(const uint8_t bssid[6], const uint8_t station[6])
{
    for (const DeauthBurstSlot &slot : g_deauthBurst) {
        if (!slot.used || !deauthSlotIsBurst(slot) ||
            !Throttle::isWithinTimespanMs(slot.lastMs, kWifiEapolDeauthCorrelationMs))
            continue;

        const bool bssidMatch = macEq(slot.bssid, bssid) || macEq(slot.tx, bssid);
        const bool stationMatch =
            macEq(slot.rx, station) || wifi80211IsBroadcastMac(slot.rx) || wifi80211IsMulticastMac(slot.rx);
        if (bssidMatch && stationMatch)
            return true;
    }
    return false;
}

static void feedEapolBurst(const WifiEapolInfo &info, const uint8_t bssid[6], const uint8_t station[6], int8_t rssi,
                           uint8_t channel)
{
    const uint8_t phaseBit = eapolPhaseBit(info.phase);
    if (phaseBit == 0 || !wifiMacIsUsableUnicast(bssid) || !wifiMacIsUsableUnicast(station))
        return;

    EapolBurstSlot *slot = findOrAllocEapolBurstSlot(bssid, station);
    if (!slot)
        return;

    const uint32_t now = millis();
    if (slot->firstMs == 0 || !Throttle::isWithinTimespanMs(slot->firstMs, kWifiEapolBurstWindowMs)) {
        slot->firstMs = now;
        slot->count = 0;
        slot->phaseMask = 0;
        slot->emitted = false;
        slot->deauthCorrelated = false;
    }

    if (slot->count < 255)
        ++slot->count;
    slot->phaseMask |= phaseBit;
    slot->lastMs = now;
    slot->channel = channel;
    slot->rssi = rssi;
    slot->deauthCorrelated = slot->deauthCorrelated || hasRecentDeauthBurstForPair(bssid, station);

    const uint8_t distinctPhases = countBits(slot->phaseMask);
    const bool repeatedHandshake = slot->count >= kWifiEapolRepeatedMinFrames && distinctPhases >= 2;
    if (slot->emitted || (!slot->deauthCorrelated && !repeatedHandshake))
        return;

    PendingWifiThreat p{};
    p.type_u8 = (uint8_t)ThreatType::WifiEapol;
    memcpy(p.mac, bssid, 6);
    p.rssi = rssi;
    p.channel = channel;
    const WifiApContext *ctx = apContextFind(bssid);
    copyApName(p, ctx);
    setWifiDetail(p, slot->deauthCorrelated ? "eapol_after_deauth" : "eapol_key_burst", ctx);
    slot->emitted = qSend(p);
}

static void promiscCb(void *buf, wifi_promiscuous_pkt_type_t pktType)
{
    if (!buf || !s_mod)
        return;
    if (pktType != WIFI_PKT_MGMT && pktType != WIFI_PKT_DATA)
        return;

    auto *pkt = static_cast<wifi_promiscuous_pkt_t *>(buf);
    unsigned len = pkt->rx_ctrl.sig_len;
    if (len <= 28)
        return;
    size_t frameLen = len >= 4 ? (size_t)len - 4 : 0;
    const uint8_t *frame = pkt->payload;
    int8_t rssi = (int8_t)pkt->rx_ctrl.rssi;
    // rx_ctrl.channel is the radio's primary channel at receive time. Capture
    // here so the OSThread tick (drainQueue) can persist it even after we've
    // hopped.
    uint8_t channel = (uint8_t)pkt->rx_ctrl.channel;

    uint8_t type = 0, subtype = 0;
    if (!wifi80211ParseFrameControl(frame, frameLen, &type, &subtype))
        return;

    uint8_t addr1[6], addr2[6], addr3[6];
    if (!wifi80211CopyAddr123(frame, frameLen, addr1, addr2, addr3))
        return;

    if (s_mode == WifiPassMode::Heartbeat) {
        // Match either Addr2 (TX) or Addr1 (RX); APs we hunt usually appear as
        // Addr2, but Addr1 catches frames targeted at the device when its MAC is
        // parked there.
        if (memcmp(addr2, s_hbMac, 6) == 0 || memcmp(addr1, s_hbMac, 6) == 0)
            s_mod->onWifiHeartbeatFrame(s_hbMac, channel, rssi);
        return;
    }

    if (type == 0 && s_prefs.isThreatTypeEnabled(ThreatType::Drone)) {
        const bool nanHit = wifi80211MgmtRemoteIdNanSignature(frame, frameLen);
        const bool beaconIe = (subtype == 8) && wifi80211BeaconHasRemoteIdVendorIe(frame, frameLen);
        if (nanHit || beaconIe) {
            PendingWifiThreat p{};
            p.type_u8 = (uint8_t)ThreatType::Drone;
            memcpy(p.mac, addr2, 6);
            p.rssi = rssi;
            p.channel = channel;
            if (nanHit)
                strncpy(p.detail, "wifi_nan", sizeof(p.detail) - 1);
            else
                strncpy(p.detail, "wifi_beacon_ie", sizeof(p.detail) - 1);
            qSend(p);
        }
    }

    if (s_prefs.isThreatTypeEnabled(ThreatType::Flock)) {
        uint8_t t0 = 0, st0 = 0;
        wifi80211ParseFrameControl(frame, frameLen, &t0, &st0);
        const bool isProbe = (t0 == 0 && st0 == 4);
        const bool flockAddr2 = macMatchesFlockInfraOui(addr2);

        if (isProbe && flockAddr2 && wifi80211IsWildcardProbeRequest(frame, frameLen)) {
            PendingWifiThreat p{};
            p.type_u8 = (uint8_t)ThreatType::Flock;
            memcpy(p.mac, addr2, 6);
            p.rssi = rssi;
            p.channel = channel;
            strncpy(p.detail, "wifi_wildcard_probe", sizeof(p.detail) - 1);
            qSend(p);
        } else if (flockAddr2) {
            PendingWifiThreat p{};
            p.type_u8 = (uint8_t)ThreatType::Flock;
            memcpy(p.mac, addr2, 6);
            p.rssi = rssi;
            p.channel = channel;
            strncpy(p.detail, "wifi_oui_addr2", sizeof(p.detail) - 1);
            qSend(p);
        }

        if (!wifi80211IsBroadcastMac(addr1) && !wifi80211IsMulticastMac(addr1) &&
            !wifi80211IsLocallyAdministeredMac(addr1) && macMatchesFlockInfraOui(addr1)) {
            PendingWifiThreat p{};
            p.type_u8 = (uint8_t)ThreatType::Flock;
            memcpy(p.mac, addr1, 6);
            p.rssi = rssi;
            p.channel = channel;
            strncpy(p.detail, "wifi_oui_addr1", sizeof(p.detail) - 1);
            qSend(p);
        }
    }

    if (s_prefs.isWifiThreatTypeEnabled(ThreatType::WifiDeauth) && wifi80211MgmtIsDeauthDisassoc(frame, frameLen)) {
        feedDeauthBurst(addr1, addr2, addr3, subtype, rssi, channel);
    }

    if (s_prefs.isWifiThreatTypeEnabled(ThreatType::WifiEapol)) {
        WifiEapolInfo eapol{};
        uint8_t bssid[6], station[6];
        if (wifi80211DataExtractEapolInfo(frame, frameLen, &eapol) &&
            wifi80211DataExtractBssidStation(frame, frameLen, bssid, station)) {
            feedEapolBurst(eapol, bssid, station, rssi, channel);
        }
    }

    if (type == 0 && subtype == 8) {
        char ssid[33]{};
        bool privacy = false;
        const bool beaconParsed = wifi80211BeaconExtractSsidAndPrivacy(frame, frameLen, ssid, sizeof(ssid), &privacy);
        if (beaconParsed)
            apContextFeed(addr2, ssid, privacy, channel);

        if (s_prefs.isWifiThreatTypeEnabled(ThreatType::WifiMultiSsid)) {
            size_t slen = strnlen(ssid, 32);
            uint16_t h = slen == 0 ? 0xFFFF : wifi80211HashSsidBytes(reinterpret_cast<const uint8_t *>(ssid), slen);
            msisFeed(addr2, h, rssi, channel);
        }

        if (s_prefs.isWifiThreatTypeEnabled(ThreatType::WifiPwnagotchi) &&
            wifi80211BeaconLooksLikePwnagotchi(frame, frameLen)) {
            PendingWifiThreat p{};
            p.type_u8 = (uint8_t)ThreatType::WifiPwnagotchi;
            memcpy(p.mac, addr2, 6);
            p.rssi = rssi;
            p.channel = channel;
            strncpy(p.detail, "beacon_json_heuristic", sizeof(p.detail) - 1);
            qSend(p);
        }

        if (s_prefs.isWifiThreatTypeEnabled(ThreatType::WifiSuspiciousAp)) {
            const char *vlab = nullptr;
            const bool privacyForVendor = beaconParsed ? privacy : true;
            if (wifi80211MacMatchesSuspiciousVendorOui(addr2, privacyForVendor, &vlab)) {
                PendingWifiThreat p{};
                p.type_u8 = (uint8_t)ThreatType::WifiSuspiciousAp;
                memcpy(p.mac, addr2, 6);
                p.rssi = rssi;
                p.channel = channel;
                if (vlab)
                    strncpy(p.detail, vlab, sizeof(p.detail) - 1);
                else
                    strncpy(p.detail, "suspicious_oui", sizeof(p.detail) - 1);
                strncpy(p.name, ssid, sizeof(p.name) - 1);
                qSend(p);
            }
        }
    }
}

static void resetPassMachine()
{
    s_phase = WifiPassPhase::Idle;
    s_mode = WifiPassMode::Duty;
    s_mod = nullptr;
    s_hbLockCh = 0;
    memset(s_hbMac, 0, sizeof(s_hbMac));
}

static void finishTeardownAndIdle(BleThreatDetectorModule *mod)
{
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(nullptr);
    drainQueue(mod);
    // Deliberately do NOT call WiFi.mode(...) here. Cycling back through
    // WIFI_OFF and back to WIFI_STA on the next pass leaks ~48 bytes per
    // cycle (see s_wifiStaInitialised comment). Power the modem down via
    // esp_wifi_stop() instead; driver state and event handlers are kept,
    // so esp_wifi_start() on the next pass is a clean restart.
    esp_wifi_stop();
    s_waitUntilMs = millis() + kTeardownSettleMs;
    s_phase = WifiPassPhase::TeardownWait;
}

void abortWifiThreatPass()
{
    if (s_phase == WifiPassPhase::Idle)
        return;

    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(nullptr);
    if (s_mod)
        drainQueue(s_mod);
    // Same rationale as finishTeardownAndIdle: stay in STA, do not toggle
    // WIFI_OFF, to avoid the per-cycle arduino-esp32 init/deinit leak.
    // Power the modem down via stop() so the driver can be re-started
    // cleanly by the next pass.
    esp_wifi_stop();
    resetPassMachine();
}

bool beginWifiThreatPass(BleThreatDetectorModule *mod)
{
    if (!mod || s_phase != WifiPassPhase::Idle)
        return false;

    ValkyriePrefs prefs = ValkyriePrefs::load();

    bool wantAnyWifi = false;
    for (unsigned u = 7; u <= 11; ++u) {
        if (prefs.isWifiThreatTypeEnabled(static_cast<ThreatType>((uint8_t)u))) {
            wantAnyWifi = true;
            break;
        }
    }
    const bool flockEn = prefs.isThreatTypeEnabled(ThreatType::Flock);
    const bool droneEn = prefs.isThreatTypeEnabled(ThreatType::Drone);

    if (!prefs.wifiThreatPhaseEnabled)
        return false;
    if (!wantAnyWifi && !flockEn && !droneEn)
        return false;

    if (!s_queue) {
        s_queue = xQueueCreate(48, sizeof(PendingWifiThreat));
        if (!s_queue) {
            LOG_WARN("Valkyrie: WiFi threat queue alloc failed");
            return false;
        }
    }

    s_mod = mod;
    s_mode = WifiPassMode::Duty;
    s_prefs = prefs;
    msisReset();
    apContextReset();
    deauthBurstReset();
    eapolBurstReset();
    while (uxQueueMessagesWaiting(s_queue) > 0) {
        PendingWifiThreat dump;
        xQueueReceive(s_queue, &dump, 0);
    }

    using wifi_threat_pass_policy::BeginDecision;
    using wifi_threat_pass_policy::decideBegin;
    using wifi_threat_pass_policy::Phase;

    const BeginDecision d = decideBegin(s_wifiStaInitialised);
    if (d.needWifiDisconnect) {
        // Cold path: drop any existing AP association without forcing
        // WIFI_OFF (disconnect(true) is what triggers the leaky deinit).
        WiFi.disconnect(false);
        s_waitUntilMs = millis() + kDisconnectSettleMs;
    } else {
        // Hot path: WiFi driver still in STA, but the modem was powered
        // down via esp_wifi_stop() at the previous teardown. Bring the
        // radio back up and use the same settle window the cold path
        // uses for WiFi.mode(WIFI_STA).
        esp_wifi_start();
        s_waitUntilMs = millis() + kStaModeSettleMs;
    }
    s_phase =
        (d.nextPhase == Phase::InitDisconnectWait) ? WifiPassPhase::InitDisconnectWait : WifiPassPhase::InitModeStaWait;
    return true;
}

bool beginWifiHeartbeat(BleThreatDetectorModule *mod, const uint8_t targetMac[6], uint8_t lockChannel)
{
    if (!mod || !targetMac || s_phase != WifiPassPhase::Idle)
        return false;

    // Heartbeat does not require any threat-type prefs to be enabled (the user
    // picked a specific row to hunt). It still respects the master Wi‑Fi phase
    // toggle so a user who explicitly disabled the radio doesn't get it powered
    // on behind their back.
    ValkyriePrefs prefs = ValkyriePrefs::load();
    if (!prefs.wifiThreatPhaseEnabled)
        return false;

    s_mod = mod;
    s_mode = WifiPassMode::Heartbeat;
    s_prefs = prefs;
    memcpy(s_hbMac, targetMac, 6);
    s_hbLockCh = (lockChannel == 1 || lockChannel == 6 || lockChannel == 11) ? lockChannel : 0;

    using wifi_threat_pass_policy::BeginDecision;
    using wifi_threat_pass_policy::decideBegin;
    using wifi_threat_pass_policy::Phase;

    const BeginDecision d = decideBegin(s_wifiStaInitialised);
    if (d.needWifiDisconnect) {
        WiFi.disconnect(false);
        s_waitUntilMs = millis() + kDisconnectSettleMs;
    } else {
        esp_wifi_start();
        s_waitUntilMs = millis() + kStaModeSettleMs;
    }
    s_phase =
        (d.nextPhase == Phase::InitDisconnectWait) ? WifiPassPhase::InitDisconnectWait : WifiPassPhase::InitModeStaWait;
    LOG_INFO("Valkyrie: WiFi heartbeat starting (lock_ch=%u)", (unsigned)s_hbLockCh);
    return true;
}

void endWifiHeartbeat()
{
    if (s_phase == WifiPassPhase::Idle || s_mode != WifiPassMode::Heartbeat)
        return;

    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(nullptr);
    // Power the modem down but keep the driver initialised (cold/hot policy).
    esp_wifi_stop();
    resetPassMachine();
    LOG_INFO("Valkyrie: WiFi heartbeat ended");
}

bool isWifiHeartbeatActive() { return s_phase != WifiPassPhase::Idle && s_mode == WifiPassMode::Heartbeat; }

bool tickWifiThreatPass(BleThreatDetectorModule *mod)
{
    const uint32_t now = millis();

    if (s_phase == WifiPassPhase::Idle)
        return true;

    if (!mod || mod != s_mod) {
        abortWifiThreatPass();
        return true;
    }

    switch (s_phase) {
    case WifiPassPhase::InitDisconnectWait:
        if ((int32_t)(now - s_waitUntilMs) < 0)
            return false;
        WiFi.mode(WIFI_STA);
        s_wifiStaInitialised = true;
        s_waitUntilMs = now + kStaModeSettleMs;
        s_phase = WifiPassPhase::InitModeStaWait;
        return false;

    case WifiPassPhase::InitModeStaWait:
        if ((int32_t)(now - s_waitUntilMs) < 0)
            return false;
        esp_wifi_set_promiscuous_rx_cb(&promiscCb);
        if (esp_wifi_set_promiscuous(true) != ESP_OK) {
            LOG_WARN("Valkyrie: esp_wifi_set_promiscuous(true) failed");
            // Balance the esp_wifi_start() (hot path) / WiFi.mode(WIFI_STA)
            // (cold path) that already powered the modem up for this pass.
            // Bailing out via resetPassMachine() alone would leave the radio
            // running, and the next pass's begin() hot-path esp_wifi_start()
            // would then double-start an already-started driver every cycle.
            // Clear the rx cb and stop the modem so start/stop stays balanced.
            // No WIFI_OFF cycle (that path is the leaky one); just stop().
            esp_wifi_set_promiscuous_rx_cb(nullptr);
            esp_wifi_stop();
            resetPassMachine();
            return true;
        }
        s_t0 = now;
        s_budgetMs = s_prefs.wifiThreatPassMs;
        if (s_mode == WifiPassMode::Heartbeat && s_hbLockCh != 0) {
            // Lock once and skip the hop tick so RSSI updates aren't gapped by hops.
            esp_wifi_set_channel(s_hbLockCh, WIFI_SECOND_CHAN_NONE);
            s_chIdx = 0;
            s_hopEndMs = (uint32_t)-1; // never hop
        } else {
            s_chIdx = 0;
            esp_wifi_set_channel(kCh[0], WIFI_SECOND_CHAN_NONE);
            s_hopEndMs = now + s_prefs.wifiThreatChannelDwellMs;
        }
        s_phase = WifiPassPhase::Scan;
#if HAS_SCREEN && defined(VALKYRIE_FORK)
        s_lastUiPumpMs = now;
        if (screen)
            screen->repaintFrameNow();
#endif
        return false;

    case WifiPassPhase::Scan: {
        // Heartbeat ignores the duty time budget; the OSThread will call
        // endWifiHeartbeat() on stop.
        if (s_mode == WifiPassMode::Duty && now - s_t0 >= s_budgetMs) {
            finishTeardownAndIdle(mod);
            return false;
        }
        if (s_mode == WifiPassMode::Duty)
            drainQueue(mod);
#if HAS_SCREEN && defined(VALKYRIE_FORK)
        if (screen && now - s_lastUiPumpMs >= 50) {
            s_lastUiPumpMs = now;
            screen->repaintFrameNow();
        }
#endif
        if (s_hopEndMs != (uint32_t)-1 && now >= s_hopEndMs) {
            s_chIdx = static_cast<uint8_t>((s_chIdx + 1) % (sizeof(kCh) / sizeof(kCh[0])));
            esp_wifi_set_channel(kCh[s_chIdx], WIFI_SECOND_CHAN_NONE);
            s_hopEndMs = now + s_prefs.wifiThreatChannelDwellMs;
        }
        return false;
    }

    case WifiPassPhase::TeardownWait:
        if ((int32_t)(now - s_waitUntilMs) < 0)
            return false;
        resetPassMachine();
        LOG_DEBUG("Valkyrie: WiFi threat pass complete");
        return true;

    default:
        resetPassMachine();
        return true;
    }
}

bool tickWifiHeartbeat(BleThreatDetectorModule *mod)
{
    // Heartbeat shares the duty state machine for cold/hot bring-up; the
    // s_mode flag distinguishes Scan-phase behavior. Heartbeat never reports
    // "complete" — endWifiHeartbeat() is the only exit.
    if (s_phase == WifiPassPhase::Idle || s_mode != WifiPassMode::Heartbeat)
        return false;
    (void)tickWifiThreatPass(mod);
    return false;
}

} // namespace valkyrie

#else // !HAS_WIFI

namespace valkyrie
{
bool beginWifiThreatPass(BleThreatDetectorModule *) { return false; }
bool tickWifiThreatPass(BleThreatDetectorModule *) { return true; }
void abortWifiThreatPass() {}
bool beginWifiHeartbeat(BleThreatDetectorModule *, const uint8_t *, uint8_t) { return false; }
bool tickWifiHeartbeat(BleThreatDetectorModule *) { return false; }
void endWifiHeartbeat() {}
bool isWifiHeartbeatActive() { return false; }
} // namespace valkyrie

#endif // HAS_WIFI

#endif // ARCH_ESP32 && VALKYRIE_FORK
