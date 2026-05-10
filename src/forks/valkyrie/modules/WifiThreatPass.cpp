#include "WifiThreatPass.h"

#if defined(ARCH_ESP32) && defined(VALKYRIE_FORK)

#include "BleThreatDetectorModule.h"
#include "FlockOuiTable.h"
#include "WifiFrameClassifier.h"
#include "WifiThreatPassPolicy.h"
#include "configuration.h"
#include "prefs/ValkyriePrefs.h"

#if HAS_WIFI

#include <WiFi.h>
#include <esp_wifi.h>
#include <freertos/FreeRTOS.h>
#include <freertos/queue.h>

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

/// Duty pass classifies + emits threats. Heartbeat pass filters for one MAC and reports RSSI to the module.
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
/// Heartbeat-only: target MAC filter and locked channel (1/6/11; 0 = hop). Seen by promiscCb.
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

// --- Multi-SSID (Marauder-style): distinct SSID hashes per BSSID in one pass ---
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
    // here so the OSThread tick (drainQueue) can persist it even after we've hopped.
    uint8_t channel = (uint8_t)pkt->rx_ctrl.channel;

    uint8_t type = 0, subtype = 0;
    if (!wifi80211ParseFrameControl(frame, frameLen, &type, &subtype))
        return;

    uint8_t addr1[6], addr2[6], addr3[6];
    if (!wifi80211CopyAddr123(frame, frameLen, addr1, addr2, addr3))
        return;

    if (s_mode == WifiPassMode::Heartbeat) {
        // Match either Addr2 (TX) or Addr1 (RX); APs we hunt usually appear as Addr2,
        // but Addr1 catches frames targeted at the device when its MAC is parked there.
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

        if (!wifi80211IsBroadcastMac(addr1) && !wifi80211IsMulticastMac(addr1) && !wifi80211IsLocallyAdministeredMac(addr1) &&
            macMatchesFlockInfraOui(addr1)) {
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
        PendingWifiThreat p{};
        p.type_u8 = (uint8_t)ThreatType::WifiDeauth;
        memcpy(p.mac, addr2, 6);
        p.rssi = rssi;
        p.channel = channel;
        strncpy(p.detail, "deauth_or_disassoc", sizeof(p.detail) - 1);
        qSend(p);
    }

    if (s_prefs.isWifiThreatTypeEnabled(ThreatType::WifiEapol) && wifi80211DataHasEapol(frame, frameLen, nullptr)) {
        PendingWifiThreat p{};
        p.type_u8 = (uint8_t)ThreatType::WifiEapol;
        memcpy(p.mac, addr2, 6);
        p.rssi = rssi;
        p.channel = channel;
        strncpy(p.detail, "eapol_llc", sizeof(p.detail) - 1);
        qSend(p);
    }

    if (type == 0 && subtype == 8) {
        if (s_prefs.isWifiThreatTypeEnabled(ThreatType::WifiMultiSsid)) {
            char ssid[33]{};
            bool privacy = false;
            wifi80211BeaconExtractSsidAndPrivacy(frame, frameLen, ssid, sizeof(ssid), &privacy);
            size_t slen = strnlen(ssid, 32);
            uint16_t h = slen == 0 ? 0xFFFF : wifi80211HashSsidBytes(reinterpret_cast<const uint8_t *>(ssid), slen);
            msisFeed(addr2, h, rssi, channel);
        }

        if (s_prefs.isWifiThreatTypeEnabled(ThreatType::WifiPwnagotchi) && wifi80211BeaconLooksLikePwnagotchi(frame, frameLen)) {
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
            bool privacy = false;
            char ssidTmp[33]{};
            wifi80211BeaconExtractSsidAndPrivacy(frame, frameLen, ssidTmp, sizeof(ssidTmp), &privacy);
            if (wifi80211MacMatchesSuspiciousVendorOui(addr2, privacy, &vlab)) {
                PendingWifiThreat p{};
                p.type_u8 = (uint8_t)ThreatType::WifiSuspiciousAp;
                memcpy(p.mac, addr2, 6);
                p.rssi = rssi;
                p.channel = channel;
                if (vlab)
                    strncpy(p.detail, vlab, sizeof(p.detail) - 1);
                else
                    strncpy(p.detail, "suspicious_oui", sizeof(p.detail) - 1);
                strncpy(p.name, ssidTmp, sizeof(p.name) - 1);
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
    s_phase = (d.nextPhase == Phase::InitDisconnectWait) ? WifiPassPhase::InitDisconnectWait
                                                         : WifiPassPhase::InitModeStaWait;
    return true;
}

bool beginWifiHeartbeat(BleThreatDetectorModule *mod, const uint8_t targetMac[6], uint8_t lockChannel)
{
    if (!mod || !targetMac || s_phase != WifiPassPhase::Idle)
        return false;

    // Heartbeat does not require any threat-type prefs to be enabled (the user picked
    // a specific row to hunt). It still respects the master Wi‑Fi phase toggle so a
    // user who explicitly disabled the radio doesn't get it powered on behind their back.
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
    s_phase = (d.nextPhase == Phase::InitDisconnectWait) ? WifiPassPhase::InitDisconnectWait
                                                         : WifiPassPhase::InitModeStaWait;
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

bool isWifiHeartbeatActive()
{
    return s_phase != WifiPassPhase::Idle && s_mode == WifiPassMode::Heartbeat;
}

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
            // No mode restore here either; if init succeeded but
            // promiscuous failed, leaving STA up is consistent with the
            // hot-path invariant and avoids the leaky WIFI_OFF cycle.
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
        // Heartbeat ignores the duty time budget; the OSThread will call endWifiHeartbeat() on stop.
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
