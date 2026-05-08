#include "WifiThreatPass.h"

#if defined(ARCH_ESP32) && defined(VALKYRIE_FORK)

#include "BleThreatDetectorModule.h"
#include "FlockOuiTable.h"
#include "WifiFrameClassifier.h"
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

namespace
{

struct PendingWifiThreat {
    uint8_t type_u8;
    uint8_t mac[6];
    char name[32];
    int32_t rssi;
    char detail[48];
};

static QueueHandle_t s_queue;
static BleThreatDetectorModule *s_mod;
static ValkyriePrefs s_prefs;

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
        mod->emitWifiThreat(cr, it.mac, it.name[0] ? it.name : nullptr, it.rssi);
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

static void msisFeed(const uint8_t bssid[6], uint16_t ssidHash, int8_t rssi)
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

    uint8_t type = 0, subtype = 0;
    if (!wifi80211ParseFrameControl(frame, frameLen, &type, &subtype))
        return;

    uint8_t addr1[6], addr2[6], addr3[6];
    if (!wifi80211CopyAddr123(frame, frameLen, addr1, addr2, addr3))
        return;

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
            strncpy(p.detail, "wifi_wildcard_probe", sizeof(p.detail) - 1);
            qSend(p);
        } else if (flockAddr2) {
            PendingWifiThreat p{};
            p.type_u8 = (uint8_t)ThreatType::Flock;
            memcpy(p.mac, addr2, 6);
            p.rssi = rssi;
            strncpy(p.detail, "wifi_oui_addr2", sizeof(p.detail) - 1);
            qSend(p);
        }

        if (!wifi80211IsBroadcastMac(addr1) && !wifi80211IsMulticastMac(addr1) && !wifi80211IsLocallyAdministeredMac(addr1) &&
            macMatchesFlockInfraOui(addr1)) {
            PendingWifiThreat p{};
            p.type_u8 = (uint8_t)ThreatType::Flock;
            memcpy(p.mac, addr1, 6);
            p.rssi = rssi;
            strncpy(p.detail, "wifi_oui_addr1", sizeof(p.detail) - 1);
            qSend(p);
        }
    }

    if (s_prefs.isWifiThreatTypeEnabled(ThreatType::WifiDeauth) && wifi80211MgmtIsDeauthDisassoc(frame, frameLen)) {
        PendingWifiThreat p{};
        p.type_u8 = (uint8_t)ThreatType::WifiDeauth;
        memcpy(p.mac, addr2, 6);
        p.rssi = rssi;
        strncpy(p.detail, "deauth_or_disassoc", sizeof(p.detail) - 1);
        qSend(p);
    }

    if (s_prefs.isWifiThreatTypeEnabled(ThreatType::WifiEapol) && wifi80211DataHasEapol(frame, frameLen, nullptr)) {
        PendingWifiThreat p{};
        p.type_u8 = (uint8_t)ThreatType::WifiEapol;
        memcpy(p.mac, addr2, 6);
        p.rssi = rssi;
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
            msisFeed(addr2, h, rssi);
        }

        if (s_prefs.isWifiThreatTypeEnabled(ThreatType::WifiPwnagotchi) && wifi80211BeaconLooksLikePwnagotchi(frame, frameLen)) {
            PendingWifiThreat p{};
            p.type_u8 = (uint8_t)ThreatType::WifiPwnagotchi;
            memcpy(p.mac, addr2, 6);
            p.rssi = rssi;
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

enum class WifiPassPhase : uint8_t {
    Idle,
    InitDisconnectWait,
    InitModeStaWait,
    Scan,
    TeardownWait,
};

static constexpr uint32_t kDisconnectSettleMs = 10;
static constexpr uint32_t kStaModeSettleMs = 50;
static constexpr uint32_t kTeardownSettleMs = 20;
static constexpr uint8_t kCh[] = {1, 6, 11};

static WifiPassPhase s_phase = WifiPassPhase::Idle;
static uint32_t s_waitUntilMs = 0;
static wifi_mode_t s_savedMode = WIFI_OFF;
static uint32_t s_t0 = 0;
static uint32_t s_budgetMs = 0;
static uint8_t s_chIdx = 0;
static uint32_t s_hopEndMs = 0;
#if HAS_SCREEN && defined(VALKYRIE_FORK)
static uint32_t s_lastUiPumpMs = 0;
#endif

static void resetPassMachine()
{
    s_phase = WifiPassPhase::Idle;
    s_mod = nullptr;
}

static void finishTeardownAndIdle(BleThreatDetectorModule *mod)
{
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(nullptr);
    drainQueue(mod);
    WiFi.mode(s_savedMode);
    s_waitUntilMs = millis() + kTeardownSettleMs;
    s_phase = WifiPassPhase::TeardownWait;
}

} // namespace

void abortWifiThreatPass()
{
    if (s_phase == WifiPassPhase::Idle)
        return;

    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(nullptr);
    if (s_mod)
        drainQueue(s_mod);
    WiFi.mode(s_savedMode);
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

    if (!prefs.wifiThreatPhaseEnabled)
        return false;
    if (!wantAnyWifi && !flockEn)
        return false;

    if (!s_queue) {
        s_queue = xQueueCreate(48, sizeof(PendingWifiThreat));
        if (!s_queue) {
            LOG_WARN("Valkyrie: WiFi threat queue alloc failed");
            return false;
        }
    }

    s_mod = mod;
    s_prefs = prefs;
    msisReset();
    while (uxQueueMessagesWaiting(s_queue) > 0) {
        PendingWifiThreat dump;
        xQueueReceive(s_queue, &dump, 0);
    }

    s_savedMode = WiFi.getMode();
    WiFi.disconnect(true);
    s_waitUntilMs = millis() + kDisconnectSettleMs;
    s_phase = WifiPassPhase::InitDisconnectWait;
    return true;
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
        s_waitUntilMs = now + kStaModeSettleMs;
        s_phase = WifiPassPhase::InitModeStaWait;
        return false;

    case WifiPassPhase::InitModeStaWait:
        if ((int32_t)(now - s_waitUntilMs) < 0)
            return false;
        esp_wifi_set_promiscuous_rx_cb(&promiscCb);
        if (esp_wifi_set_promiscuous(true) != ESP_OK) {
            LOG_WARN("Valkyrie: esp_wifi_set_promiscuous(true) failed");
            WiFi.mode(s_savedMode);
            resetPassMachine();
            return true;
        }
        s_t0 = now;
        s_budgetMs = s_prefs.wifiThreatPassMs;
        s_chIdx = 0;
        esp_wifi_set_channel(kCh[0], WIFI_SECOND_CHAN_NONE);
        s_hopEndMs = now + s_prefs.wifiThreatChannelDwellMs;
        s_phase = WifiPassPhase::Scan;
#if HAS_SCREEN && defined(VALKYRIE_FORK)
        s_lastUiPumpMs = now;
        if (screen)
            screen->repaintFrameNow();
#endif
        return false;

    case WifiPassPhase::Scan: {
        if (now - s_t0 >= s_budgetMs) {
            finishTeardownAndIdle(mod);
            return false;
        }
        drainQueue(mod);
#if HAS_SCREEN && defined(VALKYRIE_FORK)
        if (screen && now - s_lastUiPumpMs >= 50) {
            s_lastUiPumpMs = now;
            screen->repaintFrameNow();
        }
#endif
        if (now >= s_hopEndMs) {
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

} // namespace valkyrie

#else // !HAS_WIFI

namespace valkyrie
{
bool beginWifiThreatPass(BleThreatDetectorModule *) { return false; }
bool tickWifiThreatPass(BleThreatDetectorModule *) { return true; }
void abortWifiThreatPass() {}
} // namespace valkyrie

#endif // HAS_WIFI

#endif // ARCH_ESP32 && VALKYRIE_FORK
