#include "BleThreatDetectorModule.h"

#if defined(ARCH_ESP32) && defined(VALKYRIE_FORK)

#include "HubThreatAnimTiming.h"
#include "WifiThreatPass.h"
#include "../HeartbeatRssiFilter.h"
#include "AirtagStalkingState.h"
#include "BleScanSchedule.h"
#include "GeoStalking.h"
#include "../ThreatTypeUi.h"
#include "../persist/ThreatIgnoreList.h"
#include "../persist/ThreatLog.h"
#include "../proto/generated/threat_event.pb.h"
#include "PowerFSM.h"
#include "PowerStatus.h"
#include "RTC.h"
#include "main.h" // nimbleBluetooth, powerStatus
#include "mesh/MeshService.h"
#include "mesh/Router.h"
#include "mesh/generated/meshtastic/mesh.pb.h"
#include "mesh/generated/meshtastic/portnums.pb.h"
#include "mesh/mesh-pb-constants.h"
#include "sleep.h"

#include <NimBLEDevice.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>

namespace valkyrie
{

namespace
{

// Map our internal classifier enum to the wire-format nanopb enum. Kept
// in this file (and only this file) so BleClassifier.{h,cpp} can be
// host-tested without dragging nanopb headers in.
valkyrie_ThreatType toWireType(ThreatType t)
{
    switch (t) {
    case ThreatType::Airtag:
        return valkyrie_ThreatType_THREAT_TYPE_AIRTAG;
    case ThreatType::Flipper:
        return valkyrie_ThreatType_THREAT_TYPE_FLIPPER;
    case ThreatType::HCSkimmer:
        return valkyrie_ThreatType_THREAT_TYPE_HC_SKIMMER;
    case ThreatType::Flock:
        return valkyrie_ThreatType_THREAT_TYPE_FLOCK;
    case ThreatType::SmartGlasses:
        return valkyrie_ThreatType_THREAT_TYPE_SMART_GLASSES;
    case ThreatType::Drone:
        return valkyrie_ThreatType_THREAT_TYPE_DRONE;
    case ThreatType::WifiDeauth:
        return valkyrie_ThreatType_THREAT_TYPE_WIFI_DEAUTH;
    case ThreatType::WifiEapol:
        return valkyrie_ThreatType_THREAT_TYPE_WIFI_EAPOL;
    case ThreatType::WifiPwnagotchi:
        return valkyrie_ThreatType_THREAT_TYPE_WIFI_PWNAGOTCHI;
    case ThreatType::WifiSuspiciousAp:
        return valkyrie_ThreatType_THREAT_TYPE_WIFI_SUSPICIOUS_AP;
    case ThreatType::WifiMultiSsid:
        return valkyrie_ThreatType_THREAT_TYPE_WIFI_MULTI_SSID;
    case ThreatType::None:
    default:
        return valkyrie_ThreatType_THREAT_TYPE_NONE;
    }
}

#if defined(HAS_DRV2605) && defined(T_WATCH_S3)
// Same DRV2605 program as ExternalNotificationModule message buzzer haptics.
static void pulseThreatHapticOnce(bool &latch)
{
    if (latch)
        return;
    drv.setWaveform(0, 16);
    drv.setWaveform(1, 0);
    drv.setWaveform(2, 16);
    drv.setWaveform(3, 0);
    drv.setWaveform(4, 16);
    drv.setWaveform(5, 0);
    drv.setWaveform(6, 16);
    drv.setWaveform(7, 0);
    drv.go();
    latch = true;
}
#endif

#if defined(HAS_I2S)
static void pulseThreatSoundOnce(bool &latch)
{
    if (latch)
        return;
    if (!audioThread)
        return;
    if (audioThread->isPlaying())
        return;
    static const char kRttl[] = "d=8,o=6,b=1200:16";
    audioThread->beginRttl(kRttl, (uint32_t)strlen(kRttl));
    latch = true;
}
#endif

} // namespace

// Single global module instance pointer, set by the constructor and used
// by the NimBLE callback shim. The fork only ever instantiates one
// BleThreatDetectorModule (owned by ValkyrieFork.cpp).
BleThreatDetectorModule *g_module = nullptr;


// NimBLE 1.4.3 (pinned by upstream Meshtastic for esp32/esp32s3) uses
// the `NimBLEAdvertisedDeviceCallbacks` subclass shape. The callback
// just hands the raw advertised device to the module and returns; the
// classifier runs synchronously in NimBLE's host task because it is
// cheap (TLV walks + small OUI table) and we don't want to
// queue/copy advertisement payloads in RAM.
class BleScanCallback : public NimBLEAdvertisedDeviceCallbacks
{
  public:
    void onResult(NimBLEAdvertisedDevice *advertisedDevice) override
    {
        if (g_module && advertisedDevice)
            g_module->onAdvertisement(advertisedDevice);
    }
};

static BleScanCallback g_scanCallback;

#if HAS_WIFI && !defined(ARCH_PORTDUINO)
static bool wifiPhaseShouldRun(const ValkyriePrefs &p)
{
    return p.wifiThreatPhaseEnabled && p.isWifiThreatPassConfigured();
}
#else
static bool wifiPhaseShouldRun(const ValkyriePrefs &)
{
    return false;
}
#endif

static bool anyDutyThreatWork(const ValkyriePrefs &p)
{
#if HAS_WIFI && !defined(ARCH_PORTDUINO)
    return p.bleThreatPhaseEnabled || wifiPhaseShouldRun(p);
#else
    return p.bleThreatPhaseEnabled;
#endif
}

// ----------------------------------------------------------------------------
// Construction / destruction
// ----------------------------------------------------------------------------

BleThreatDetectorModule::BleThreatDetectorModule(const ValkyriePrefs &p)
    : OSThread("ValkyrieBLE"), prefs(p)
{
    g_module = this;
    ThreatIgnoreList::reloadCache();

    // Subscribe to sleep events so we can stop the radio cleanly before
    // the system shuts BT/peripherals down. RadioInterface uses the same
    // pattern (see firmware/src/mesh/RadioInterface.cpp:701).
    lightSleepObserver.observe(&notifyLightSleep);
    deepSleepObserver.observe(&notifyDeepSleep);
    preflightSleepObserver.observe(&preflightSleep);

    // OSThread starts running automatically (see concurrency::OSThread
    // ctor in firmware/src/concurrency/OSThread.cpp). The first runOnce()
    // will simply return the next interval — we don't want to scan
    // immediately on boot since the GATT server is still standing up.
    setIntervalFromNow(5 * 1000); // first tick 5s after boot
}

BleThreatDetectorModule::~BleThreatDetectorModule()
{
    if (heartbeatActive)
        stopHeartbeat();
    passNotificationBatchOpen = false;
    passNotificationBuffer.clear();
    haltBleScan();
    preflightSleepObserver.unobserve(&preflightSleep);
    lightSleepObserver.unobserve(&notifyLightSleep);
    deepSleepObserver.unobserve(&notifyDeepSleep);
    if (g_module == this)
        g_module = nullptr;
}

// ----------------------------------------------------------------------------
// Scan setup / teardown
// ----------------------------------------------------------------------------

void BleThreatDetectorModule::initScanIfNeeded()
{
    if (scanInitialised)
        return;

    // We rely on Meshtastic's NimbleBluetooth having already called
    // NimBLEDevice::init() for the GATT server. If the user disabled
    // bluetooth (wait_bluetooth_secs expired with no client, or BT
    // turned off in config), nimbleBluetooth->isActive() will be false
    // and getScan() may not be safe. In that case we skip scanning —
    // Phase 1 is intentionally cooperative with phone connectivity, not
    // a replacement for it.
    if (!nimbleBluetooth || !nimbleBluetooth->isActive()) {
        return;
    }

    scan = NimBLEDevice::getScan();
    if (!scan)
        return;

    scan->setAdvertisedDeviceCallbacks(&g_scanCallback, /*wantDuplicates=*/false);
    // Passive scan only — DO NOT call setActiveScan(true), that would TX
    // SCAN_REQ packets and burn battery + draw attention. The tracker
    // detection logic only needs ADV_IND payloads.
    scan->setActiveScan(false);
    // ~40% in-window radio duty (0.5ms units). A continuous-mode scan
    // with interval==window would lock the radio and break the GATT
    // server.
    scan->setInterval(160);
    scan->setWindow(64);
    // Stream results through onResult() instead of accumulating them.
    scan->setMaxResults(0);

    scanInitialised = true;
    LOG_INFO("Valkyrie: BLE scan initialised (interval=160 window=64 passive max_results=0)");
}

bool BleThreatDetectorModule::shouldScan() const
{
    // 1. Don't scan unless we're in a foreground-ish power state.
    if (powerFSM.getState() != &::stateON && powerFSM.getState() != &::stateDARK)
        return false;

    // 2. Don't drain a low battery further. If we're on USB power
    //    (knowsUSB && hasUSB) we can scan regardless of charge.
    if (powerStatus) {
        bool onUsb = powerStatus->knowsUSB() && powerStatus->getHasUSB();
        if (!onUsb && powerStatus->getHasBattery() && powerStatus->getBatteryChargePercent() < prefs.minBatteryPct) {
            return false;
        }
    }

    return true;
}

void BleThreatDetectorModule::startScanWindow()
{
    if (!scan || scanActive)
        return;

    // Duration arg is in seconds. Passing 0 means "scan forever" — DO
    // NOT do that; we want NimBLE to auto-stop after our window so we
    // don't have to perfectly time our own stop call against an LS
    // transition.
    if (scan->start(prefs.scanWindowSecs, /*scanCompleteCB=*/nullptr, /*is_continue=*/false)) {
        scanActive = true;
        hapticEmittedThisScanWindow = false;
        soundEmittedThisScanWindow = false;
        scanStartedMs = millis();
        passNotificationBuffer.clear();
        passNotificationBatchOpen = true;
        LOG_DEBUG("Valkyrie: BLE scan started for %us", prefs.scanWindowSecs);
    } else {
        LOG_WARN("Valkyrie: BLE scan start failed (likely contended by GATT)");
        passNotificationBatchOpen = false;
    }
}

void BleThreatDetectorModule::haltBleScan()
{
    if (scan && scanActive) {
        scan->stop();
        scan->clearResults();
        scanActive = false;
        hubBleWindowEndMs = millis();
        LOG_DEBUG("Valkyrie: BLE scan halted");
    }
}

void BleThreatDetectorModule::finishDutyThreatPassEpilogue()
{
    flushPassNotification(false);
    passNotificationBatchOpen = false;
    lastScanWindowEndMs = millis();
}

void BleThreatDetectorModule::finalizeDutyThreatPass()
{
    if (heartbeatActive) {
        finishDutyThreatPassEpilogue();
        return;
    }
    if (valkyrie::beginWifiThreatPass(this)) {
        wifiThreatPassActive = true;
        return;
    }
    finishDutyThreatPassEpilogue();
}

void BleThreatDetectorModule::abortBleScanForSleep()
{
    valkyrie::abortWifiThreatPass();
#if HAS_WIFI && !defined(ARCH_PORTDUINO)
    // Heartbeat hunt uses the same Wi‑Fi state machine but a separate exit; clean it
    // up too so a sleep edge doesn't leave the modem half-promiscuous.
    valkyrie::endWifiHeartbeat();
#endif
    wifiThreatPassActive = false;
    deferredConstantBleScanRestart = false;
    haltBleScan();
    flushPassNotification(true);
    passNotificationBatchOpen = false;
    lastScanWindowEndMs = millis();
}

void BleThreatDetectorModule::appendPassThreatNotificationLine(const ClassificationResult &cls, const uint8_t mac[6],
                                                               const char *name, int32_t rssi, const char *detailBuf)
{
    char line[224];
    if (name && name[0])
        snprintf(line, sizeof(line), "%s %02X:%02X:%02X:%02X:%02X:%02X %d dBm \"%s\"", threatTypeWireName(cls.type),
                 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], (int)rssi, name);
    else
        snprintf(line, sizeof(line), "%s %02X:%02X:%02X:%02X:%02X:%02X %d dBm", threatTypeWireName(cls.type), mac[0],
                 mac[1], mac[2], mac[3], mac[4], mac[5], (int)rssi);
    if (detailBuf && detailBuf[0]) {
        const size_t n = strlen(line);
        snprintf(line + n, sizeof(line) - n, " %s", detailBuf);
        line[sizeof(line) - 1] = '\0';
    }
    if (!passNotificationBuffer.empty())
        passNotificationBuffer += '\n';
    passNotificationBuffer += line;
}

void BleThreatDetectorModule::flushPassNotification(bool sleepAbort)
{
    if (!router || !service) {
        passNotificationBuffer.clear();
        return;
    }

    if (sleepAbort && passNotificationBuffer.empty()) {
        return;
    }

    if (sleepAbort) {
        passNotificationBuffer += '\n';
        passNotificationBuffer += "Valkyrie: pass aborted (sleep)";
    }

    if (passNotificationBuffer.empty())
        return;

    // meshtastic_ClientNotification.message is char[400]; reserve one byte for NUL.
    constexpr size_t kMsgMax = 399;
    const std::string full = passNotificationBuffer;
    passNotificationBuffer.clear();

    size_t pos = 0;
    for (int ci = 0; ci < 2 && pos < full.size(); ++ci) {
        meshtastic_ClientNotification *cn = clientNotificationPool.allocZeroed();
        if (!cn) {
            LOG_WARN("Valkyrie: ClientNotification alloc failed");
            break;
        }
        size_t len = full.size() - pos;
        if (len > kMsgMax)
            len = kMsgMax;
        memcpy(cn->message, full.data() + pos, len);
        cn->message[len] = '\0';
        cn->level = meshtastic_LogRecord_Level_WARNING;
        cn->time = getValidTime(RTCQualityFromNet);
        service->sendClientNotification(cn);
        pos += len;
    }
    if (pos < full.size())
        LOG_WARN("Valkyrie: batched notification truncated (%u bytes unsent)", (unsigned)(full.size() - pos));
}

// ----------------------------------------------------------------------------
// Sleep observers (cleanly tear down before LS/SDS so we don't leave
// the radio half-configured when peripherals are powered down).
// ----------------------------------------------------------------------------

int BleThreatDetectorModule::onLightSleep(void *)
{
    abortBleScanForSleep();
    return 0;
}

int BleThreatDetectorModule::onDeepSleep(void *)
{
    abortBleScanForSleep();
    return 0;
}

int BleThreatDetectorModule::preflightSleepCb(void *)
{
    if (heartbeatActive)
        return 1;
    // Wardrive session owns the radio + must keep GPS/UI ticking; refuse LS for the same
    // reason heartbeat / constant chain do.
    if (wardriveActive)
        return 1;
    // Belt-and-braces: if the runOnce nudge ever loses the race, still
    // refuse LS while constant scan is configured so we don't tear BT down
    // mid-window.
    if (prefs.bleThreatDetectorEnabled && prefs.constantBleScanMode && prefs.bleThreatPhaseEnabled)
        return 1;
    return 0;
}

// ----------------------------------------------------------------------------
// Wardrive session integration.
//
// Wardrive needs exclusive use of the Wi‑Fi radio (WiFi.scanNetworks runs in
// STA mode) and must keep PowerFSM awake for the duration of the drive — same
// constraints constant BLE scan has, plus the extra requirement that our duty
// cycle stop firing entirely so it doesn't fight the session for the modem.
//
// pauseForWardrive():
//   - Tears down any in-flight BLE scan and Wi‑Fi promiscuous pass (the existing
//     sleep-edge path already handles both cleanly).
//   - Sets wardriveActive so runOnce() bails out at the top until cleared.
//   - The session OSThread starts immediately after this returns; the LS-refuse
//     vote in preflightSleepCb + the EVENT_CONTACT_FROM_PHONE nudge in runOnce
//     keep PowerFSM in DARK/ON.
// resumeFromWardrive():
//   - Clears the flag and nudges runOnce so the next duty cycle starts promptly.
// ----------------------------------------------------------------------------

void BleThreatDetectorModule::pauseForWardrive()
{
    if (wardriveActive)
        return;
    LOG_INFO("Valkyrie: pausing BLE threat detector for wardrive session");
    abortBleScanForSleep();
    wardriveActive = true;
}

void BleThreatDetectorModule::resumeFromWardrive()
{
    if (!wardriveActive)
        return;
    LOG_INFO("Valkyrie: resuming BLE threat detector after wardrive session");
    wardriveActive = false;
    setIntervalFromNow(0);
}

bool BleThreatDetectorModule::startHeartbeat(const uint8_t mac[6], ThreatType type, ThreatSource source, uint8_t lockChannel)
{
    // Tear any duty-cycle work down regardless of the chosen radio path: Wi‑Fi
    // heartbeat must not run on top of an in-flight duty Wi‑Fi pass, and BLE
    // heartbeat needs the duty BLE scan stopped to flip wantDuplicates on.
    abortBleScanForSleep();

    // Reset shared heartbeat state up-front so partial init failures don't leave
    // stale RSSI/tier visible to the UI.
    heartbeatActive = true;
    heartbeatSource = source;
    heartbeatLockChannel = lockChannel;
    memcpy(heartbeatTargetMac, mac, 6);
    heartbeatTargetType = type;
    heartbeatLastRssi = -128;
    heartbeatLastAdvMs = 0;
    heartbeatSessionStartMs = millis();
    heartbeatEverSeenTarget = false;
    heartbeatSmoothedValid = false;
    heartbeatSmoothedRssi = -128;
    heartbeatLatchedTierU8 = static_cast<uint8_t>(HeartbeatSignalTier::None);

    if (source == ThreatSource::Wifi) {
#if HAS_WIFI && !defined(ARCH_PORTDUINO)
        if (!valkyrie::beginWifiHeartbeat(this, mac, lockChannel)) {
            LOG_WARN("Valkyrie: WiFi heartbeat begin failed");
            heartbeatActive = false;
            heartbeatTargetType = ThreatType::None;
            heartbeatSource = ThreatSource::Ble;
            heartbeatLockChannel = 0;
            return false;
        }
        scanStartedMs = millis();
        LOG_INFO("Valkyrie: heartbeat mode started (Wi-Fi, lock_ch=%u)", (unsigned)lockChannel);
        setIntervalFromNow(0);
        return true;
#else
        LOG_WARN("Valkyrie: WiFi heartbeat unsupported on this build");
        heartbeatActive = false;
        heartbeatTargetType = ThreatType::None;
        heartbeatSource = ThreatSource::Ble;
        heartbeatLockChannel = 0;
        return false;
#endif
    }

    if (!nimbleBluetooth || !nimbleBluetooth->isActive()) {
        heartbeatActive = false;
        heartbeatTargetType = ThreatType::None;
        return false;
    }

    initScanIfNeeded();
    if (!scan || !scanInitialised) {
        heartbeatActive = false;
        heartbeatTargetType = ThreatType::None;
        return false;
    }

    scan->setAdvertisedDeviceCallbacks(&g_scanCallback, /*wantDuplicates=*/true);
    if (!scan->start(0, /*scanCompleteCB=*/nullptr, /*is_continue=*/false)) {
        LOG_WARN("Valkyrie: heartbeat continuous scan start failed");
        scan->setAdvertisedDeviceCallbacks(&g_scanCallback, /*wantDuplicates=*/false);
        heartbeatActive = false;
        heartbeatTargetType = ThreatType::None;
        return false;
    }
    scanActive = true;
    hapticEmittedThisScanWindow = false;
    scanStartedMs = millis();
    LOG_INFO("Valkyrie: heartbeat mode started (BLE)");
    setIntervalFromNow(0);
    return true;
}

void BleThreatDetectorModule::stopHeartbeat()
{
    if (!heartbeatActive)
        return;

    const ThreatSource src = heartbeatSource;

    heartbeatActive = false;
    heartbeatEverSeenTarget = false;
    heartbeatLastAdvMs = 0;
    heartbeatTargetType = ThreatType::None;
    heartbeatSmoothedValid = false;
    heartbeatSmoothedRssi = -128;
    heartbeatLatchedTierU8 = static_cast<uint8_t>(HeartbeatSignalTier::None);
    heartbeatLockChannel = 0;
    heartbeatSource = ThreatSource::Ble;

    if (src == ThreatSource::Wifi) {
#if HAS_WIFI && !defined(ARCH_PORTDUINO)
        valkyrie::endWifiHeartbeat();
#endif
    } else if (scan && scanInitialised) {
        haltBleScan();
        scan->setAdvertisedDeviceCallbacks(&g_scanCallback, /*wantDuplicates=*/false);
    }
    LOG_INFO("Valkyrie: heartbeat mode stopped");
    setIntervalFromNow(0);
}

void BleThreatDetectorModule::onWifiHeartbeatFrame(const uint8_t mac[6], uint8_t /*channel*/, int32_t rssi)
{
    if (!heartbeatActive || heartbeatSource != ThreatSource::Wifi)
        return;
    if (memcmp(mac, heartbeatTargetMac, 6) != 0)
        return;

    const uint32_t nowMs = millis();
    const uint32_t prevAdvMs = heartbeatLastAdvMs;

    heartbeatLastRssi = rssi;
    heartbeatLastAdvMs = nowMs;

    const bool gapStale = (prevAdvMs != 0) && (nowMs - prevAdvMs > kHeartbeatRssiStaleMs);

    if (!heartbeatSmoothedValid || gapStale) {
        heartbeatSmoothedRssi = heartbeatRssiEmaNext(true, 0, rssi);
        heartbeatSmoothedValid = true;
        heartbeatLatchedTierU8 = static_cast<uint8_t>(heartbeatRssiInstaTier(rssi));
    } else {
        heartbeatSmoothedRssi = heartbeatRssiEmaNext(false, heartbeatSmoothedRssi, rssi);
        heartbeatRssiApplyHysteresis(&heartbeatLatchedTierU8, heartbeatSmoothedRssi);
    }

    heartbeatEverSeenTarget = true;
}

HeartbeatSignalTier BleThreatDetectorModule::getHeartbeatSignalTier() const
{
    if (!heartbeatActive)
        return HeartbeatSignalTier::None;

    // Bursty advertisers (e.g. Find My / AirTag) often have multi-second ADV gaps.
    const uint32_t now = millis();

    if (!heartbeatEverSeenTarget || heartbeatLastAdvMs == 0)
        return HeartbeatSignalTier::None;

    uint32_t ageMs = now - heartbeatLastAdvMs;
    if (now < heartbeatLastAdvMs)
        ageMs = 0;
    if (ageMs > kHeartbeatRssiStaleMs)
        return HeartbeatSignalTier::None;

    // Tier from EMA + hysteresis (maintained in onAdvertisement).
    return static_cast<HeartbeatSignalTier>(heartbeatLatchedTierU8);
}

int32_t BleThreatDetectorModule::getHeartbeatSmoothedRssi() const
{
    return heartbeatSmoothedValid ? heartbeatSmoothedRssi : -128;
}

// ----------------------------------------------------------------------------
// OSThread tick
// ----------------------------------------------------------------------------

int32_t BleThreatDetectorModule::runOnce()
{
    static constexpr int32_t kWifiThreatPollMs = 20;

    // Constant BLE scan / wardrive must keep BT/NimBLE alive across wait_bluetooth_secs;
    // re-enter DARK to reset the DARK->LS timed transition. Same pattern as
    // MQTT.cpp's EVENT_CONTACT_FROM_PHONE keep-awake.
    const bool wantKeepAwake = wardriveActive ||
                               (prefs.bleThreatDetectorEnabled && prefs.constantBleScanMode && prefs.bleThreatPhaseEnabled);
    if (wantKeepAwake && powerFSM.getState() == &::stateDARK) {
        powerFSM.trigger(EVENT_CONTACT_FROM_PHONE);
    }

    // While a wardrive session owns the radio, do not touch the duty cycle at all.
    // The session OSThread handles UI / scan / GPS / log on its own timeline; we only
    // stay alive to keep the LS-refuse vote and the keep-awake nudge above ticking.
    if (wardriveActive) {
        return 250;
    }

    if (heartbeatActive) {
        if (heartbeatSource == ThreatSource::Wifi) {
#if HAS_WIFI && !defined(ARCH_PORTDUINO)
            if (!shouldScan())
                return 30 * 1000;
            // Drives cold/hot bring-up + Scan tick. Heartbeat never reports complete; ends via stopHeartbeat().
            valkyrie::tickWifiHeartbeat(this);
            return 50;
#else
            return 30 * 1000;
#endif
        }
        if (!shouldScan()) {
            return 30 * 1000;
        }
        initScanIfNeeded();
        if (!scanInitialised || !scan) {
            return 5 * 1000;
        }
        if (scanActive && scan->isScanning()) {
            return 400;
        }
        // Continuous scan dropped — restart (radio contention, LS edge, etc.).
        scan->setAdvertisedDeviceCallbacks(&g_scanCallback, /*wantDuplicates=*/true);
        if (scan->start(0, nullptr, false)) {
            scanActive = true;
            hapticEmittedThisScanWindow = false;
            scanStartedMs = millis();
            LOG_DEBUG("Valkyrie: heartbeat scan restarted");
        } else {
            LOG_WARN("Valkyrie: heartbeat scan restart failed");
        }
        return 400;
    }

    if (wifiThreatPassActive) {
        if (valkyrie::tickWifiThreatPass(this)) {
            wifiThreatPassActive = false;
            finishDutyThreatPassEpilogue();
            if (deferredConstantBleScanRestart) {
                deferredConstantBleScanRestart = false;
                if (shouldScan()) {
                    initScanIfNeeded();
                    startScanWindow();
                }
            }
        }
        return kWifiThreatPollMs;
    }

    // If a scan is in flight, check whether it's done. NimBLE 1.4.x
    // auto-stops after the duration we passed to start(), but we still
    // need to clear our scanActive flag so the next tick can launch a
    // fresh window.
    if (scanActive) {
        if (scan && !scan->isScanning()) {
            haltBleScan();
            finalizeDutyThreatPass();
            LOG_DEBUG("Valkyrie: scan window complete (%u detections so far)", (unsigned)totalDetections);
            if (wifiThreatPassActive)
                deferredConstantBleScanRestart =
                    prefs.constantBleScanMode && prefs.bleThreatPhaseEnabled && shouldScan();
            else if (prefs.constantBleScanMode && prefs.bleThreatPhaseEnabled && shouldScan()) {
                initScanIfNeeded();
                startScanWindow();
            }
            return wifiThreatPassActive ? kWifiThreatPollMs : 1000;
        }
        uint32_t elapsedMs = millis() - scanStartedMs;
        uint32_t hardCapMs = (uint32_t)prefs.scanWindowSecs * 1000U + 2000U;
        if (elapsedMs > hardCapMs) {
            // Belt and braces: stop on our timer in case NimBLE
            // didn't honour the duration arg (rare, but cheaper to
            // be defensive than to debug a stuck scan).
            LOG_WARN("Valkyrie: scan exceeded hard cap, forcing stop");
            haltBleScan();
            finalizeDutyThreatPass();
            if (wifiThreatPassActive)
                deferredConstantBleScanRestart =
                    prefs.constantBleScanMode && prefs.bleThreatPhaseEnabled && shouldScan();
            else if (prefs.constantBleScanMode && prefs.bleThreatPhaseEnabled && shouldScan()) {
                initScanIfNeeded();
                startScanWindow();
            }
        }
        // Tick again soon while a scan is in flight so we notice the
        // completion promptly without holding the watchdog.
        return wifiThreatPassActive ? kWifiThreatPollMs : 1000;
    }

    if (!shouldScan()) {
        // Re-check every 30s while gated; this is what keeps us out of
        // the way of LS slices.
        return 30 * 1000;
    }

    if (!anyDutyThreatWork(prefs)) {
        return 30 * 1000;
    }

    // Idle between passes (BLE window and/or Wi‑Fi phase); gap may be 0 only when constant BLE chaining is active.
    if (lastScanWindowEndMs != 0) {
        uint32_t gapMs = ble_scan_schedule::idleGapMsAfterWindow(prefs);
        uint32_t now = millis();
        uint32_t elapsed = now - lastScanWindowEndMs;
        if (elapsed < gapMs) {
            uint32_t remain = gapMs - elapsed;
            // Cap single sleep to 60s so we re-evaluate shouldScan / prefs often enough.
            uint32_t tick = remain > 60000U ? 60000U : remain;
            return (int32_t)tick;
        }
    }

#if HAS_WIFI && !defined(ARCH_PORTDUINO)
    if (!prefs.bleThreatPhaseEnabled && wifiPhaseShouldRun(prefs)) {
        passNotificationBuffer.clear();
        passNotificationBatchOpen = true;
        hubBleWindowEndMs = millis() - kHubBleScanStripOutroMs;
        finalizeDutyThreatPass();
        return wifiThreatPassActive ? kWifiThreatPollMs : 1000;
    }
#endif

    initScanIfNeeded();
    if (!scanInitialised) {
        // GATT server not up yet, try again in a bit.
        return 5 * 1000;
    }

    startScanWindow();
    if (scanActive) {
        // Poll often while a window runs so we clear scanActive soon after NimBLE stops (callbacks still run).
        return 1000;
    }

    // Failed to start (contended), back off (shorter when constant scan).
    return ble_scan_schedule::failedStartBackoffMs(prefs);
}

// ----------------------------------------------------------------------------
// Detection path: classify -> dedupe -> persist + phone emit
// ----------------------------------------------------------------------------

void BleThreatDetectorModule::emitWifiThreat(const ClassificationResult &cls, const uint8_t mac[6], const char *name,
                                             int32_t rssi, uint8_t channel)
{
    if (cls.type == ThreatType::None)
        return;

    if (cls.type == ThreatType::Flock) {
        if (!prefs.isThreatTypeEnabled(ThreatType::Flock))
            return;
    } else if (cls.type == ThreatType::Drone) {
        if (!prefs.isThreatTypeEnabled(ThreatType::Drone))
            return;
    } else if (static_cast<uint8_t>(cls.type) >= 7 && static_cast<uint8_t>(cls.type) <= 11) {
        if (!prefs.isWifiThreatTypeEnabled(cls.type))
            return;
    } else {
        return;
    }

    if (ThreatIgnoreList::isIgnored(cls.type, mac))
        return;

    if (!tryAdmitDetection(mac, cls.type))
        return;

    emitDetection(cls, mac, name ? name : "", rssi, ThreatSource::Wifi, channel);
}

bool BleThreatDetectorModule::tryAdmitDetection(const uint8_t mac[6], ThreatType type)
{
    uint32_t now = millis();
    uint32_t windowMs = (uint32_t)prefs.dedupeWindowSecs * 1000U;

    for (size_t i = 0; i < kDedupeCap; ++i) {
        DedupeEntry &e = dedupe[i];
        if (e.used && e.type == type && memcmp(e.mac, mac, 6) == 0) {
            if ((now - e.lastSeenMs) < windowMs) {
                return false; // recently emitted, drop
            }
            e.lastSeenMs = now;
            return true;
        }
    }

    // Insert (replace oldest by ring index when full).
    DedupeEntry &slot = dedupe[dedupeNext];
    dedupeNext = (dedupeNext + 1) % kDedupeCap;
    memcpy(slot.mac, mac, 6);
    slot.type = type;
    slot.lastSeenMs = now;
    slot.used = true;
    return true;
}

bool BleThreatDetectorModule::tryAdmitPhoneNotification(const uint8_t mac[6], ThreatType type)
{
    uint32_t now = millis();

    for (size_t i = 0; i < kPhoneCooldownCap; ++i) {
        PhoneCooldownEntry &e = phoneCooldown[i];
        if (e.used && e.type == type && memcmp(e.mac, mac, 6) == 0) {
            if ((now - e.lastSentMs) < kPhoneCooldownMs) {
                return false; // within phone-notification cooldown, suppress phone push
            }
            e.lastSentMs = now;
            return true;
        }
    }

    PhoneCooldownEntry &slot = phoneCooldown[phoneCooldownNext];
    phoneCooldownNext = (phoneCooldownNext + 1) % kPhoneCooldownCap;
    memcpy(slot.mac, mac, 6);
    slot.type = type;
    slot.lastSentMs = now;
    slot.used = true;
    return true;
}

void BleThreatDetectorModule::emitDetection(const ClassificationResult &cls, const uint8_t mac[6], const char *name,
                                            int32_t rssi, ThreatSource source, uint8_t channel, bool gpsStalkingTrigger,
                                            uint32_t gpsStalkingSightings, uint32_t gpsStalkingPlaces)
{
    ++totalDetections;

    char detailBuf[sizeof(ClassificationResult::detail)] = {0};
    if (gpsStalkingTrigger) {
        if (cls.detail[0])
            snprintf(detailBuf, sizeof detailBuf, "%s [gps-stk %u/%u]", cls.detail, (unsigned)gpsStalkingSightings,
                     (unsigned)gpsStalkingPlaces);
        else
            snprintf(detailBuf, sizeof detailBuf, "[gps-stk %u/%u]", (unsigned)gpsStalkingSightings,
                     (unsigned)gpsStalkingPlaces);
    } else {
        strncpy(detailBuf, cls.detail, sizeof detailBuf - 1);
        detailBuf[sizeof detailBuf - 1] = '\0';
    }

    uint32_t tsSecs = millis() / 1000U;

    // 1. Local persistence.
    ThreatLog::append(tsSecs, threatTypeWireName(cls.type), mac, name, rssi, detailBuf, source, channel);

    LOG_INFO("Valkyrie: threat=%s mac=%02X:%02X:%02X:%02X:%02X:%02X rssi=%d name=\"%s\" detail=\"%s\"", threatTypeWireName(cls.type),
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], (int)rssi, name ? name : "", detailBuf);

#if defined(HAS_DRV2605) && defined(T_WATCH_S3)
    if (prefs.threatDetectionHapticEnabled)
        pulseThreatHapticOnce(hapticEmittedThisScanWindow);
#endif

#if defined(HAS_I2S)
    if (prefs.threatDetectionSoundEnabled)
        pulseThreatSoundOnce(soundEmittedThisScanWindow);
#endif

    // 2. Phone delivery: heartbeat uses immediate PRIVATE_APP + ClientNotification.
    //    Passive duty uses policy A — batch newline ClientNotification at pass end only (no per-detection PRIVATE_APP).
    if (!router || !service)
        return;

    if (heartbeatActive) {
        if (!prefs.phoneNotificationsEnabled || !tryAdmitPhoneNotification(mac, cls.type))
            return;

        valkyrie_BleThreatEvent ev = valkyrie_BleThreatEvent_init_zero;
        ev.timestamp = tsSecs;
        ev.type = toWireType(cls.type);
        memcpy(ev.mac, mac, 6);
        if (name) {
            strncpy(ev.name, name, sizeof(ev.name) - 1);
            ev.name[sizeof(ev.name) - 1] = '\0';
        }
        ev.rssi = rssi;
        if (detailBuf[0]) {
            strncpy(ev.detail, detailBuf, sizeof(ev.detail) - 1);
            ev.detail[sizeof(ev.detail) - 1] = '\0';
        }
        ev.stalking_gps_triggered = gpsStalkingTrigger;
        ev.stalking_sightings = gpsStalkingSightings;
        ev.stalking_distinct_places = gpsStalkingPlaces;

        meshtastic_MeshPacket *p = router->allocForSending();
        if (!p) {
            LOG_WARN("Valkyrie: allocForSending() returned null, dropping threat event");
            return;
        }

        p->decoded.portnum = meshtastic_PortNum_PRIVATE_APP;
        p->decoded.want_response = false;
        p->priority = meshtastic_MeshPacket_Priority_BACKGROUND;

        size_t encoded = pb_encode_to_bytes(p->decoded.payload.bytes, sizeof(p->decoded.payload.bytes), &valkyrie_BleThreatEvent_msg,
                                            &ev);
        if (encoded == 0) {
            LOG_WARN("Valkyrie: pb_encode_to_bytes failed, dropping threat event");
            packetPool.release(p);
            return;
        }
        p->decoded.payload.size = encoded;

        service->sendToPhone(p);

        meshtastic_ClientNotification *cn = clientNotificationPool.allocZeroed();
        if (cn) {
            cn->level = meshtastic_LogRecord_Level_WARNING;
            cn->time = getValidTime(RTCQualityFromNet);
            snprintf(cn->message, sizeof(cn->message), "Valkyrie: %s %02X:%02X:%02X:%02X:%02X:%02X %d dBm",
                     threatTypeWireName(cls.type), mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], (int)rssi);
            service->sendClientNotification(cn);
        }
        return;
    }

    if (passNotificationBatchOpen) {
        if (prefs.phoneNotificationsEnabled && tryAdmitPhoneNotification(mac, cls.type))
            appendPassThreatNotificationLine(cls, mac, name, rssi, detailBuf);
        return;
    }

    {
        if (!prefs.phoneNotificationsEnabled || !tryAdmitPhoneNotification(mac, cls.type))
            return;

        valkyrie_BleThreatEvent ev = valkyrie_BleThreatEvent_init_zero;
        ev.timestamp = tsSecs;
        ev.type = toWireType(cls.type);
        memcpy(ev.mac, mac, 6);
        if (name) {
            strncpy(ev.name, name, sizeof(ev.name) - 1);
            ev.name[sizeof(ev.name) - 1] = '\0';
        }
        ev.rssi = rssi;
        if (detailBuf[0]) {
            strncpy(ev.detail, detailBuf, sizeof(ev.detail) - 1);
            ev.detail[sizeof(ev.detail) - 1] = '\0';
        }
        ev.stalking_gps_triggered = gpsStalkingTrigger;
        ev.stalking_sightings = gpsStalkingSightings;
        ev.stalking_distinct_places = gpsStalkingPlaces;

        meshtastic_MeshPacket *p = router->allocForSending();
        if (!p) {
            LOG_WARN("Valkyrie: allocForSending() returned null, dropping threat event");
            return;
        }

        p->decoded.portnum = meshtastic_PortNum_PRIVATE_APP;
        p->decoded.want_response = false;
        p->priority = meshtastic_MeshPacket_Priority_BACKGROUND;

        size_t encoded = pb_encode_to_bytes(p->decoded.payload.bytes, sizeof(p->decoded.payload.bytes), &valkyrie_BleThreatEvent_msg,
                                            &ev);
        if (encoded == 0) {
            LOG_WARN("Valkyrie: pb_encode_to_bytes failed, dropping threat event");
            packetPool.release(p);
            return;
        }
        p->decoded.payload.size = encoded;

        service->sendToPhone(p);

        meshtastic_ClientNotification *cn = clientNotificationPool.allocZeroed();
        if (cn) {
            cn->level = meshtastic_LogRecord_Level_WARNING;
            cn->time = getValidTime(RTCQualityFromNet);
            snprintf(cn->message, sizeof(cn->message), "Valkyrie: %s %02X:%02X:%02X:%02X:%02X:%02X %d dBm",
                     threatTypeWireName(cls.type), mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], (int)rssi);
            service->sendClientNotification(cn);
        }
    }
}

void BleThreatDetectorModule::reloadPrefs()
{
    if (heartbeatActive)
        stopHeartbeat();
    prefs = ValkyriePrefs::load();
    ThreatIgnoreList::reloadCache();
    setIntervalFromNow(0);
}

void BleThreatDetectorModule::reloadIgnoreList()
{
    ThreatIgnoreList::reloadCache();
}

void BleThreatDetectorModule::onAdvertisement(NimBLEAdvertisedDevice *ad)
{
    if (!ad)
        return;

    NimBLEAddress addr = ad->getAddress();
    uint8_t mac[6] = {0};
    const uint8_t *raw = addr.getNative();
    if (raw) {
        for (size_t i = 0; i < 6; ++i)
            mac[i] = raw[5 - i];
    }

    if (heartbeatActive) {
        bool matched = (memcmp(mac, heartbeatTargetMac, 6) == 0);
        if (!matched && raw)
            matched = (memcmp(raw, heartbeatTargetMac, 6) == 0);
        if (!matched && heartbeatTargetType == ThreatType::Airtag) {
            const uint8_t *payload = ad->getPayload();
            const size_t payloadLen = ad->getPayloadLength();
            const std::string nameStr = ad->getName();
            const auto cls = classifyAdvertisement(payload, payloadLen, nameStr.c_str(), mac);
            if (cls.type == ThreatType::Airtag)
                matched = true;
        }
        if (!matched)
            return;

        const int32_t rssiRaw = ad->getRSSI();
        const uint32_t nowMs = millis();
        const uint32_t prevAdvMs = heartbeatLastAdvMs;

        heartbeatLastRssi = rssiRaw;
        heartbeatLastAdvMs = nowMs;

        const bool gapStale =
            (prevAdvMs != 0) && (nowMs - prevAdvMs > kHeartbeatRssiStaleMs);

        if (!heartbeatSmoothedValid || gapStale) {
            heartbeatSmoothedRssi = heartbeatRssiEmaNext(true, 0, rssiRaw);
            heartbeatSmoothedValid = true;
            heartbeatLatchedTierU8 = static_cast<uint8_t>(heartbeatRssiInstaTier(rssiRaw));
        } else {
            heartbeatSmoothedRssi = heartbeatRssiEmaNext(false, heartbeatSmoothedRssi, rssiRaw);
            heartbeatRssiApplyHysteresis(&heartbeatLatchedTierU8, heartbeatSmoothedRssi);
        }

        heartbeatEverSeenTarget = true;
        return;
    }

    // NimBLE 1.4.3: getPayload() returns the raw advertisement bytes,
    // getPayloadLength() the length. getName() returns std::string.
    const uint8_t *payload = ad->getPayload();
    size_t payloadLen = ad->getPayloadLength();
    std::string nameStr = ad->getName();

    auto cls = classifyAdvertisement(payload, payloadLen, nameStr.c_str(), mac);
    if (cls.type == ThreatType::None)
        return;
    if (!prefs.isThreatTypeEnabled(cls.type))
        return;

    if (ThreatIgnoreList::isIgnored(cls.type, mac))
        return;

    if (cls.type == ThreatType::Airtag) {
        int32_t lat_i = 0;
        int32_t lon_i = 0;
        if (readGeoForStalking(&lat_i, &lon_i)) {
            AirtagStalkingConfig sc{};
            sc.minSightings = prefs.stalkMinSightings;
            sc.minDistinctPlaces = prefs.stalkMinDistinctPlaces;
            sc.minSeparationM = prefs.stalkMinSeparationM;
            sc.entryTtlSecs = prefs.stalkEntryTtlSecs;
            AirtagStalkingGateResult gr = airtagStalking.recordSighting(mac, lat_i, lon_i, millis(), sc);
            if (!gr.allowEmit)
                return;
            if (!tryAdmitDetection(mac, cls.type))
                return;
            emitDetection(cls, mac, nameStr.c_str(), ad->getRSSI(), ThreatSource::Ble, 0, true, gr.sightings,
                          gr.distinctPlaces);
            return;
        }
    }

    if (!tryAdmitDetection(mac, cls.type))
        return; // dedupe-throttled

    emitDetection(cls, mac, nameStr.c_str(), ad->getRSSI(), ThreatSource::Ble, 0);
}

} // namespace valkyrie

#endif // ARCH_ESP32 && VALKYRIE_FORK
