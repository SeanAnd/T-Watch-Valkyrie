#pragma once

#include "configuration.h"

#if defined(ARCH_ESP32) && defined(VALKYRIE_FORK)

#include "../HeartbeatSignalTier.h"
#include "../prefs/ValkyriePrefs.h"
#include "AirtagStalkingState.h"
#include "BleClassifier.h"
#include "Observer.h"
#include "concurrency/OSThread.h"
#include "esp_sleep.h"

#include <stdint.h>
#include <string>

// Forward declarations to avoid pulling NimBLE into our public header.
class NimBLEScan;
class NimBLEAdvertisedDevice;

namespace valkyrie
{

// Power-aware passive BLE threat detector. Runs as a single
// concurrency::OSThread instance owned by ValkyrieFork.cpp. Piggybacks
// on the NimBLE stack already initialised by the upstream Meshtastic
// GATT server, so the phone link is unaffected.
//
// Lifecycle (driven by runOnce()):
//
//   Idle      -> Scanning   after idle gap from ble_scan_schedule (0 when
//                            constantBleScanMode && bleThreatPhaseEnabled), else max(0, scanIntervalSecs
//                            - scanWindowSecs) from end of last *threat pass*
//                            (BLE window + Wi‑Fi promiscuous phase); PowerFSM in {ON, DARK},
//                            battery OK. BLE path requires NimBLE initialised.
//   Wi‑Fi‑only When bleThreatPhaseEnabled is false and prefs allow Wi‑Fi work, idle gap then
//               async Wi‑Fi pass only (no NimBLE window); hubBleWindowEndMs anchored for sprite timeline.
//   Scanning  -> Idle       after BLE window completes, Wi‑Fi threat pass runs,
//                            then lastScanWindowEndMs updates (wardriving-style pass)
//   any       -> Disabled   on notifyDeepSleep / notifyLightSleep
//   Disabled  -> Idle       once we run again post-wake
//
// Detections flow:
//
//   onResult(ad) -> classifyAdvertisement(..., mac) -> dedupe -> ThreatLog + LOG_INFO + (duty pass:
//   newline batches for ClientNotification; heartbeat: immediate PRIVATE_APP + notification).
//   Policy A: during passive duty BLE+Wi-Fi pass, suppress per-detection PRIVATE_APP to reduce spam;
//   ThreatLog remains the structured sink. One or two ClientNotifications flush at pass end (400-char cells).
class BleThreatDetectorModule : private concurrency::OSThread
{
  public:
    explicit BleThreatDetectorModule(const ValkyriePrefs &prefs);
    ~BleThreatDetectorModule();

    uint32_t getTotalDetections() const { return totalDetections; }
    bool isScanActive() const { return scanActive; }
    bool isWifiThreatPassActive() const { return wifiThreatPassActive; }
    uint32_t getScanStartedMs() const { return scanStartedMs; }
    uint32_t getLastScanWindowEndMs() const { return lastScanWindowEndMs; }
    /** Millis when the NimBLE scan window stopped (hub sprite: BLE outro anchor before/during Wi‑Fi phase). */
    uint32_t getHubBleWindowEndMs() const { return hubBleWindowEndMs; }

    /** Reload prefs from NVS (call after changing threat-type or scan prefs in UI). */
    void reloadPrefs();

    /** Reload ignore list from NVS (call after UI add/remove). */
    void reloadIgnoreList();

    /** Wi‑Fi promiscuous phase: emit after classifying an 802.11 frame (respects prefs + ignore list + dedupe).
     *  `channel` is the receive channel (1/6/11) or 0 if unknown; persisted in the threat log so the
     *  Wi‑Fi heartbeat hunt can lock to it. */
    void emitWifiThreat(const ClassificationResult &cls, const uint8_t mac[6], const char *name, int32_t rssi,
                        uint8_t channel);

    /** Proximity “heartbeat” listen mode for one MAC. `source` selects radio path:
     *  Ble => continuous NimBLE passive scan with duplicates on; Wifi => esp_wifi promiscuous
     *  filtering for `mac`, optionally locked to `lockChannel` (1/6/11; 0 keeps hopping 1/6/11). */
    bool startHeartbeat(const uint8_t mac[6], ThreatType type, ThreatSource source, uint8_t lockChannel);
    void stopHeartbeat();
    bool isHeartbeatActive() const { return heartbeatActive; }
    ThreatSource getHeartbeatSource() const { return heartbeatSource; }

    /** Called from WifiThreatPass while a Wi‑Fi heartbeat hunt is active and the
     *  promiscuous callback sees a frame from the target MAC. Updates EMA / tier. */
    void onWifiHeartbeatFrame(const uint8_t mac[6], uint8_t channel, int32_t rssi);

    HeartbeatSignalTier getHeartbeatSignalTier() const;
    int32_t getHeartbeatLastRssi() const { return heartbeatLastRssi; }
    /** EMA-smoothed dBm used with hysteresis for tier + display; -128 if no samples yet. */
    int32_t getHeartbeatSmoothedRssi() const;
    bool getHeartbeatEverSeenTarget() const { return heartbeatEverSeenTarget; }

  private:
    // OSThread hook.
    int32_t runOnce() override;

    void initScanIfNeeded();
    bool shouldScan() const;
    void startScanWindow();
    /// Stop NimBLE scan hardware if active; does not update hub timing or run Wi-Fi phase.
    void haltBleScan();
    /// End of duty-cycle BLE phase: Wi‑Fi promiscuous pass when enabled (passive duty only), then lastScanWindowEndMs.
    void finalizeDutyThreatPass();
    /// Flush batched notifications and stamp `lastScanWindowEndMs` after BLE + optional Wi‑Fi pass.
    void finishDutyThreatPassEpilogue();
    /// Fast teardown before LS/deep sleep or when handing off to heartbeat: no Wi‑Fi pass.
    void abortBleScanForSleep();

    // Friends needed because the NimBLE callback shim (a private class
    // inside the .cpp) reaches in to call onAdvertisement().
    friend class BleScanCallback;
    void onAdvertisement(NimBLEAdvertisedDevice *advertisedDevice);

    // sleep observers — abort in-flight scan before the system enters LS/SDS.
    int onLightSleep(void *unused);
    int onDeepSleep(void *unused);
    int preflightSleepCb(void *unused);

    CallbackObserver<BleThreatDetectorModule, void *> lightSleepObserver =
        CallbackObserver<BleThreatDetectorModule, void *>(this, &BleThreatDetectorModule::onLightSleep);
    CallbackObserver<BleThreatDetectorModule, void *> deepSleepObserver =
        CallbackObserver<BleThreatDetectorModule, void *>(this, &BleThreatDetectorModule::onDeepSleep);
    CallbackObserver<BleThreatDetectorModule, void *> preflightSleepObserver =
        CallbackObserver<BleThreatDetectorModule, void *>(this, &BleThreatDetectorModule::preflightSleepCb);

    // Bounded mac+type ring used to throttle re-emit of the same threat.
    static constexpr size_t kDedupeCap = 64;
    struct DedupeEntry {
        uint8_t mac[6];
        ThreatType type;
        uint32_t lastSeenMs;
        bool used;
    };
    DedupeEntry dedupe[kDedupeCap]{};
    size_t dedupeNext = 0;

    bool tryAdmitDetection(const uint8_t mac[6], ThreatType type);

    void emitDetection(const ClassificationResult &cls, const uint8_t mac[6], const char *name, int32_t rssi,
                       ThreatSource source, uint8_t channel, bool gpsStalkingTrigger = false,
                       uint32_t gpsStalkingSightings = 0, uint32_t gpsStalkingPlaces = 0);

    void appendPassThreatNotificationLine(const ClassificationResult &cls, const uint8_t mac[6], const char *name,
                                          int32_t rssi, const char *detailBuf);
    void flushPassNotification(bool sleepAbort);

    ValkyriePrefs prefs;
    AirtagStalkingState airtagStalking;

    // Scan state.
    NimBLEScan *scan = nullptr;
    bool scanInitialised = false;
    bool scanActive = false;
    /// At most one threat haptic per passive scan window (`emitDetection`; reset in startScanWindow).
    bool hapticEmittedThisScanWindow = false;
    /// At most one threat sound per passive scan window (`emitDetection`; reset in startScanWindow).
    bool soundEmittedThisScanWindow = false;
    uint32_t scanStartedMs = 0;
    /// Set when a scan window ends (NimBLE stop or forced stop). Zero means
    /// no window has completed yet this session — no inter-window gap then.
    uint32_t lastScanWindowEndMs = 0;
    /// When the BLE phase stopped (`haltBleScan`); hub uses this so Wi‑Fi promiscuous time does not reuse the sleep timeline.
    uint32_t hubBleWindowEndMs = 0;
    /// True while the chunked Wi‑Fi promiscuous threat pass is in progress (hub status).
    volatile bool wifiThreatPassActive = false;
    /// If constant BLE scan is on, start the next window only after async Wi‑Fi pass completes.
    bool deferredConstantBleScanRestart = false;

    // For diagnostics / future UI.
    uint32_t totalDetections = 0;

    // Heartbeat proximity mode (single-target passive listen).
    // NimBLE callbacks may run on another task; volatile so the UI loop sees updates.
    volatile bool heartbeatActive = false;
    uint8_t heartbeatTargetMac[6]{};
    volatile int32_t heartbeatLastRssi = -128;
    volatile uint32_t heartbeatLastAdvMs = 0;
    uint32_t heartbeatSessionStartMs = 0;
    volatile bool heartbeatEverSeenTarget = false;
    ThreatType heartbeatTargetType = ThreatType::None;
    ThreatSource heartbeatSource = ThreatSource::Ble;
    uint8_t heartbeatLockChannel = 0;

    // Heartbeat RSSI: EMA + hysteresis (updated only from onAdvertisement / NimBLE path).
    volatile bool heartbeatSmoothedValid = false;
    volatile int32_t heartbeatSmoothedRssi = -128;
    volatile uint8_t heartbeatLatchedTierU8 = 0; // HeartbeatSignalTier

    /// Passive duty: newline batch for ClientNotification; policy A defers PRIVATE_APP until burst optional future.
    std::string passNotificationBuffer;
    bool passNotificationBatchOpen = false;
};

} // namespace valkyrie

#endif // ARCH_ESP32 && VALKYRIE_FORK
