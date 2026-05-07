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
//                            constantBleScanMode), else max(0, scanIntervalSecs
//                            - scanWindowSecs) from last window end; PowerFSM
//                            in {ON, DARK}, battery OK, NimBLE initialised
//   Scanning  -> Idle       after scan_window elapses (NimBLE stop)
//   any       -> Disabled   on notifyDeepSleep / notifyLightSleep
//   Disabled  -> Idle       once we run again post-wake
//
// Detections flow:
//
//   onResult(ad) -> classifyAdvertisement(..., mac) -> dedupe -> {ThreatLog,
//                                                         service->sendToPhone(PRIVATE_APP)}
class BleThreatDetectorModule : private concurrency::OSThread
{
  public:
    explicit BleThreatDetectorModule(const ValkyriePrefs &prefs);
    ~BleThreatDetectorModule();

    uint32_t getTotalDetections() const { return totalDetections; }
    bool isScanActive() const { return scanActive; }
    uint32_t getScanStartedMs() const { return scanStartedMs; }
    uint32_t getLastScanWindowEndMs() const { return lastScanWindowEndMs; }

    /** Reload prefs from NVS (call after changing threat-type or scan prefs in UI). */
    void reloadPrefs();

    /** Reload ignore list from NVS (call after UI add/remove). */
    void reloadIgnoreList();

    /** Proximity “heartbeat” listen mode for one MAC: continuous passive scan, duplicates on, no logging/phone. */
    bool startHeartbeat(const uint8_t mac[6], ThreatType type);
    void stopHeartbeat();
    bool isHeartbeatActive() const { return heartbeatActive; }

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
    void stopScanWindow();

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
                       bool gpsStalkingTrigger = false, uint32_t gpsStalkingSightings = 0, uint32_t gpsStalkingPlaces = 0);

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

    // Heartbeat RSSI: EMA + hysteresis (updated only from onAdvertisement / NimBLE path).
    volatile bool heartbeatSmoothedValid = false;
    volatile int32_t heartbeatSmoothedRssi = -128;
    volatile uint8_t heartbeatLatchedTierU8 = 0; // HeartbeatSignalTier
};

} // namespace valkyrie

#endif // ARCH_ESP32 && VALKYRIE_FORK
