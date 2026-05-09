#pragma once

#include "../modules/BleClassifier.h"

#include <stdint.h>

namespace valkyrie
{

// Lives in its own NVS namespace ("valkyrie") via the Arduino Preferences
// library, deliberately separate from upstream's "meshtastic" namespace so
// rebases never collide on key names or layout.
struct ValkyriePrefs {
    bool bleThreatDetectorEnabled;
    uint16_t scanIntervalSecs; // target seconds between *starts* of consecutive threat passes (idle gap =
                               // max(0, scanIntervalSecs - scanWindowSecs); pass = BLE window + Wi‑Fi threat pass)
    uint16_t scanWindowSecs;   // duration of each passive scan window
    uint8_t minBatteryPct;     // skip scans below this battery level
    uint16_t dedupeWindowSecs; // mac+type re-emit throttle

    // Bits 0..5 enable scanning for ThreatType::Airtag..Drone (bit = 1 => on).
    static constexpr uint8_t kThreatScanMaskAll = 0x3F;
    uint8_t threatScanMask;

    /// When false, skip the NimBLE passive scan window; Wi‑Fi-only duty may still run (HAS_WIFI).
    bool bleThreatPhaseEnabled;

    // Wi‑Fi promiscuous phase (end of BLE window, or standalone when BLE phase is off). Brief STA disruption.
    bool wifiThreatPhaseEnabled;
    /// Bits 0..4 enable ThreatType::WifiDeauth..WifiMultiSsid (7..11).
    static constexpr uint8_t kWifiThreatScanMaskAll = 0x1F;
    uint8_t wifiThreatScanMask;
    uint16_t wifiThreatPassMs;         // total time budget per pass
    uint16_t wifiThreatChannelDwellMs; // dwell per channel hop (1/6/11)

    // When true, no idle gap between BLE scan windows (higher power use). NVS key const_scn.
    bool constantBleScanMode;

    // Passive threat detection feedback (emitDetection only; heartbeat hunt mode ignores these).
    bool threatDetectionHapticEnabled; // NVS key thr_hapt
    bool threatDetectionSoundEnabled;  // NVS key thr_snd

    // AirTag-only: when GPS (or fixed position) is usable, require this many
    // sightings at least this many distinct place cells before emit. NVS keys stk_*.
    uint8_t stalkMinSightings;
    uint8_t stalkMinDistinctPlaces;
    uint16_t stalkMinSeparationM;
    uint32_t stalkEntryTtlSecs;

    // Load with defaults seeded if nothing has ever been written.
    static ValkyriePrefs load();

    // Persist back to NVS. Phase 1 only writes when the user changes
    // something via the future serial CLI; on first boot we just seed
    // defaults and leave the namespace populated.
    void save() const;

    // Defaults baked alongside userPrefs.valkyrie.jsonc.
    static ValkyriePrefs defaults();

    bool isThreatTypeEnabled(ThreatType t) const;
    void setThreatTypeEnabled(ThreatType t, bool on);

    bool isWifiThreatTypeEnabled(ThreatType t) const;
    void setWifiThreatTypeEnabled(ThreatType t, bool on);

    /** True when `beginWifiThreatPass` would proceed past early prefs checks (WifiThreatPass.cpp). */
    bool isWifiThreatPassConfigured() const;
};

// ----------------------------------------------------------------------------

inline bool ValkyriePrefs::isThreatTypeEnabled(ThreatType t) const
{
    uint8_t v = static_cast<uint8_t>(t);
    if (v < 1 || v > 6)
        return false;
    return (threatScanMask & static_cast<uint8_t>(1u << (v - 1))) != 0;
}

inline void ValkyriePrefs::setThreatTypeEnabled(ThreatType t, bool on)
{
    uint8_t v = static_cast<uint8_t>(t);
    if (v < 1 || v > 6)
        return;
    uint8_t bit = static_cast<uint8_t>(1u << (v - 1));
    if (on)
        threatScanMask |= bit;
    else
        threatScanMask = static_cast<uint8_t>(threatScanMask & static_cast<uint8_t>(~bit));
}

inline bool ValkyriePrefs::isWifiThreatTypeEnabled(ThreatType t) const
{
    uint8_t v = static_cast<uint8_t>(t);
    if (v < 7 || v > 11)
        return false;
    return (wifiThreatScanMask & static_cast<uint8_t>(1u << (v - 7))) != 0;
}

inline void ValkyriePrefs::setWifiThreatTypeEnabled(ThreatType t, bool on)
{
    uint8_t v = static_cast<uint8_t>(t);
    if (v < 7 || v > 11)
        return;
    uint8_t bit = static_cast<uint8_t>(1u << (v - 7));
    if (on)
        wifiThreatScanMask |= bit;
    else
        wifiThreatScanMask = static_cast<uint8_t>(wifiThreatScanMask & static_cast<uint8_t>(~bit));
}

inline bool ValkyriePrefs::isWifiThreatPassConfigured() const
{
    if (!wifiThreatPhaseEnabled)
        return false;
    if (isThreatTypeEnabled(ThreatType::Flock))
        return true;
    if (isThreatTypeEnabled(ThreatType::Drone))
        return true;
    for (unsigned u = 7; u <= 11; ++u) {
        if (isWifiThreatTypeEnabled(static_cast<ThreatType>((uint8_t)u)))
            return true;
    }
    return false;
}

} // namespace valkyrie
