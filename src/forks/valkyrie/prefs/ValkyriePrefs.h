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
    uint16_t scanIntervalSecs; // target seconds between *starts* of consecutive windows (idle gap =
                               // max(0, scanIntervalSecs - scanWindowSecs); see BleThreatDetectorModule)
    uint16_t scanWindowSecs;   // duration of each passive scan window
    uint8_t minBatteryPct;     // skip scans below this battery level
    uint16_t dedupeWindowSecs; // mac+type re-emit throttle

    // Bits 0..5 enable scanning for ThreatType::Airtag..Drone (bit = 1 => on).
    static constexpr uint8_t kThreatScanMaskAll = 0x3F;
    uint8_t threatScanMask;

    // When true, no idle gap between BLE scan windows (higher power use). NVS key const_scn.
    bool constantBleScanMode;

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

} // namespace valkyrie
