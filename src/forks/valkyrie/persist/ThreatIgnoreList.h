#pragma once

#include "../modules/BleClassifier.h"

#include <stddef.h>
#include <stdint.h>

namespace valkyrie
{

// NVS-backed list of (ThreatType, BLE MAC) pairs to suppress in
// BleThreatDetectorModule (no log append, haptic, or phone event).
class ThreatIgnoreList
{
  public:
    static constexpr size_t kMaxEntries = 32;

    // Reload RAM cache from NVS (call at boot and after UI edits).
    static void reloadCache();

    static bool isIgnored(ThreatType t, const uint8_t mac[6]);
    static size_t count();

    // Storage order is append order; index 0 is oldest entry.
    static bool getEntry(size_t index, ThreatType *typeOut, uint8_t macOut[6]);

    // Returns true if the pair is present after the call (added or duplicate).
    // Returns false if list is full and the pair was not present.
    static bool add(ThreatType t, const uint8_t mac[6]);

    static void removeAt(size_t index);

  private:
    static bool persistLocked();
};

} // namespace valkyrie
