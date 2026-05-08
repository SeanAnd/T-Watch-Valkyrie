#pragma once

#include "../prefs/ValkyriePrefs.h"

#include <stdint.h>

namespace valkyrie
{
namespace ble_scan_schedule
{

/// Milliseconds to wait after a threat pass completes (BLE scan window + Wi‑Fi threat phase);
/// 0 when constant scan mode chains BLE windows back-to-back (Wi‑Fi still runs between windows).
inline uint32_t idleGapMsAfterWindow(const ValkyriePrefs &p)
{
    if (p.constantBleScanMode && p.bleThreatPhaseEnabled)
        return 0;
    uint32_t gapSecs = (p.scanIntervalSecs > p.scanWindowSecs) ? (uint32_t)(p.scanIntervalSecs - p.scanWindowSecs) : 0U;
    return gapSecs * 1000U;
}

/// OSThread sleep when NimBLE scan start fails (shorter retry when duty cycle is already aggressive).
inline int32_t failedStartBackoffMs(const ValkyriePrefs &p)
{
    if (p.constantBleScanMode && p.bleThreatPhaseEnabled)
        return 5000;
    return (int32_t)p.scanIntervalSecs * 1000;
}

} // namespace ble_scan_schedule
} // namespace valkyrie
