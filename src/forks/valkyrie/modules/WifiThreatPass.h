#pragma once

#include "configuration.h"

#if defined(ARCH_ESP32) && defined(VALKYRIE_FORK)

class BleThreatDetectorModule;

namespace valkyrie
{

/// Passive Wi‑Fi promiscuous sweep at end of a duty-cycle threat pass (after BLE window).
/// No-op when `!HAS_WIFI`, prefs disable Wi‑Fi scanning, or `mod` is null.
void runWifiThreatPass(BleThreatDetectorModule *mod);

} // namespace valkyrie

#endif
