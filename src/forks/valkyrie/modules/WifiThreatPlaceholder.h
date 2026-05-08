#pragma once

#include "configuration.h"

#if defined(ARCH_ESP32) && defined(VALKYRIE_FORK)

namespace valkyrie
{

/// Placeholder for future Wi-Fi threat scanning during a duty-cycle pass.
/// Must remain cheap (no STA/AP bring-up, no WiFi.scanNetworks) so mesh/BLE coexistence stays predictable.
/// Logs only; do not push stub strings to ClientNotification (avoid noisy alerts every pass).
void runWifiThreatPlaceholderPass();

} // namespace valkyrie

#endif // ARCH_ESP32 && VALKYRIE_FORK
