#pragma once

#include <stdint.h>

namespace valkyrie
{

/// Duration (ms) of the BLE “start scan” strip played in reverse before the Wi‑Fi phase in the hub sprite.
/// Must match `ValkyrieHubFrame.cpp`: `kBleStartFrameCount * kFrameMsIntro` (6 × 160).
constexpr uint32_t kHubBleScanStripOutroMs = 6 * 160;

} // namespace valkyrie
