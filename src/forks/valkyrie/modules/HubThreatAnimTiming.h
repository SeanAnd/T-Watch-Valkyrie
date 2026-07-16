#pragma once

#include <stdint.h>

namespace valkyrie
{

constexpr unsigned kHubScanIntroFrameCount = 6;
constexpr uint32_t kHubScanIntroFrameMs = 480;

/// Duration of the scan strip used to synchronize the detector and hub animation.
constexpr uint32_t kHubBleScanStripOutroMs = kHubScanIntroFrameCount * kHubScanIntroFrameMs;

} // namespace valkyrie
