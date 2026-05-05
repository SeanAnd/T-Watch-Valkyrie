#pragma once

#include "HeartbeatSignalTier.h"

#include <cstdint>

namespace valkyrie
{

/// Same window as `BleThreatDetectorModule::getHeartbeatSignalTier()` staleness.
constexpr uint32_t kHeartbeatRssiStaleMs = 10000;
/// EMA alpha = 64/256 = 0.25 on integer dBm.
constexpr int32_t kHeartbeatRssiEmaAlpha256 = 64;

/** Nominal tier from smoothed (or raw) dBm — used after init / stale reset. */
HeartbeatSignalTier heartbeatRssiInstaTier(int32_t sDbm);

/**
 * Exponential moving average of RSSI. When `initOrStaleReset`, returns `rawDbm`.
 * Otherwise `prevSmoothed` must be a prior EMA output (not -128 sentinel unless first call).
 */
int32_t heartbeatRssiEmaNext(bool initOrStaleReset, int32_t prevSmoothed, int32_t rawDbm);

/**
 * Hysteresis state machine: reads/writes `*latchedTierU8` as `static_cast<uint8_t>(HeartbeatSignalTier)`.
 * If latched is `None`, sets instant tier from `smoothedDbm`.
 */
void heartbeatRssiApplyHysteresis(volatile uint8_t *latchedTierU8, int32_t smoothedDbm);

} // namespace valkyrie
