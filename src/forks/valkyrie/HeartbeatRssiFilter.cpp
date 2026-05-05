#include "HeartbeatRssiFilter.h"

#include <cstdint>

namespace valkyrie
{

HeartbeatSignalTier heartbeatRssiInstaTier(int32_t s)
{
    if (s >= -60)
        return HeartbeatSignalTier::Strong;
    if (s >= -75)
        return HeartbeatSignalTier::Medium;
    return HeartbeatSignalTier::Weak;
}

int32_t heartbeatRssiEmaNext(bool initOrStaleReset, int32_t prevSmoothed, int32_t rawDbm)
{
    if (initOrStaleReset)
        return rawDbm;
    const int64_t prev = prevSmoothed;
    return (int32_t)((kHeartbeatRssiEmaAlpha256 * (int64_t)rawDbm + (256 - kHeartbeatRssiEmaAlpha256) * prev + 128) >> 8);
}

void heartbeatRssiApplyHysteresis(volatile uint8_t *latchedTierU8, int32_t s)
{
    if (!latchedTierU8)
        return;

    auto T = static_cast<HeartbeatSignalTier>(*latchedTierU8);
    if (T == HeartbeatSignalTier::None) {
        *latchedTierU8 = static_cast<uint8_t>(heartbeatRssiInstaTier(s));
        return;
    }
    switch (T) {
    case HeartbeatSignalTier::Weak:
        if (s >= -73)
            *latchedTierU8 = static_cast<uint8_t>(HeartbeatSignalTier::Medium);
        break;
    case HeartbeatSignalTier::Medium:
        if (s < -77)
            *latchedTierU8 = static_cast<uint8_t>(HeartbeatSignalTier::Weak);
        else if (s >= -58)
            *latchedTierU8 = static_cast<uint8_t>(HeartbeatSignalTier::Strong);
        break;
    case HeartbeatSignalTier::Strong:
        if (s < -62)
            *latchedTierU8 = static_cast<uint8_t>(HeartbeatSignalTier::Medium);
        break;
    default:
        break;
    }
}

} // namespace valkyrie
