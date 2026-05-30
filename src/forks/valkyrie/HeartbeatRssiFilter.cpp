#include "HeartbeatRssiFilter.h"

#include <cstdint>

namespace valkyrie
{

HeartbeatSignalTier heartbeatRssiInstaTier(int32_t s)
{
    if (s >= -48)
        return HeartbeatSignalTier::VeryStrong;
    if (s >= -58)
        return HeartbeatSignalTier::Strong;
    if (s >= -68)
        return HeartbeatSignalTier::MediumStrong;
    if (s >= -78)
        return HeartbeatSignalTier::Medium;
    if (s >= -88)
        return HeartbeatSignalTier::Weak;
    return HeartbeatSignalTier::VeryWeak;
}

static void latchTier(volatile uint8_t *latchedTierU8, HeartbeatSignalTier tier)
{
    *latchedTierU8 = static_cast<uint8_t>(tier);
}

static bool isKnownTier(HeartbeatSignalTier tier)
{
    switch (tier) {
    case HeartbeatSignalTier::None:
    case HeartbeatSignalTier::VeryWeak:
    case HeartbeatSignalTier::Weak:
    case HeartbeatSignalTier::Medium:
    case HeartbeatSignalTier::MediumStrong:
    case HeartbeatSignalTier::Strong:
    case HeartbeatSignalTier::VeryStrong:
        return true;
    default:
        return false;
    }
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
    if (!isKnownTier(T) || T == HeartbeatSignalTier::None) {
        latchTier(latchedTierU8, heartbeatRssiInstaTier(s));
        return;
    }
    // Deadbands around nominal boundaries keep EMA wiggle from flipping adjacent tiers.
    switch (T) {
    case HeartbeatSignalTier::VeryWeak:
        if (s >= -84)
            latchTier(latchedTierU8, HeartbeatSignalTier::Weak);
        break;
    case HeartbeatSignalTier::Weak:
        if (s < -92)
            latchTier(latchedTierU8, HeartbeatSignalTier::VeryWeak);
        else if (s >= -74)
            latchTier(latchedTierU8, HeartbeatSignalTier::Medium);
        break;
    case HeartbeatSignalTier::Medium:
        if (s < -82)
            latchTier(latchedTierU8, HeartbeatSignalTier::Weak);
        else if (s >= -64)
            latchTier(latchedTierU8, HeartbeatSignalTier::MediumStrong);
        break;
    case HeartbeatSignalTier::MediumStrong:
        if (s < -72)
            latchTier(latchedTierU8, HeartbeatSignalTier::Medium);
        else if (s >= -54)
            latchTier(latchedTierU8, HeartbeatSignalTier::Strong);
        break;
    case HeartbeatSignalTier::Strong:
        if (s < -62)
            latchTier(latchedTierU8, HeartbeatSignalTier::MediumStrong);
        else if (s >= -44)
            latchTier(latchedTierU8, HeartbeatSignalTier::VeryStrong);
        break;
    case HeartbeatSignalTier::VeryStrong:
        if (s < -52)
            latchTier(latchedTierU8, HeartbeatSignalTier::Strong);
        break;
    default:
        break;
    }
}

} // namespace valkyrie
