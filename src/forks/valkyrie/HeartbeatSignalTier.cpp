#include "HeartbeatSignalTier.h"

#if defined(VALKYRIE_FORK)

namespace valkyrie
{

const char *heartbeatTierLabel(HeartbeatSignalTier t)
{
    switch (t) {
    case HeartbeatSignalTier::None:
        return "None";
    case HeartbeatSignalTier::VeryWeak:
        return "Very weak";
    case HeartbeatSignalTier::Weak:
        return "Weak";
    case HeartbeatSignalTier::Medium:
        return "Medium";
    case HeartbeatSignalTier::MediumStrong:
        return "Medium strong";
    case HeartbeatSignalTier::Strong:
        return "Strong";
    case HeartbeatSignalTier::VeryStrong:
        return "Very strong";
    default:
        return "None";
    }
}

uint32_t heartbeatTierPulsePeriodMs(HeartbeatSignalTier t)
{
    switch (t) {
    case HeartbeatSignalTier::VeryWeak:
        return 2200;
    case HeartbeatSignalTier::Weak:
        return 1600;
    case HeartbeatSignalTier::Medium:
        return 1100;
    case HeartbeatSignalTier::MediumStrong:
        return 760;
    case HeartbeatSignalTier::Strong:
        return 460;
    case HeartbeatSignalTier::VeryStrong:
        return 260;
    case HeartbeatSignalTier::None:
    default:
        return 0;
    }
}

} // namespace valkyrie

#endif
