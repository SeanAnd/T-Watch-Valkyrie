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
        return 5500;
    case HeartbeatSignalTier::Weak:
        return 4000;
    case HeartbeatSignalTier::Medium:
        return 2750;
    case HeartbeatSignalTier::MediumStrong:
        return 1900;
    case HeartbeatSignalTier::Strong:
        return 1150;
    case HeartbeatSignalTier::VeryStrong:
        return 650;
    case HeartbeatSignalTier::None:
    default:
        return 0;
    }
}

} // namespace valkyrie

#endif
