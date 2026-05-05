#include "HeartbeatSignalTier.h"

#if defined(VALKYRIE_FORK)

namespace valkyrie
{

const char *heartbeatTierLabel(HeartbeatSignalTier t)
{
    switch (t) {
    case HeartbeatSignalTier::None:
        return "None";
    case HeartbeatSignalTier::Weak:
        return "Weak";
    case HeartbeatSignalTier::Medium:
        return "Medium";
    case HeartbeatSignalTier::Strong:
        return "Strong";
    default:
        return "None";
    }
}

} // namespace valkyrie

#endif
