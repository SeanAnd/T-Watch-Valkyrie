#pragma once

#include <cstdint>

// Enum is host-testable (no Arduino / configuration.h). Valkyrie-only helpers
// live behind VALKYRIE_FORK because the .cpp is likewise fork-only in PlatformIO.
namespace valkyrie
{

/// UI + feedback tier for heartbeat proximity (must stay in sync with sprite loop windows).
enum class HeartbeatSignalTier { None, VeryWeak, Weak, Medium, MediumStrong, Strong, VeryStrong };

} // namespace valkyrie

#if defined(VALKYRIE_FORK)

namespace valkyrie
{

const char *heartbeatTierLabel(HeartbeatSignalTier t);
uint32_t heartbeatTierPulsePeriodMs(HeartbeatSignalTier t);

} // namespace valkyrie

#endif
