#pragma once

// Enum is host-testable (no Arduino / configuration.h). `heartbeatTierLabel`
// is only declared when building the Valkyrie fork; the .cpp is likewise
// fork-only in PlatformIO, so the symbol always links there.
namespace valkyrie
{

/// UI + feedback tier for heartbeat proximity (must stay in sync with sprite loop windows).
enum class HeartbeatSignalTier { None, Weak, Medium, Strong };

} // namespace valkyrie

#if defined(VALKYRIE_FORK)

namespace valkyrie
{

const char *heartbeatTierLabel(HeartbeatSignalTier t);

} // namespace valkyrie

#endif
