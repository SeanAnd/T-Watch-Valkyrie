#pragma once

#include <stddef.h>
#include <stdint.h>

namespace valkyrie
{
namespace ExperienceLog
{

static constexpr size_t kMaxEntries = 12;
static constexpr size_t kDetailBytes = 40;

enum class Source : uint8_t {
    Threat = 0,
    Mesh = 1,
    Wardrive = 2,
};

struct Entry {
    uint32_t amount = 0;
    uint32_t ageSecs = 0;
    Source source = Source::Threat;
    char detail[kDetailBytes] = {0};
};

/// Append a recent XP event to the fixed-size rolling buffer. RAM-only by design:
/// the lifetime XP totals stay in NVS, while this UI log only shows fresh context.
void record(Source source, uint32_t amount, const char *detail);

/// Clear the recent in-RAM XP event list.
void clear();

/// Number of currently visible entries, capped at kMaxEntries.
size_t count();

/// Read entry by newest-first index (0 = most recent). Returns false when out of range.
bool readRecent(size_t recentIndex, Entry *out);

/// Convenience formatter for the watch menu, e.g. "+24 Flock threat (12s)".
bool formatRecentLine(size_t recentIndex, char *out, size_t outCap);

} // namespace ExperienceLog
} // namespace valkyrie
