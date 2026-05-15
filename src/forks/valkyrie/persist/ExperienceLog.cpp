#include "ExperienceLog.h"

#include "configuration.h"

#if defined(ARCH_ESP32) && defined(VALKYRIE_FORK)

#include "concurrency/Lock.h"
#include "concurrency/LockGuard.h"

#include <Arduino.h>
#include <cstdio>
#include <cstring>

namespace valkyrie
{
namespace ExperienceLog
{
namespace
{

struct StoredEntry {
    uint32_t amount = 0;
    uint32_t wallMs = 0;
    Source source = Source::Threat;
    char detail[kDetailBytes] = {0};
};

StoredEntry gRing[kMaxEntries]{};
size_t gHead = 0;
size_t gCount = 0;

concurrency::Lock &logLock()
{
    static concurrency::Lock lock;
    return lock;
}

const char *sourceLabel(Source source)
{
    switch (source) {
    case Source::Threat:
        return "Threat";
    case Source::Mesh:
        return "Mesh";
    case Source::Wardrive:
        return "Wardrive";
    default:
        return "XP";
    }
}

} // namespace

void record(Source source, uint32_t amount, const char *detail)
{
    if (amount == 0)
        return;

    concurrency::Lock &lock = logLock();
    concurrency::LockGuard guard(&lock);

    StoredEntry &e = gRing[gHead];
    e.amount = amount;
    e.wallMs = millis();
    e.source = source;
    if (detail && detail[0]) {
        strncpy(e.detail, detail, sizeof(e.detail) - 1);
        e.detail[sizeof(e.detail) - 1] = '\0';
    } else {
        snprintf(e.detail, sizeof(e.detail), "%s", sourceLabel(source));
    }

    gHead = (gHead + 1U) % kMaxEntries;
    if (gCount < kMaxEntries)
        gCount++;
}

void clear()
{
    concurrency::Lock &lock = logLock();
    concurrency::LockGuard guard(&lock);
    gHead = 0;
    gCount = 0;
    memset(gRing, 0, sizeof(gRing));
}

size_t count()
{
    concurrency::Lock &lock = logLock();
    concurrency::LockGuard guard(&lock);
    return gCount;
}

bool readRecent(size_t recentIndex, Entry *out)
{
    if (!out)
        return false;

    concurrency::Lock &lock = logLock();
    concurrency::LockGuard guard(&lock);

    if (recentIndex >= gCount)
        return false;

    const size_t newest = (gHead + kMaxEntries - 1U) % kMaxEntries;
    const size_t slot = (newest + kMaxEntries - (recentIndex % kMaxEntries)) % kMaxEntries;
    const StoredEntry &src = gRing[slot];

    out->amount = src.amount;
    out->ageSecs = (millis() - src.wallMs) / 1000U;
    out->source = src.source;
    strncpy(out->detail, src.detail, sizeof(out->detail) - 1);
    out->detail[sizeof(out->detail) - 1] = '\0';
    return true;
}

bool formatRecentLine(size_t recentIndex, char *out, size_t outCap)
{
    if (!out || outCap == 0)
        return false;
    out[0] = '\0';

    Entry e{};
    if (!readRecent(recentIndex, &e))
        return false;

    uint32_t age = e.ageSecs;
    if (age > 9999U)
        age = 9999U;
    snprintf(out, outCap, "+%u %s (%us)", (unsigned)e.amount, e.detail, (unsigned)age);
    return true;
}

} // namespace ExperienceLog
} // namespace valkyrie

#else // !ARCH_ESP32 || !VALKYRIE_FORK

namespace valkyrie
{
namespace ExperienceLog
{
void record(Source, uint32_t, const char *) {}
void clear() {}
size_t count() { return 0; }
bool readRecent(size_t, Entry *) { return false; }
bool formatRecentLine(size_t, char *, size_t) { return false; }
} // namespace ExperienceLog
} // namespace valkyrie

#endif
