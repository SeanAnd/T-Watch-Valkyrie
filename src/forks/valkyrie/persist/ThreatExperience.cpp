#include "ThreatExperience.h"

#include "configuration.h"

#if defined(ARCH_ESP32) && defined(VALKYRIE_FORK)

#include "ThreatLog.h"
#include "ThreatLogDecode.h"
#include "FSCommon.h"
#include "SPILock.h"

#include <Preferences.h>

#include <atomic>
#include <cstdint>
#include <cstring>

namespace valkyrie
{
namespace ThreatExperience
{
namespace
{

static constexpr const char *kNvsNamespace = "valkyrie";
static constexpr const char *kKeyTotalXp = "thr_xp";
/// 0 = migration from current `threats.log` still pending; 1 = done (either backfilled or post-clear baseline).
static constexpr const char *kKeyXpMigr = "xp_mig";

/// Hot path: hub frame draws read this every render. NVS is expensive, so cache the value
/// in-process and invalidate from the writer paths (`onDistinctThreatLogged`, `onThreatLogCleared`).
static std::atomic<uint32_t> gCachedTotalXp{0};
static std::atomic<bool> gCachedTotalValid{false};

using threatlog_decode::decodeIdentity;

/// Per-threat XP (rarer detections dominate). Tweaked vs relative frequency / surprise value on the street.
constexpr unsigned xpForThreatType(ThreatType t)
{
    switch (t) {
    case ThreatType::HCSkimmer:
        return 40;
    case ThreatType::WifiDeauth:
        return 12;
    case ThreatType::Airtag:
        return 10;
    case ThreatType::Flipper:
        return 20;
    case ThreatType::Flock:
        return 24;
    case ThreatType::WifiMultiSsid:
        return 26;
    case ThreatType::WifiEapol:
        return 28;
    case ThreatType::WifiSuspiciousAp:
        return 32;
    case ThreatType::SmartGlasses:
        return 10;
    case ThreatType::WifiPwnagotchi:
        return 44;
    case ThreatType::Drone:
        return 52;
    case ThreatType::None:
    default:
        return 8;
    }
}

static void migrateTotalsFromThreatLogIfNeededLocked()
{
    Preferences prefs;
    if (!prefs.begin(kNvsNamespace, /*readOnly=*/true))
        return;
    if (prefs.getUChar(kKeyXpMigr, 0) != 0) {
        prefs.end();
        return;
    }
    prefs.end();

    constexpr size_t bufCap = 256;
    char buf[bufCap];

    uint32_t fromFile = 0;
    if (FSCom.exists(ThreatLog::kPath)) {
        auto file = FSCom.open(ThreatLog::kPath, FILE_O_READ);
        if (file) {
            while (file.available()) {
                String line = file.readStringUntil('\n');
                line.trim();
                if (line.length() == 0)
                    continue;
                strncpy(buf, line.c_str(), bufCap - 1);
                buf[bufCap - 1] = '\0';
                ThreatType ty = ThreatType::None;
                uint8_t mac[6];
                if (decodeIdentity(buf, &ty, mac))
                    fromFile += xpForThreatType(ty);
            }
            file.close();
        }
    }

    if (!prefs.begin(kNvsNamespace, /*readOnly=*/false))
        return;
    uint32_t cur = prefs.getUInt(kKeyTotalXp, 0);
    uint32_t merged = cur > fromFile ? cur : fromFile;
    prefs.putUInt(kKeyTotalXp, merged);
    prefs.putUChar(kKeyXpMigr, 1);
    prefs.end();
}

} // namespace

LevelProgress levelProgress(uint32_t totalXp)
{
    LevelProgress out{};
    /// XP spent to climb from displayed level `L` to `L+1` is `kTierBase + kTierScale * L` — higher levels cost more.
    constexpr uint64_t kTierBase = 140;
    constexpr uint64_t kTierScale = 45;

    auto spentThroughCompletedTiers = [kTierBase, kTierScale](unsigned tiersDone) -> uint64_t {
        uint64_t n = tiersDone;
        return n * kTierBase + kTierScale * (n * (n + 1U)) / 2;
    };

    unsigned lo = 0;
    unsigned hi = 70000;
    while (lo + 1 < hi) {
        unsigned mid = (lo + hi) / 2;
        uint64_t s = spentThroughCompletedTiers(mid);
        if (s <= (uint64_t)totalXp)
            lo = mid;
        else
            hi = mid;
    }
    const unsigned nCompleted = lo;

    uint64_t spentForCompleted = spentThroughCompletedTiers(nCompleted);
    out.level = nCompleted + 1;
    uint64_t tier = kTierBase + kTierScale * (uint64_t)out.level;
    if (tier == 0)
        tier = 1;
    if (tier > UINT32_MAX)
        tier = UINT32_MAX;
    out.xpNeededThisLevel = (uint32_t)tier;

    uint64_t into = (uint64_t)totalXp - spentForCompleted;
    if (into > tier)
        into = tier;
    out.xpTowardNext = (uint32_t)into;
    return out;
}

uint32_t totalPoints()
{
    if (gCachedTotalValid.load(std::memory_order_acquire))
        return gCachedTotalXp.load(std::memory_order_relaxed);

    {
        concurrency::LockGuard guard(spiLock);
        migrateTotalsFromThreatLogIfNeededLocked();
    }

    Preferences prefs;
    if (!prefs.begin(kNvsNamespace, /*readOnly=*/true))
        return 0;
    uint32_t v = prefs.getUInt(kKeyTotalXp, 0);
    prefs.end();

    gCachedTotalXp.store(v, std::memory_order_relaxed);
    gCachedTotalValid.store(true, std::memory_order_release);
    return v;
}

void onDistinctThreatLogged(const char *threatWireTypeToken)
{
    ThreatType t = threatWireTypeToken ? threatlog_decode::wireTokenToThreatType(threatWireTypeToken) : ThreatType::None;
    const unsigned delta = xpForThreatType(t);

    Preferences prefs;
    if (!prefs.begin(kNvsNamespace, /*readOnly=*/false))
        return;
    uint32_t cur = prefs.getUInt(kKeyTotalXp, 0);
    uint32_t next = cur + delta;
    if (next < cur)
        next = UINT32_MAX;
    prefs.putUInt(kKeyTotalXp, next);
    prefs.end();

    gCachedTotalXp.store(next, std::memory_order_relaxed);
    gCachedTotalValid.store(true, std::memory_order_release);
}

void onThreatLogCleared()
{
    Preferences prefs;
    if (!prefs.begin(kNvsNamespace, /*readOnly=*/false))
        return;
    prefs.putUInt(kKeyTotalXp, 0);
    prefs.putUChar(kKeyXpMigr, 1);
    prefs.end();

    gCachedTotalXp.store(0, std::memory_order_relaxed);
    gCachedTotalValid.store(true, std::memory_order_release);
}

} // namespace ThreatExperience
} // namespace valkyrie

#endif
