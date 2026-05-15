#include "MeshExperience.h"

#include "configuration.h"

#if defined(ARCH_ESP32) && defined(VALKYRIE_FORK)

#include "ExperienceLog.h"
#include "ThreatExperience.h"
#include "mesh/RadioLibInterface.h"
#include "mesh/Router.h"

#include <Preferences.h>

#include <atomic>
#include <cstdio>
#include <cstdint>

namespace valkyrie
{
namespace MeshExperience
{
namespace
{

static constexpr const char *kNvsNamespace = "valkyrie";
static constexpr const char *kKeyMeshXp = "mesh_xp";
/// Reserved sentinel for future schema bumps. Currently unused (no migration on v1).
static constexpr const char *kKeyMeshXpMigr = "mxp_mig";

/// Per-tick weight constants, expressed in tenths of an XP so the `rxGood` 0.1/packet credit
/// and the `rxDupe` 0.5/packet penalty stay integer-only.
constexpr uint32_t kTenthsPerRelay = 100;        // 10 XP per forwarded packet
constexpr uint32_t kTenthsPerRelayCanceled = 10; // 1 XP per "I almost relayed" event
constexpr uint32_t kTenthsPerRxGood = 1;         // 0.1 XP per witnessed packet
constexpr uint32_t kTenthsPerRxDupePenalty = 5;  // 0.5 XP penalty per duplicate (clamped)

/// Hot path: hub frame reads `totalPoints()` every render via `totalCombinedXp()`. NVS reads are
/// expensive, so cache and invalidate from the writer paths (`flushPending`, `resetMeshXp`).
static std::atomic<uint32_t> gCachedMeshXp{0};
static std::atomic<bool> gCachedMeshValid{false};

/// RAM-only snapshot of the radio/router counters at the previous tick. Counters reset on reboot, so
/// we don't persist this — the first tick after boot just baselines and awards nothing.
struct CounterSnapshot {
    uint32_t txRelay;
    uint32_t txRelayCanceled;
    uint32_t rxGood;
    uint32_t rxDupe;
    bool valid;
};
static CounterSnapshot gSnap{};

/// Fractional XP accumulator (tenths). RAM-only: at most ~0.9 XP can be lost on reboot, which is
/// well below any user-visible threshold and avoids per-tick NVS writes.
static uint32_t gPendingTenths = 0;

static void persistTotal(uint32_t newTotal)
{
    Preferences prefs;
    if (!prefs.begin(kNvsNamespace, /*readOnly=*/false))
        return;
    prefs.putUInt(kKeyMeshXp, newTotal);
    prefs.end();

    gCachedMeshXp.store(newTotal, std::memory_order_relaxed);
    gCachedMeshValid.store(true, std::memory_order_release);
}

static uint32_t loadTotal()
{
    if (gCachedMeshValid.load(std::memory_order_acquire))
        return gCachedMeshXp.load(std::memory_order_relaxed);

    Preferences prefs;
    if (!prefs.begin(kNvsNamespace, /*readOnly=*/true))
        return 0;
    uint32_t v = prefs.getUInt(kKeyMeshXp, 0);
    prefs.end();

    gCachedMeshXp.store(v, std::memory_order_relaxed);
    gCachedMeshValid.store(true, std::memory_order_release);
    return v;
}

} // namespace

uint32_t totalPoints()
{
    return loadTotal();
}

uint32_t totalCombinedXp()
{
    uint64_t sum = (uint64_t)ThreatExperience::totalPoints() + (uint64_t)totalPoints();
    return sum > UINT32_MAX ? UINT32_MAX : (uint32_t)sum;
}

void resetMeshXp()
{
    gPendingTenths = 0;
    gSnap.valid = false;
    persistTotal(0);
}

void onRadioCountersTick()
{
    auto *radio = RadioLibInterface::instance;
    if (!radio || !router)
        return;

    CounterSnapshot cur{radio->txRelay, router->txRelayCanceled, radio->rxGood, router->rxDupe, true};

    if (!gSnap.valid) {
        gSnap = cur;
        return;
    }

    if (cur.txRelay < gSnap.txRelay || cur.txRelayCanceled < gSnap.txRelayCanceled || cur.rxGood < gSnap.rxGood ||
        cur.rxDupe < gSnap.rxDupe) {
        // Counter regressed -> a reboot or counter reset happened between ticks. Re-baseline silently.
        gSnap = cur;
        return;
    }

    uint32_t dRelay = cur.txRelay - gSnap.txRelay;
    uint32_t dCancel = cur.txRelayCanceled - gSnap.txRelayCanceled;
    uint32_t dRxGood = cur.rxGood - gSnap.rxGood;
    uint32_t dRxDupe = cur.rxDupe - gSnap.rxDupe;

    uint64_t gainedTenths = (uint64_t)kTenthsPerRelay * dRelay + (uint64_t)kTenthsPerRelayCanceled * dCancel +
                            (uint64_t)kTenthsPerRxGood * dRxGood;
    uint64_t penaltyTenths = (uint64_t)kTenthsPerRxDupePenalty * dRxDupe;
    uint64_t netTenths = gainedTenths > penaltyTenths ? gainedTenths - penaltyTenths : 0;

    gSnap = cur;

    if (netTenths == 0)
        return;

    uint64_t accumulated = (uint64_t)gPendingTenths + netTenths;
    uint64_t whole = accumulated / 10;
    gPendingTenths = (uint32_t)(accumulated % 10);

    if (whole == 0)
        return;

    uint64_t cur_total = loadTotal();
    uint64_t next = cur_total + whole;
    if (next > UINT32_MAX)
        next = UINT32_MAX;
    const uint32_t credited = next > cur_total ? (uint32_t)(next - cur_total) : 0;

    persistTotal((uint32_t)next);
    if (credited == 0)
        return;

    char detail[ExperienceLog::kDetailBytes];
    if (dRelay > 0) {
        snprintf(detail, sizeof(detail), "Mesh relay x%u", (unsigned)dRelay);
    } else if (dCancel > 0) {
        snprintf(detail, sizeof(detail), "Mesh near-relay x%u", (unsigned)dCancel);
    } else {
        snprintf(detail, sizeof(detail), "Mesh RX x%u", (unsigned)dRxGood);
    }
    ExperienceLog::record(ExperienceLog::Source::Mesh, credited, detail);
}

} // namespace MeshExperience
} // namespace valkyrie

#else // !ARCH_ESP32 || !VALKYRIE_FORK

namespace valkyrie
{
namespace MeshExperience
{
uint32_t totalPoints() { return 0; }
uint32_t totalCombinedXp() { return 0; }
void resetMeshXp() {}
void onRadioCountersTick() {}
} // namespace MeshExperience
} // namespace valkyrie

#endif
