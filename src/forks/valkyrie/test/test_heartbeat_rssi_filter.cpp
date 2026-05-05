// Native unit tests for valkyrie::heartbeatRssi* (EMA + hysteresis).
//
// Build & run on host:
//   cd firmware/src/forks/valkyrie/test
//   c++ -std=gnu++17 -O0 -g ../HeartbeatRssiFilter.cpp test_heartbeat_rssi_filter.cpp -o /tmp/valkyrie_hb_rssi_test && /tmp/valkyrie_hb_rssi_test
//
// Excluded from the t-watch-s3-valkyrie build via `build_src_filter -<forks/valkyrie/test/>`.

#include "../HeartbeatRssiFilter.h"

#include <cstdint>
#include <cstdio>

namespace
{

int g_failures = 0;

#define EXPECT(cond, msg)                                                                                                        \
    do {                                                                                                                         \
        if (!(cond)) {                                                                                                           \
            std::fprintf(stderr, "FAIL: %s (line %d)\n", (msg), __LINE__);                                                         \
            ++g_failures;                                                                                                        \
        }                                                                                                                        \
    } while (0)

using valkyrie::HeartbeatSignalTier;
using valkyrie::heartbeatRssiApplyHysteresis;
using valkyrie::heartbeatRssiEmaNext;
using valkyrie::heartbeatRssiInstaTier;
using valkyrie::kHeartbeatRssiStaleMs;

static HeartbeatSignalTier tierOf(uint8_t u)
{
    return static_cast<HeartbeatSignalTier>(u);
}

void test_insta_tier_boundaries()
{
    EXPECT(heartbeatRssiInstaTier(-59) == HeartbeatSignalTier::Strong, "insta -59 Strong");
    EXPECT(heartbeatRssiInstaTier(-60) == HeartbeatSignalTier::Strong, "insta -60 Strong");
    EXPECT(heartbeatRssiInstaTier(-61) == HeartbeatSignalTier::Medium, "insta -61 Medium");
    EXPECT(heartbeatRssiInstaTier(-75) == HeartbeatSignalTier::Medium, "insta -75 Medium");
    EXPECT(heartbeatRssiInstaTier(-76) == HeartbeatSignalTier::Weak, "insta -76 Weak");
}

void test_ema_init_and_step()
{
    const int32_t a = heartbeatRssiEmaNext(true, 0, -80);
    EXPECT(a == -80, "EMA init returns raw");
    // Next: 0.25*(-72) + 0.75*(-80) = -18 - 60 = -78
    const int32_t b = heartbeatRssiEmaNext(false, a, -72);
    EXPECT(b == -78, "EMA step matches 0.25/0.75 blend");
}

void test_hysteresis_weak_stays_until_73()
{
    uint8_t latched = static_cast<uint8_t>(HeartbeatSignalTier::Weak);
    heartbeatRssiApplyHysteresis(&latched, -74);
    EXPECT(tierOf(latched) == HeartbeatSignalTier::Weak, "weak at -74 stays weak");
    heartbeatRssiApplyHysteresis(&latched, -73);
    EXPECT(tierOf(latched) == HeartbeatSignalTier::Medium, "weak crosses to medium at -73");
}

void test_hysteresis_medium_drops_at_77()
{
    uint8_t latched = static_cast<uint8_t>(HeartbeatSignalTier::Medium);
    heartbeatRssiApplyHysteresis(&latched, -77);
    EXPECT(tierOf(latched) == HeartbeatSignalTier::Medium, "medium at -77 stays medium");
    heartbeatRssiApplyHysteresis(&latched, -78);
    EXPECT(tierOf(latched) == HeartbeatSignalTier::Weak, "medium drops weak below -77");
}

void test_hysteresis_strong_deadband()
{
    uint8_t latched = static_cast<uint8_t>(HeartbeatSignalTier::Strong);
    heartbeatRssiApplyHysteresis(&latched, -61);
    EXPECT(tierOf(latched) == HeartbeatSignalTier::Strong, "strong holds at -61");
    heartbeatRssiApplyHysteresis(&latched, -62);
    EXPECT(tierOf(latched) == HeartbeatSignalTier::Strong, "strong holds at -62 (leave threshold is s < -62)");
    heartbeatRssiApplyHysteresis(&latched, -63);
    EXPECT(tierOf(latched) == HeartbeatSignalTier::Medium, "strong drops at -63");
}

void test_hysteresis_none_seeds_insta()
{
    uint8_t latched = static_cast<uint8_t>(HeartbeatSignalTier::None);
    heartbeatRssiApplyHysteresis(&latched, -63);
    EXPECT(tierOf(latched) == HeartbeatSignalTier::Medium, "None seeds to insta Medium at -63");
}

/** Mirrors BleThreatDetectorModule heartbeat RSSI update order (ms gaps, not wall clock). */
struct HeartbeatRssiPipeline {
    uint8_t latched = static_cast<uint8_t>(HeartbeatSignalTier::None);
    int32_t smoothed = -128;
    bool valid = false;
    uint32_t fakeMs = 0;
    uint32_t lastAdvMs = 0;

    void packet(int32_t rssiRaw, uint32_t gapSinceLastPacketMs)
    {
        fakeMs += gapSinceLastPacketMs;
        const uint32_t prevAdvMs = lastAdvMs;
        lastAdvMs = fakeMs;

        const bool gapStale = (prevAdvMs != 0) && (fakeMs - prevAdvMs > kHeartbeatRssiStaleMs);

        if (!valid || gapStale) {
            smoothed = heartbeatRssiEmaNext(true, 0, rssiRaw);
            valid = true;
            latched = static_cast<uint8_t>(heartbeatRssiInstaTier(rssiRaw));
        } else {
            smoothed = heartbeatRssiEmaNext(false, smoothed, rssiRaw);
            heartbeatRssiApplyHysteresis(&latched, smoothed);
        }
    }
};

void test_pipeline_raw_chatter_near_boundary_stays_medium()
{
    HeartbeatRssiPipeline p;
    // Start medium-ish so EMA lives near -60 boundary.
    p.packet(-65, 1);
    EXPECT(tierOf(p.latched) == HeartbeatSignalTier::Medium, "start medium");

    HeartbeatSignalTier first = tierOf(p.latched);
    for (int i = 0; i < 40; ++i) {
        p.packet(-59, 5);
        p.packet(-61, 5);
    }
    EXPECT(tierOf(p.latched) == first, "chatter -59/-61 should not flip tier vs initial");
    EXPECT(tierOf(p.latched) == HeartbeatSignalTier::Medium, "expect remain Medium after EMA+hysteresis");
}

void test_pipeline_stale_gap_reinits_insta()
{
    HeartbeatRssiPipeline p;
    p.packet(-90, 1);
    EXPECT(tierOf(p.latched) == HeartbeatSignalTier::Weak, "weak start");

    const uint32_t gap = kHeartbeatRssiStaleMs + 1;
    p.packet(-55, gap);
    EXPECT(tierOf(p.latched) == HeartbeatSignalTier::Strong, "after stale gap reinstantiate Strong from raw -55");
    EXPECT(p.smoothed == -55, "smoothed reset to raw on stale");
}

} // namespace

int main()
{
    test_insta_tier_boundaries();
    test_ema_init_and_step();
    test_hysteresis_weak_stays_until_73();
    test_hysteresis_medium_drops_at_77();
    test_hysteresis_strong_deadband();
    test_hysteresis_none_seeds_insta();
    test_pipeline_raw_chatter_near_boundary_stays_medium();
    test_pipeline_stale_gap_reinits_insta();

    if (g_failures == 0) {
        std::printf("OK: all heartbeat RSSI filter tests passed\n");
        return 0;
    }
    std::fprintf(stderr, "FAILED: %d heartbeat RSSI filter tests failed\n", g_failures);
    return 1;
}
