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
    EXPECT(heartbeatRssiInstaTier(-47) == HeartbeatSignalTier::VeryStrong, "insta -47 VeryStrong");
    EXPECT(heartbeatRssiInstaTier(-48) == HeartbeatSignalTier::VeryStrong, "insta -48 VeryStrong");
    EXPECT(heartbeatRssiInstaTier(-49) == HeartbeatSignalTier::Strong, "insta -49 Strong");
    EXPECT(heartbeatRssiInstaTier(-58) == HeartbeatSignalTier::Strong, "insta -58 Strong");
    EXPECT(heartbeatRssiInstaTier(-59) == HeartbeatSignalTier::MediumStrong, "insta -59 MediumStrong");
    EXPECT(heartbeatRssiInstaTier(-68) == HeartbeatSignalTier::MediumStrong, "insta -68 MediumStrong");
    EXPECT(heartbeatRssiInstaTier(-69) == HeartbeatSignalTier::Medium, "insta -69 Medium");
    EXPECT(heartbeatRssiInstaTier(-78) == HeartbeatSignalTier::Medium, "insta -78 Medium");
    EXPECT(heartbeatRssiInstaTier(-79) == HeartbeatSignalTier::Weak, "insta -79 Weak");
    EXPECT(heartbeatRssiInstaTier(-88) == HeartbeatSignalTier::Weak, "insta -88 Weak");
    EXPECT(heartbeatRssiInstaTier(-89) == HeartbeatSignalTier::VeryWeak, "insta -89 VeryWeak");
}

void test_ema_init_and_step()
{
    const int32_t a = heartbeatRssiEmaNext(true, 0, -80);
    EXPECT(a == -80, "EMA init returns raw");
    // Next: alpha/256 * (-72) + (1-alpha/256)*(-80); alpha=48 -> -78
    const int32_t b = heartbeatRssiEmaNext(false, a, -72);
    EXPECT(b == -78, "EMA step matches alpha blend");
}

void test_hysteresis_very_weak_stays_until_promote_threshold()
{
    uint8_t latched = static_cast<uint8_t>(HeartbeatSignalTier::VeryWeak);
    heartbeatRssiApplyHysteresis(&latched, -85);
    EXPECT(tierOf(latched) == HeartbeatSignalTier::VeryWeak, "very weak at -85 stays very weak");
    heartbeatRssiApplyHysteresis(&latched, -84);
    EXPECT(tierOf(latched) == HeartbeatSignalTier::Weak, "very weak crosses to weak at -84");
}

void test_hysteresis_weak_adjacent_deadbands()
{
    uint8_t latched = static_cast<uint8_t>(HeartbeatSignalTier::Weak);
    heartbeatRssiApplyHysteresis(&latched, -92);
    EXPECT(tierOf(latched) == HeartbeatSignalTier::Weak, "weak at -92 stays weak");
    heartbeatRssiApplyHysteresis(&latched, -93);
    EXPECT(tierOf(latched) == HeartbeatSignalTier::VeryWeak, "weak drops very weak below -92");

    latched = static_cast<uint8_t>(HeartbeatSignalTier::Weak);
    heartbeatRssiApplyHysteresis(&latched, -75);
    EXPECT(tierOf(latched) == HeartbeatSignalTier::Weak, "weak at -75 stays weak");
    heartbeatRssiApplyHysteresis(&latched, -74);
    EXPECT(tierOf(latched) == HeartbeatSignalTier::Medium, "weak crosses to medium at -74");
}

void test_hysteresis_medium_adjacent_deadbands()
{
    uint8_t latched = static_cast<uint8_t>(HeartbeatSignalTier::Medium);
    heartbeatRssiApplyHysteresis(&latched, -82);
    EXPECT(tierOf(latched) == HeartbeatSignalTier::Medium, "medium at -82 stays medium");
    heartbeatRssiApplyHysteresis(&latched, -83);
    EXPECT(tierOf(latched) == HeartbeatSignalTier::Weak, "medium drops weak below -82");

    latched = static_cast<uint8_t>(HeartbeatSignalTier::Medium);
    heartbeatRssiApplyHysteresis(&latched, -65);
    EXPECT(tierOf(latched) == HeartbeatSignalTier::Medium, "medium at -65 stays medium");
    heartbeatRssiApplyHysteresis(&latched, -64);
    EXPECT(tierOf(latched) == HeartbeatSignalTier::MediumStrong, "medium crosses to medium strong at -64");
}

void test_hysteresis_medium_strong_adjacent_deadbands()
{
    uint8_t latched = static_cast<uint8_t>(HeartbeatSignalTier::MediumStrong);
    heartbeatRssiApplyHysteresis(&latched, -72);
    EXPECT(tierOf(latched) == HeartbeatSignalTier::MediumStrong, "medium strong at -72 stays medium strong");
    heartbeatRssiApplyHysteresis(&latched, -73);
    EXPECT(tierOf(latched) == HeartbeatSignalTier::Medium, "medium strong drops medium below -72");

    latched = static_cast<uint8_t>(HeartbeatSignalTier::MediumStrong);
    heartbeatRssiApplyHysteresis(&latched, -55);
    EXPECT(tierOf(latched) == HeartbeatSignalTier::MediumStrong, "medium strong at -55 stays medium strong");
    heartbeatRssiApplyHysteresis(&latched, -54);
    EXPECT(tierOf(latched) == HeartbeatSignalTier::Strong, "medium strong crosses to strong at -54");
}

void test_hysteresis_strong_adjacent_deadbands()
{
    uint8_t latched = static_cast<uint8_t>(HeartbeatSignalTier::Strong);
    heartbeatRssiApplyHysteresis(&latched, -62);
    EXPECT(tierOf(latched) == HeartbeatSignalTier::Strong, "strong at -62 stays strong");
    heartbeatRssiApplyHysteresis(&latched, -63);
    EXPECT(tierOf(latched) == HeartbeatSignalTier::MediumStrong, "strong drops medium strong below -62");

    latched = static_cast<uint8_t>(HeartbeatSignalTier::Strong);
    heartbeatRssiApplyHysteresis(&latched, -45);
    EXPECT(tierOf(latched) == HeartbeatSignalTier::Strong, "strong at -45 stays strong");
    heartbeatRssiApplyHysteresis(&latched, -44);
    EXPECT(tierOf(latched) == HeartbeatSignalTier::VeryStrong, "strong crosses to very strong at -44");
}

void test_hysteresis_very_strong_deadband()
{
    uint8_t latched = static_cast<uint8_t>(HeartbeatSignalTier::VeryStrong);
    heartbeatRssiApplyHysteresis(&latched, -52);
    EXPECT(tierOf(latched) == HeartbeatSignalTier::VeryStrong, "very strong holds at -52");
    heartbeatRssiApplyHysteresis(&latched, -53);
    EXPECT(tierOf(latched) == HeartbeatSignalTier::Strong, "very strong drops at -53");
}

void test_hysteresis_unknown_seeds_insta()
{
    uint8_t latched = 255;
    heartbeatRssiApplyHysteresis(&latched, -68);
    EXPECT(tierOf(latched) == HeartbeatSignalTier::MediumStrong, "unknown seeds to insta MediumStrong at -68");
}

void test_hysteresis_none_seeds_insta()
{
    uint8_t latched = static_cast<uint8_t>(HeartbeatSignalTier::None);
    heartbeatRssiApplyHysteresis(&latched, -63);
    EXPECT(tierOf(latched) == HeartbeatSignalTier::MediumStrong, "None seeds to insta MediumStrong at -63");
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
    // Start medium-ish so EMA lives near the weak/medium boundary.
    p.packet(-76, 1);
    EXPECT(tierOf(p.latched) == HeartbeatSignalTier::Medium, "start medium");

    HeartbeatSignalTier first = tierOf(p.latched);
    for (int i = 0; i < 40; ++i) {
        p.packet(-77, 5);
        p.packet(-79, 5);
    }
    EXPECT(tierOf(p.latched) == first, "chatter -77/-79 should not flip tier vs initial");
    EXPECT(tierOf(p.latched) == HeartbeatSignalTier::Medium, "expect remain Medium after EMA+hysteresis");
}

void test_pipeline_stale_gap_reinits_insta()
{
    HeartbeatRssiPipeline p;
    p.packet(-90, 1);
    EXPECT(tierOf(p.latched) == HeartbeatSignalTier::VeryWeak, "very weak start");

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
    test_hysteresis_very_weak_stays_until_promote_threshold();
    test_hysteresis_weak_adjacent_deadbands();
    test_hysteresis_medium_adjacent_deadbands();
    test_hysteresis_medium_strong_adjacent_deadbands();
    test_hysteresis_strong_adjacent_deadbands();
    test_hysteresis_very_strong_deadband();
    test_hysteresis_unknown_seeds_insta();
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
