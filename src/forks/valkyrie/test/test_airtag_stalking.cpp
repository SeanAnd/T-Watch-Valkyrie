// Host unit tests for valkyrie::AirtagStalkingState (no Meshtastic / NimBLE).
//
//   c++ -std=gnu++17 -O0 -g ../modules/AirtagStalkingState.cpp test_airtag_stalking.cpp -o /tmp/valkyrie_stalk_test && /tmp/valkyrie_stalk_test

#include "../modules/AirtagStalkingState.h"

#include <cstdio>
#include <cstring>

namespace
{

int g_failures = 0;

#define EXPECT(cond, msg)                                                                                                        \
    do {                                                                                                                         \
        if (!(cond)) {                                                                                                           \
            std::fprintf(stderr, "FAIL: %s (line %d)\n", (msg), __LINE__);                                                       \
            ++g_failures;                                                                                                        \
        }                                                                                                                        \
    } while (0)

} // namespace

int main()
{
    using valkyrie::AirtagStalkingConfig;
    using valkyrie::AirtagStalkingState;

    AirtagStalkingState s;
    AirtagStalkingConfig cfg{3, 2, 75, 86400};
    uint8_t mac[6] = {0xAA, 0xBB, 0xCC, 0x01, 0x02, 0x03};

    // Same ~75m grid cell: two sightings -> not enough sightings / one place.
    auto a = s.recordSighting(mac, 450000000, -730000000, 1000, cfg);
    EXPECT(!a.allowEmit, "first sight no emit");
    auto b = s.recordSighting(mac, 450000100, -730000000, 2000, cfg);
    EXPECT(!b.allowEmit, "second sight same cell no emit");

    // Third sighting far enough for a second place cell (>> stalkMinSeparationM).
    auto c = s.recordSighting(mac, 451200000, -730000000, 3000, cfg);
    EXPECT(c.allowEmit, "third sight second place should emit");
    EXPECT(c.sightings >= 3u, "sightings count");
    EXPECT(c.distinctPlaces >= 2u, "distinct places");

    if (g_failures == 0) {
        std::printf("OK: all AirtagStalkingState tests passed\n");
        return 0;
    }
    std::fprintf(stderr, "FAILED: %d stalking tests failed\n", g_failures);
    return 1;
}
