#pragma once

#include <cstddef>
#include <cstdint>

namespace valkyrie
{

// Tunable thresholds for AirGuard-style multi-sight + multi-place logic.
struct AirtagStalkingConfig {
    uint8_t minSightings;
    uint8_t minDistinctPlaces;
    uint16_t minSeparationM;
    uint32_t entryTtlSecs;
};

struct AirtagStalkingGateResult {
    bool allowEmit;
    uint32_t sightings;
    uint32_t distinctPlaces;
};

// Bounded in-RAM state: correlate sightings by BLE MAC (v1; rotating
// addresses limit accuracy — see README).
class AirtagStalkingState
{
  public:
    static constexpr size_t kMaxEntries = 24;
    static constexpr size_t kMaxPlaceKeys = 8;

    AirtagStalkingGateResult recordSighting(const uint8_t mac[6], int32_t lat_i, int32_t lon_i, uint32_t nowMs,
                                            const AirtagStalkingConfig &cfg);

  private:
    struct Entry {
        bool used = false;
        uint8_t mac[6]{};
        uint32_t lastUpdateMs = 0;
        uint32_t sightings = 0;
        uint8_t nPlaceKeys = 0;
        uint32_t placeKeys[kMaxPlaceKeys]{};
    };

    Entry entries[kMaxEntries]{};

    void purgeExpired(uint32_t nowMs, uint32_t ttlMs);
    int findMac(const uint8_t mac[6]) const;
    int allocateEntry(const uint8_t mac[6], uint32_t nowMs, const AirtagStalkingConfig &cfg);
    static int32_t gridQuantumFromSepM(uint16_t sepMeters);
    static uint32_t placeKeyFor(int32_t lat_i, int32_t lon_i, uint16_t sepMeters);
    static bool appendDistinctPlace(Entry &e, uint32_t key);
};

} // namespace valkyrie
