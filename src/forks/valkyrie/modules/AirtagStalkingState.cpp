#include "AirtagStalkingState.h"

#include <cstring>

namespace valkyrie
{

void AirtagStalkingState::purgeExpired(uint32_t nowMs, uint32_t ttlMs)
{
    if (ttlMs == 0)
        return;
    for (size_t i = 0; i < kMaxEntries; ++i) {
        Entry &e = entries[i];
        if (!e.used)
            continue;
        uint32_t age = nowMs - e.lastUpdateMs;
        if (age > ttlMs)
            e.used = false;
    }
}

int AirtagStalkingState::findMac(const uint8_t mac[6]) const
{
    if (!mac)
        return -1;
    for (size_t i = 0; i < kMaxEntries; ++i) {
        if (entries[i].used && memcmp(entries[i].mac, mac, 6) == 0)
            return (int)i;
    }
    return -1;
}

int AirtagStalkingState::allocateEntry(const uint8_t mac[6], uint32_t nowMs, const AirtagStalkingConfig &cfg)
{
    (void)cfg;
    // Free slot
    for (size_t i = 0; i < kMaxEntries; ++i) {
        if (!entries[i].used) {
            entries[i].used = true;
            memcpy(entries[i].mac, mac, 6);
            entries[i].lastUpdateMs = nowMs;
            entries[i].sightings = 0;
            entries[i].nPlaceKeys = 0;
            memset(entries[i].placeKeys, 0, sizeof(entries[i].placeKeys));
            return (int)i;
        }
    }
    // Evict oldest by lastUpdateMs among used slots
    size_t best = 0;
    uint32_t bestTime = 0xFFFFFFFFu;
    for (size_t i = 0; i < kMaxEntries; ++i) {
        if (!entries[i].used)
            continue;
        if (entries[i].lastUpdateMs < bestTime) {
            bestTime = entries[i].lastUpdateMs;
            best = i;
        }
    }
    Entry &e = entries[best];
    e.used = true;
    memcpy(e.mac, mac, 6);
    e.lastUpdateMs = nowMs;
    e.sightings = 0;
    e.nPlaceKeys = 0;
    memset(e.placeKeys, 0, sizeof(e.placeKeys));
    return (int)best;
}

int32_t AirtagStalkingState::gridQuantumFromSepM(uint16_t sepMeters)
{
    if (sepMeters < 5)
        sepMeters = 5;
    // latitude_i is in 1e-7 degrees; ~111.32 km per degree latitude.
    int64_t q = (int64_t)sepMeters * 10000000LL / 111320LL;
    if (q < 50)
        q = 50;
    return (int32_t)q;
}

uint32_t AirtagStalkingState::placeKeyFor(int32_t lat_i, int32_t lon_i, uint16_t sepMeters)
{
    int32_t q = gridQuantumFromSepM(sepMeters);
    int32_t la = lat_i / q;
    int32_t lo = lon_i / q;
    uint32_t a = (uint32_t)la;
    uint32_t b = (uint32_t)lo;
    return (a * 0x9E3779B1u) ^ (b * 0x85EBCA6Bu);
}

bool AirtagStalkingState::appendDistinctPlace(Entry &e, uint32_t key)
{
    for (uint8_t i = 0; i < e.nPlaceKeys; ++i) {
        if (e.placeKeys[i] == key)
            return false;
    }
    if (e.nPlaceKeys >= kMaxPlaceKeys)
        return true;
    e.placeKeys[e.nPlaceKeys++] = key;
    return true;
}

AirtagStalkingGateResult AirtagStalkingState::recordSighting(const uint8_t mac[6], int32_t lat_i, int32_t lon_i, uint32_t nowMs,
                                                             const AirtagStalkingConfig &cfg)
{
    AirtagStalkingGateResult r{};
    if (!mac)
        return r;

    uint32_t ttlMs = cfg.entryTtlSecs * 1000U;
    purgeExpired(nowMs, ttlMs);

    int idx = findMac(mac);
    if (idx < 0)
        idx = allocateEntry(mac, nowMs, cfg);
    if (idx < 0)
        return r;

    Entry &e = entries[(size_t)idx];
    e.lastUpdateMs = nowMs;
    e.sightings++;

    uint32_t pk = placeKeyFor(lat_i, lon_i, cfg.minSeparationM);
    appendDistinctPlace(e, pk);

    r.sightings = e.sightings;
    r.distinctPlaces = e.nPlaceKeys;
    r.allowEmit = (e.sightings >= cfg.minSightings && e.nPlaceKeys >= cfg.minDistinctPlaces);
    return r;
}

} // namespace valkyrie
