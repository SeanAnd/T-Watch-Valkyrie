#pragma once

#include <stdint.h>

#if defined(ARCH_ESP32) && defined(VALKYRIE_FORK)

namespace valkyrie
{

// True when we have a non-degenerate lat/lon for the local user suitable
// for AirTag stalking correlation (GPS lock or fixed position). Writes
// Meshtastic-style fixed-point degrees (latitude_i / 1e7).
bool readGeoForStalking(int32_t *latOut, int32_t *lonOut);

} // namespace valkyrie

#endif // ARCH_ESP32 && VALKYRIE_FORK

