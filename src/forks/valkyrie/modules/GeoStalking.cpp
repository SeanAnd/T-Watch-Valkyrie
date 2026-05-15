#include "configuration.h"
#include "GeoStalking.h"

#if defined(ARCH_ESP32) && defined(VALKYRIE_FORK)

#include "GPSStatus.h"
#include "mesh/NodeDB.h"

namespace valkyrie
{

// Delegates to GPSStatus::getHasUsablePosition(), which already considers on-device GPS lock,
// config.position.fixed_position, and live phone-supplied localPosition (staleness-gated).
// AirTag stalking now works on phone-only T-Watch S3 builds as a side benefit.
bool readGeoForStalking(int32_t *latOut, int32_t *lonOut)
{
    if (!latOut || !lonOut || !gpsStatus || !gpsStatus->getHasUsablePosition())
        return false;
    *latOut = gpsStatus->getLatitude();
    *lonOut = gpsStatus->getLongitude();
    return (*latOut != 0 || *lonOut != 0);
}

} // namespace valkyrie

#endif // ARCH_ESP32 && VALKYRIE_FORK
