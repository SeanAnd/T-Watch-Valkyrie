#include "configuration.h"
#include "GeoStalking.h"

#if defined(ARCH_ESP32) && defined(VALKYRIE_FORK)

#include "GPSStatus.h"
#include "mesh/NodeDB.h"

namespace valkyrie
{

bool readGeoForStalking(int32_t *latOut, int32_t *lonOut)
{
    if (!latOut || !lonOut)
        return false;
    if (!gpsStatus)
        return false;

#if HAS_GPS
    if (config.position.fixed_position) {
        *latOut = gpsStatus->getLatitude();
        *lonOut = gpsStatus->getLongitude();
        return (*latOut != 0 || *lonOut != 0);
    }
    if (!gpsStatus->getHasLock())
        return false;
    *latOut = gpsStatus->getLatitude();
    *lonOut = gpsStatus->getLongitude();
    return (*latOut != 0 || *lonOut != 0);
#else
    if (!config.position.fixed_position)
        return false;
    *latOut = gpsStatus->getLatitude();
    *lonOut = gpsStatus->getLongitude();
    return (*latOut != 0 || *lonOut != 0);
#endif
}

} // namespace valkyrie

#endif // ARCH_ESP32 && VALKYRIE_FORK
