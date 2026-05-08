#include "WifiThreatPlaceholder.h"

#if defined(ARCH_ESP32) && defined(VALKYRIE_FORK)

#include "configuration.h"

namespace valkyrie
{

void runWifiThreatPlaceholderPass()
{
#if HAS_WIFI
    static uint32_t s_passCount = 0;
    s_passCount++;
    LOG_DEBUG("Valkyrie: WiFi threat placeholder pass #%u", (unsigned)s_passCount);
#endif
}

} // namespace valkyrie

#endif // ARCH_ESP32 && VALKYRIE_FORK
