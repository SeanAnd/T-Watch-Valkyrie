#include "ValkyrieFork.h"
#include "configuration.h"

#if defined(ARCH_ESP32) && defined(VALKYRIE_FORK)

#include "modules/BleThreatDetectorModule.h"
#include "persist/ThreatIgnoreList.h"
#include "prefs/ValkyriePrefs.h"

namespace valkyrie
{

BleThreatDetectorModule *bleThreatDetector = nullptr;

void syncBleThreatDetectorFromPrefs()
{
    ValkyriePrefs prefs = ValkyriePrefs::load();
    if (prefs.bleThreatDetectorEnabled) {
        if (!bleThreatDetector) {
            LOG_INFO("Valkyrie: starting BLE threat detector (interval=%us window=%us min_batt=%u%% constant=%d)",
                     prefs.scanIntervalSecs, prefs.scanWindowSecs, prefs.minBatteryPct, (int)prefs.constantBleScanMode);
            bleThreatDetector = new BleThreatDetectorModule(prefs);
        }
    } else {
        if (bleThreatDetector) {
            delete bleThreatDetector;
            bleThreatDetector = nullptr;
            LOG_INFO("Valkyrie: BLE threat detector stopped (disabled in prefs)");
        } else {
            LOG_INFO("Valkyrie: BLE threat detector disabled in prefs, skipping");
        }
    }
}

void setupFork()
{
    ThreatIgnoreList::reloadCache();
    syncBleThreatDetectorFromPrefs();
}

} // namespace valkyrie

#else // !ARCH_ESP32 || !VALKYRIE_FORK

namespace valkyrie
{
void setupFork() {}
} // namespace valkyrie

#endif
