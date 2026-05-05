#include "ValkyrieSettingsMenu.h"

#include "configuration.h"

#if defined(ARCH_ESP32) && defined(VALKYRIE_FORK)

#include "ValkyrieFork.h"
#include "../modules/BleThreatDetectorModule.h"
#include "prefs/ValkyriePrefs.h"
#include "graphics/Screen.h"
#include "graphics/draw/MenuHandler.h"
#include "main.h"

#include <cstdio>

namespace valkyrie
{

void showSettingsMenu()
{
    ValkyriePrefs prefs = ValkyriePrefs::load();

    enum opt { OptBack, OptToggleDetector, OptConstantScan };
    static char detectorToggleLabel[28];
    snprintf(detectorToggleLabel, sizeof(detectorToggleLabel), "%s detector", prefs.bleThreatDetectorEnabled ? "Disable" : "Enable");

    static char constantScanLabel[40];
    snprintf(constantScanLabel, sizeof(constantScanLabel), "Scan Mode: %s", prefs.constantBleScanMode ? "Constant" : "Interval");

    static const char *labels[] = {"Back", detectorToggleLabel, constantScanLabel};
    static int enums[] = {OptBack, OptToggleDetector, OptConstantScan};

    graphics::BannerOverlayOptions bannerOptions{};
    bannerOptions.message = "Valkyrie settings";
    bannerOptions.optionsArrayPtr = labels;
    bannerOptions.optionsEnumPtr = enums;
    bannerOptions.optionsCount = 3;
    bannerOptions.bannerCallback = [](int selected) -> void {
        if (selected == OptBack) {
            graphics::menuHandler::menuQueue = graphics::menuHandler::ValkyrieRootMenu;
            screen->runNow();
        } else if (selected == OptToggleDetector) {
            ValkyriePrefs p = ValkyriePrefs::load();
            p.bleThreatDetectorEnabled = !p.bleThreatDetectorEnabled;
            p.save();
            syncBleThreatDetectorFromPrefs();
            screen->showSimpleBanner("Saved.", 4000);
        } else if (selected == OptConstantScan) {
            ValkyriePrefs p = ValkyriePrefs::load();
            if (p.constantBleScanMode) {
                p.constantBleScanMode = false;
                p.save();
                if (bleThreatDetector)
                    bleThreatDetector->reloadPrefs();
                screen->showSimpleBanner("Saved.", 4000);
            } else {
                // Defer to next handleMenuSwitch: opening another overlay from inside this callback is
                // cleared immediately by NotificationRenderer::resetBanner() after the callback returns.
                graphics::menuHandler::menuQueue = graphics::menuHandler::ValkyrieConstantScanConfirmMenu;
                screen->runNow();
            }
        }
    };
    screen->showOverlayBanner(bannerOptions);
}

void showConstantScanEnableConfirmMenu()
{
    static const char *opts[] = {"No", "Yes"};
    static const int enums[] = {0, 1};
    graphics::BannerOverlayOptions b{};
    b.message = "Enable constant BLE scan?\n\nNote: this will diminish battery life.";
    b.optionsArrayPtr = opts;
    b.optionsEnumPtr = enums;
    b.optionsCount = 2;
    b.bannerCallback = [](int selected) -> void {
        if (selected == 1) {
            ValkyriePrefs p = ValkyriePrefs::load();
            p.constantBleScanMode = true;
            p.save();
            if (bleThreatDetector)
                bleThreatDetector->reloadPrefs();
        }
        graphics::menuHandler::menuQueue = graphics::menuHandler::ValkyrieSettingsMenu;
        screen->runNow();
    };
    screen->showOverlayBanner(b);
}

} // namespace valkyrie

#endif
