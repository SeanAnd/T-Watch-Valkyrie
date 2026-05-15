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

#if HAS_WIFI && !defined(ARCH_PORTDUINO)
    enum opt {
        OptBack,
        OptToggleDetector,
        OptConstantScan,
        OptBleThreatPhase,
        OptWifiThreatPhase,
        OptNotifications,
        OptWardrive
    };
    static char blePhaseLabel[36];
    static char wifiPhaseLabel[38];
    snprintf(blePhaseLabel, sizeof(blePhaseLabel), "BLE threat phase: %s", prefs.bleThreatPhaseEnabled ? "On" : "Off");
    snprintf(wifiPhaseLabel, sizeof(wifiPhaseLabel), "WiFi threat phase: %s", prefs.wifiThreatPhaseEnabled ? "On" : "Off");

    static char detectorToggleLabel[28];
    snprintf(detectorToggleLabel, sizeof(detectorToggleLabel), "%s detector", prefs.bleThreatDetectorEnabled ? "Disable" : "Enable");

    static char constantScanLabel[40];
    snprintf(constantScanLabel, sizeof(constantScanLabel), "Scan Mode: %s", prefs.constantBleScanMode ? "Constant" : "Interval");

    static const char *labels[] = {"Back",         detectorToggleLabel, constantScanLabel, blePhaseLabel,
                                   wifiPhaseLabel, "Notifications",     "Wardrive..."};
    static int enums[] = {OptBack,           OptToggleDetector, OptConstantScan, OptBleThreatPhase,
                          OptWifiThreatPhase, OptNotifications,  OptWardrive};

    graphics::BannerOverlayOptions bannerOptions{};
    bannerOptions.message = "Valkyrie settings";
    bannerOptions.optionsArrayPtr = labels;
    bannerOptions.optionsEnumPtr = enums;
    bannerOptions.optionsCount = 7;
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
                graphics::menuHandler::menuQueue = graphics::menuHandler::ValkyrieConstantScanConfirmMenu;
                screen->runNow();
            }
        } else if (selected == OptBleThreatPhase) {
            ValkyriePrefs p = ValkyriePrefs::load();
            p.bleThreatPhaseEnabled = !p.bleThreatPhaseEnabled;
            p.save();
            if (bleThreatDetector)
                bleThreatDetector->reloadPrefs();
            screen->showSimpleBanner("Saved.", 4000);
        } else if (selected == OptWifiThreatPhase) {
            ValkyriePrefs p = ValkyriePrefs::load();
            p.wifiThreatPhaseEnabled = !p.wifiThreatPhaseEnabled;
            p.save();
            if (bleThreatDetector)
                bleThreatDetector->reloadPrefs();
            screen->showSimpleBanner("Saved.", 4000);
        } else if (selected == OptNotifications) {
            graphics::menuHandler::menuQueue = graphics::menuHandler::ValkyrieNotificationsMenu;
            screen->runNow();
        } else if (selected == OptWardrive) {
            graphics::menuHandler::menuQueue = graphics::menuHandler::ValkyrieWardriveSettingsMenu;
            screen->runNow();
        }
    };
    screen->showOverlayBanner(bannerOptions);
#else
    enum opt { OptBack, OptToggleDetector, OptConstantScan, OptBleThreatPhase, OptNotifications, OptWardrive };
    static char blePhaseLabel[36];
    snprintf(blePhaseLabel, sizeof(blePhaseLabel), "BLE threat phase: %s", prefs.bleThreatPhaseEnabled ? "On" : "Off");

    static char detectorToggleLabel[28];
    snprintf(detectorToggleLabel, sizeof(detectorToggleLabel), "%s detector", prefs.bleThreatDetectorEnabled ? "Disable" : "Enable");

    static char constantScanLabel[40];
    snprintf(constantScanLabel, sizeof(constantScanLabel), "Scan Mode: %s", prefs.constantBleScanMode ? "Constant" : "Interval");

    static const char *labels[] = {"Back",        detectorToggleLabel, constantScanLabel,
                                   blePhaseLabel, "Notifications",     "Wardrive..."};
    static int enums[] = {OptBack,           OptToggleDetector, OptConstantScan,
                          OptBleThreatPhase, OptNotifications,  OptWardrive};

    graphics::BannerOverlayOptions bannerOptions{};
    bannerOptions.message = "Valkyrie settings";
    bannerOptions.optionsArrayPtr = labels;
    bannerOptions.optionsEnumPtr = enums;
    bannerOptions.optionsCount = 6;
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
                graphics::menuHandler::menuQueue = graphics::menuHandler::ValkyrieConstantScanConfirmMenu;
                screen->runNow();
            }
        } else if (selected == OptBleThreatPhase) {
            ValkyriePrefs p = ValkyriePrefs::load();
            p.bleThreatPhaseEnabled = !p.bleThreatPhaseEnabled;
            p.save();
            if (bleThreatDetector)
                bleThreatDetector->reloadPrefs();
            screen->showSimpleBanner("Saved.", 4000);
        } else if (selected == OptNotifications) {
            graphics::menuHandler::menuQueue = graphics::menuHandler::ValkyrieNotificationsMenu;
            screen->runNow();
        } else if (selected == OptWardrive) {
            graphics::menuHandler::menuQueue = graphics::menuHandler::ValkyrieWardriveSettingsMenu;
            screen->runNow();
        }
    };
    screen->showOverlayBanner(bannerOptions);
#endif
}

void showNotificationsMenu()
{
    ValkyriePrefs prefs = ValkyriePrefs::load();

    enum opt { OptBack, OptToggleHaptic, OptToggleSound, OptTogglePhone };
    static char hapticLabel[22];
    static char soundLabel[20];
    static char phoneLabel[20];
    snprintf(hapticLabel, sizeof(hapticLabel), "Haptic: %s", prefs.threatDetectionHapticEnabled ? "On" : "Off");
    snprintf(soundLabel, sizeof(soundLabel), "Sound: %s", prefs.threatDetectionSoundEnabled ? "On" : "Off");
    snprintf(phoneLabel, sizeof(phoneLabel), "Phone: %s", prefs.phoneNotificationsEnabled ? "On" : "Off");

    static const char *labels[] = {"Back", hapticLabel, soundLabel, phoneLabel};
    static int enums[] = {OptBack, OptToggleHaptic, OptToggleSound, OptTogglePhone};

    graphics::BannerOverlayOptions bannerOptions{};
    bannerOptions.message = "Notifications";
    bannerOptions.optionsArrayPtr = labels;
    bannerOptions.optionsEnumPtr = enums;
    bannerOptions.optionsCount = 4;
    bannerOptions.bannerCallback = [](int selected) -> void {
        if (selected == OptBack) {
            graphics::menuHandler::menuQueue = graphics::menuHandler::ValkyrieSettingsMenu;
            screen->runNow();
            return;
        }
        ValkyriePrefs p = ValkyriePrefs::load();
        if (selected == OptToggleHaptic)
            p.threatDetectionHapticEnabled = !p.threatDetectionHapticEnabled;
        else if (selected == OptToggleSound)
            p.threatDetectionSoundEnabled = !p.threatDetectionSoundEnabled;
        else if (selected == OptTogglePhone)
            p.phoneNotificationsEnabled = !p.phoneNotificationsEnabled;
        else
            return;
        p.save();
        if (bleThreatDetector)
            bleThreatDetector->reloadPrefs();
        // Re-queue this menu so labels refresh and the user stays on Notifications
        // (showSimpleBanner would dismiss the options overlay).
        graphics::menuHandler::menuQueue = graphics::menuHandler::ValkyrieNotificationsMenu;
        screen->runNow();
    };
    screen->showOverlayBanner(bannerOptions);
}

void showConstantScanEnableConfirmMenu()
{
    static const char *opts[] = {"No", "Yes"};
    static const int enums[] = {0, 1};
    graphics::BannerOverlayOptions b{};
    b.message = "Enable constant scanning mode?\n\nNote: this will diminish battery life.";
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
