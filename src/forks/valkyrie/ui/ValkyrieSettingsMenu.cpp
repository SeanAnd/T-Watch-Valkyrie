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
    enum opt { OptBack, OptToggleDetector, OptConstantScan, OptWifiThreatScan, OptNotifications };
    static char wifiScanLabel[44];
    snprintf(wifiScanLabel, sizeof(wifiScanLabel), "WiFi threat scan: %s", prefs.wifiThreatScanEnabled ? "On" : "Off");

    static char detectorToggleLabel[28];
    snprintf(detectorToggleLabel, sizeof(detectorToggleLabel), "%s detector", prefs.bleThreatDetectorEnabled ? "Disable" : "Enable");

    static char constantScanLabel[40];
    snprintf(constantScanLabel, sizeof(constantScanLabel), "Scan Mode: %s", prefs.constantBleScanMode ? "Constant" : "Interval");

    static const char *labels[] = {"Back", detectorToggleLabel, constantScanLabel, wifiScanLabel, "Notifications"};
    static int enums[] = {OptBack, OptToggleDetector, OptConstantScan, OptWifiThreatScan, OptNotifications};

    graphics::BannerOverlayOptions bannerOptions{};
    bannerOptions.message = "Valkyrie settings";
    bannerOptions.optionsArrayPtr = labels;
    bannerOptions.optionsEnumPtr = enums;
    bannerOptions.optionsCount = 5;
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
        } else if (selected == OptWifiThreatScan) {
            ValkyriePrefs p = ValkyriePrefs::load();
            p.wifiThreatScanEnabled = !p.wifiThreatScanEnabled;
            p.save();
            if (bleThreatDetector)
                bleThreatDetector->reloadPrefs();
            screen->showSimpleBanner("Saved.", 4000);
        } else if (selected == OptNotifications) {
            graphics::menuHandler::menuQueue = graphics::menuHandler::ValkyrieNotificationsMenu;
            screen->runNow();
        }
    };
    screen->showOverlayBanner(bannerOptions);
#else
    enum opt { OptBack, OptToggleDetector, OptConstantScan, OptNotifications };
    static char detectorToggleLabel[28];
    snprintf(detectorToggleLabel, sizeof(detectorToggleLabel), "%s detector", prefs.bleThreatDetectorEnabled ? "Disable" : "Enable");

    static char constantScanLabel[40];
    snprintf(constantScanLabel, sizeof(constantScanLabel), "Scan Mode: %s", prefs.constantBleScanMode ? "Constant" : "Interval");

    static const char *labels[] = {"Back", detectorToggleLabel, constantScanLabel, "Notifications"};
    static int enums[] = {OptBack, OptToggleDetector, OptConstantScan, OptNotifications};

    graphics::BannerOverlayOptions bannerOptions{};
    bannerOptions.message = "Valkyrie settings";
    bannerOptions.optionsArrayPtr = labels;
    bannerOptions.optionsEnumPtr = enums;
    bannerOptions.optionsCount = 4;
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
        } else if (selected == OptNotifications) {
            graphics::menuHandler::menuQueue = graphics::menuHandler::ValkyrieNotificationsMenu;
            screen->runNow();
        }
    };
    screen->showOverlayBanner(bannerOptions);
#endif
}

void showNotificationsMenu()
{
    ValkyriePrefs prefs = ValkyriePrefs::load();

    enum opt { OptBack, OptToggleHaptic, OptToggleSound };
    static char hapticLabel[22];
    static char soundLabel[20];
    snprintf(hapticLabel, sizeof(hapticLabel), "Haptic: %s", prefs.threatDetectionHapticEnabled ? "On" : "Off");
    snprintf(soundLabel, sizeof(soundLabel), "Sound: %s", prefs.threatDetectionSoundEnabled ? "On" : "Off");

    static const char *labels[] = {"Back", hapticLabel, soundLabel};
    static int enums[] = {OptBack, OptToggleHaptic, OptToggleSound};

    graphics::BannerOverlayOptions bannerOptions{};
    bannerOptions.message = "Notifications";
    bannerOptions.optionsArrayPtr = labels;
    bannerOptions.optionsEnumPtr = enums;
    bannerOptions.optionsCount = 3;
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
