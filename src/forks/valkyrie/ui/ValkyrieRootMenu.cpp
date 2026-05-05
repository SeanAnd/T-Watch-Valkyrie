#include "ValkyrieRootMenu.h"

#include "configuration.h"

#if defined(ARCH_ESP32) && defined(VALKYRIE_FORK)

#include "ValkyrieThreatsMenu.h"
#include "ValkyrieThreatLogMenu.h"
#include "ValkyrieIgnoreListMenu.h"
#include "graphics/Screen.h"
#include "graphics/draw/MenuHandler.h"
#include "main.h"

namespace valkyrie
{

void showRootMenu()
{
    enum opt {
        OptBack,
        OptThreatLog,
        OptIgnoredDevices,
        OptThreats,
        OptBluetooth,
        OptWiFiTgl,
        OptSettings,
        EnumEnd
    };
    static const char *labels[EnumEnd] = {"Back"};
    static int enums[EnumEnd] = {OptBack};
    int n = 1;

    labels[n] = "Threat log";
    enums[n++] = OptThreatLog;
    labels[n] = "Ignored devices";
    enums[n++] = OptIgnoredDevices;
    labels[n] = "Threats";
    enums[n++] = OptThreats;
    labels[n] = "Bluetooth";
    enums[n++] = OptBluetooth;
#if HAS_WIFI && !defined(ARCH_PORTDUINO)
    labels[n] = "WiFi";
    enums[n++] = OptWiFiTgl;
#endif
    labels[n] = "Settings";
    enums[n++] = OptSettings;

    graphics::BannerOverlayOptions bannerOptions;
    bannerOptions.message = "Valkyrie";
    bannerOptions.optionsArrayPtr = labels;
    bannerOptions.optionsEnumPtr = enums;
    bannerOptions.optionsCount = (uint8_t)n;
    bannerOptions.bannerCallback = [](int selected) -> void {
        if (selected == OptThreatLog) {
            threatLogMenuResetPage();
            graphics::menuHandler::menuQueue = graphics::menuHandler::ValkyrieThreatLogMenu;
            screen->runNow();
        } else if (selected == OptIgnoredDevices) {
            ignoreListMenuResetPage();
            graphics::menuHandler::menuQueue = graphics::menuHandler::ValkyrieIgnoreListMenu;
            screen->runNow();
        } else if (selected == OptThreats) {
            graphics::menuHandler::menuQueue = graphics::menuHandler::ValkyrieThreatsMenu;
            screen->runNow();
        } else if (selected == OptBluetooth) {
            graphics::menuHandler::menuQueue = graphics::menuHandler::BluetoothToggleMenu;
            screen->runNow();
#if HAS_WIFI && !defined(ARCH_PORTDUINO)
        } else if (selected == OptWiFiTgl) {
            graphics::menuHandler::menuQueue = graphics::menuHandler::WifiToggleMenu;
            screen->runNow();
#endif
        } else if (selected == OptSettings) {
            graphics::menuHandler::menuQueue = graphics::menuHandler::ValkyrieSettingsMenu;
            screen->runNow();
        }
    };
    screen->showOverlayBanner(bannerOptions);
}

} // namespace valkyrie

#endif
