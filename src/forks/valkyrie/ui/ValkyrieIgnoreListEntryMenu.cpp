#include "ValkyrieIgnoreListEntryMenu.h"

#include "configuration.h"

#if defined(ARCH_ESP32) && defined(VALKYRIE_FORK)

#include "../ThreatTypeUi.h"
#include "../modules/BleThreatDetectorModule.h"
#include "../persist/ThreatIgnoreList.h"
#include "ValkyrieFork.h"
#include "graphics/Screen.h"
#include "graphics/draw/MenuHandler.h"
#include "main.h"

#include <cstdio>

namespace valkyrie
{

namespace
{
static size_t s_storageIndex = 0;
} // namespace

void ignoreListEntryMenuOpen(size_t storageIndex)
{
    s_storageIndex = storageIndex;
}

void showIgnoreListEntryMenu()
{
    ThreatType t = ThreatType::None;
    uint8_t mac[6] = {0};
    if (!ThreatIgnoreList::getEntry(s_storageIndex, &t, mac)) {
        static const char *labels[] = {"Back"};
        static const int enums[] = {0};
        graphics::BannerOverlayOptions banner{};
        banner.message = "Entry missing";
        banner.optionsArrayPtr = labels;
        banner.optionsEnumPtr = const_cast<int *>(enums);
        banner.optionsCount = 1;
        banner.bannerCallback = [](int) -> void {
            graphics::menuHandler::menuQueue = graphics::menuHandler::ValkyrieIgnoreListMenu;
            screen->runNow();
        };
        screen->showOverlayBanner(banner);
        return;
    }

    static char msg[96];
    snprintf(msg, sizeof(msg), "%s\n%02X:%02X:%02X:%02X:%02X:%02X", threatTypeMenuLabel(t), mac[0], mac[1], mac[2], mac[3], mac[4],
             mac[5]);

    enum opt { OptBack, OptRemove };
    static const char *labels[] = {"Back", "Remove from ignore list"};
    static const int enums[] = {OptBack, OptRemove};

    static size_t s_removeIndex = 0;
    s_removeIndex = s_storageIndex;

    graphics::BannerOverlayOptions banner{};
    banner.message = msg;
    banner.optionsArrayPtr = labels;
    banner.optionsEnumPtr = const_cast<int *>(enums);
    banner.optionsCount = 2;
    banner.bannerCallback = [](int selected) -> void {
        if (selected == OptBack) {
            graphics::menuHandler::menuQueue = graphics::menuHandler::ValkyrieIgnoreListMenu;
            screen->runNow();
            return;
        }
        if (selected == OptRemove) {
            ThreatIgnoreList::removeAt(s_removeIndex);
            if (bleThreatDetector)
                bleThreatDetector->reloadIgnoreList();
            graphics::menuHandler::menuQueue = graphics::menuHandler::ValkyrieIgnoreListMenu;
            screen->runNow();
        }
    };
    screen->showOverlayBanner(banner);
}

} // namespace valkyrie

#endif
