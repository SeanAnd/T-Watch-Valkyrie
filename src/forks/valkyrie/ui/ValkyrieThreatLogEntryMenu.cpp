#include "ValkyrieThreatLogEntryMenu.h"

#include "configuration.h"

#if defined(ARCH_ESP32) && defined(VALKYRIE_FORK)

#include "../ThreatTypeUi.h"
#include "../modules/BleThreatDetectorModule.h"
#include "../persist/ThreatIgnoreList.h"
#include "../persist/ThreatLog.h"
#include "ValkyrieFork.h"
#include "ValkyrieHeartbeatFeedback.h"
#include "ValkyrieHeartbeatFrame.h"
#include "ValkyrieHeartbeatInput.h"
#include "graphics/Screen.h"
#include "graphics/draw/MenuHandler.h"
#include "main.h"

#include <cstdio>
#include <cstring>

namespace valkyrie
{

namespace
{
static size_t s_page = 0;
static size_t s_lineOnPage = 0;
} // namespace

void threatLogEntryMenuOpen(size_t pageIndex, size_t lineOnPage)
{
    s_page = pageIndex;
    s_lineOnPage = lineOnPage;
}

void showThreatLogEntryMenu()
{
    static constexpr size_t kLinesPerPage = 3;
    char raw[256];
    if (!ThreatLog::readViewerLine(s_page, s_lineOnPage, kLinesPerPage, raw, sizeof(raw))) {
        static const char *labels[] = {"Back"};
        static const int enums[] = {0};
        graphics::BannerOverlayOptions banner{};
        banner.message = "Cannot read entry";
        banner.optionsArrayPtr = labels;
        banner.optionsEnumPtr = const_cast<int *>(enums);
        banner.optionsCount = 1;
        banner.bannerCallback = [](int) -> void {
            graphics::menuHandler::menuQueue = graphics::menuHandler::ValkyrieThreatLogMenu;
            screen->runNow();
        };
        screen->showOverlayBanner(banner);
        return;
    }

    ThreatType t = ThreatType::None;
    uint8_t mac[6] = {0};
    ThreatSource srcLog = ThreatSource::Ble;
    uint8_t channelLog = 0;
    if (!ThreatLog::decodeFullIdentityFromCsvLine(raw, &t, mac, &srcLog, &channelLog)) {
        static const char *labels[] = {"Back"};
        static const int enums[] = {0};
        graphics::BannerOverlayOptions banner{};
        banner.message = "Cannot read entry";
        banner.optionsArrayPtr = labels;
        banner.optionsEnumPtr = const_cast<int *>(enums);
        banner.optionsCount = 1;
        banner.bannerCallback = [](int) -> void {
            graphics::menuHandler::menuQueue = graphics::menuHandler::ValkyrieThreatLogMenu;
            screen->runNow();
        };
        screen->showOverlayBanner(banner);
        return;
    }

    static char msg[96];
    snprintf(msg, sizeof(msg), "%s\n%02X:%02X:%02X:%02X:%02X:%02X", threatTypeMenuLabel(t), mac[0], mac[1], mac[2], mac[3], mac[4],
             mac[5]);

    enum opt { OptBack, OptAddIgnore, OptHeartbeat };
    static const char *labels[] = {"Back", "Add to ignore list", "Heartbeat"};
    static const int enums[] = {OptBack, OptAddIgnore, OptHeartbeat};

    static ThreatType s_typeForAdd;
    static uint8_t s_macForAdd[6];
    static ThreatSource s_sourceForAdd;
    static uint8_t s_channelForAdd;
    s_typeForAdd = t;
    memcpy(s_macForAdd, mac, 6);
    s_sourceForAdd = srcLog;
    s_channelForAdd = channelLog;

    graphics::BannerOverlayOptions banner{};
    banner.message = msg;
    banner.optionsArrayPtr = labels;
    banner.optionsEnumPtr = const_cast<int *>(enums);
    banner.optionsCount = 3;
    banner.bannerCallback = [](int selected) -> void {
        if (selected == OptBack) {
            graphics::menuHandler::menuQueue = graphics::menuHandler::ValkyrieThreatLogMenu;
            screen->runNow();
            return;
        }
        if (selected == OptAddIgnore) {
            ThreatIgnoreList::add(s_typeForAdd, s_macForAdd);
            if (bleThreatDetector)
                bleThreatDetector->reloadIgnoreList();
            graphics::menuHandler::menuQueue = graphics::menuHandler::ValkyrieThreatLogMenu;
            screen->runNow();
            return;
        }
        if (selected == OptHeartbeat) {
            if (!bleThreatDetector) {
                static const char *errLabels[] = {"Back"};
                static const int errEnums[] = {0};
                graphics::BannerOverlayOptions err{};
                err.message = "Detection unavailable";
                err.optionsArrayPtr = errLabels;
                err.optionsEnumPtr = const_cast<int *>(errEnums);
                err.optionsCount = 1;
                err.bannerCallback = [](int) {
                    graphics::menuHandler::menuQueue = graphics::menuHandler::ValkyrieThreatLogEntryMenu;
                    screen->runNow();
                };
                screen->showOverlayBanner(err);
                return;
            }
            resetHeartbeatAlertUiState();
            if (!bleThreatDetector->startHeartbeat(s_macForAdd, s_typeForAdd, s_sourceForAdd, s_channelForAdd)) {
                static const char *errLabels[] = {"Back"};
                static const int errEnums[] = {0};
                graphics::BannerOverlayOptions err{};
                err.message = (s_sourceForAdd == ThreatSource::Wifi) ? "Wi-Fi required" : "Bluetooth required";
                err.optionsArrayPtr = errLabels;
                err.optionsEnumPtr = const_cast<int *>(errEnums);
                err.optionsCount = 1;
                err.bannerCallback = [](int) {
                    graphics::menuHandler::menuQueue = graphics::menuHandler::ValkyrieThreatLogEntryMenu;
                    screen->runNow();
                };
                screen->showOverlayBanner(err);
                return;
            }
            setHeartbeatAlertUiActive(true);
            startHeartbeatFeedback();
            screen->startAlert(drawHeartbeatFrame);
        }
    };
    screen->showOverlayBanner(banner);
}

} // namespace valkyrie

#endif
