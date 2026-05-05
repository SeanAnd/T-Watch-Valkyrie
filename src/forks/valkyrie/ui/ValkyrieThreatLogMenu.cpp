#include "ValkyrieThreatLogMenu.h"

#include "configuration.h"

#if defined(ARCH_ESP32) && defined(VALKYRIE_FORK)

#include "../ThreatTypeUi.h"
#include "ValkyrieThreatLogEntryMenu.h"
#include "persist/ThreatLog.h"
#include "graphics/Screen.h"
#include "graphics/draw/MenuHandler.h"
#include "main.h"

#include <cstring>
#include <cstdio>

namespace valkyrie
{

static size_t s_threatPage = 0;
static constexpr size_t kLinesPerPage = 3;

// Confirmation must not open from inside the banner SELECT callback — NotificationRenderer
// calls resetBanner() immediately after the callback, which clears any nested overlay.
static bool s_pendingClearConfirm = false;

void threatLogMenuResetPage()
{
    s_threatPage = 0;
}

namespace
{

static size_t linesOnThreatPage(size_t page, size_t perPage, size_t total)
{
    if (total == 0 || page * perPage >= total)
        return 0;
    size_t endExclusive = total - page * perPage;
    size_t startInclusive = endExclusive > perPage ? endExclusive - perPage : 0;
    return endExclusive - startInclusive;
}

enum opt : int {
    OptBack = 0,
    OptLine0 = 10,
    OptLine1 = 11,
    OptLine2 = 12,
    OptPrev = 20,
    OptNext = 21,
    OptClearAll = 22,
};

} // namespace

void showThreatLogMenu()
{
    if (s_pendingClearConfirm) {
        s_pendingClearConfirm = false;
        static const char *confirmLabels[] = {"No", "Yes"};
        graphics::BannerOverlayOptions confirm{};
        confirm.message = "Erase all threat log entries?";
        confirm.optionsArrayPtr = confirmLabels;
        confirm.optionsCount = 2;
        confirm.bannerCallback = [](int confirmSelected) -> void {
            if (confirmSelected == 1) {
                ThreatLog::clearAll();
                threatLogMenuResetPage();
                graphics::menuHandler::menuQueue = graphics::menuHandler::ValkyrieRootMenu;
            } else {
                graphics::menuHandler::menuQueue = graphics::menuHandler::ValkyrieThreatLogMenu;
            }
            screen->runNow();
        };
        screen->showOverlayBanner(confirm);
        return;
    }

    size_t total = ThreatLog::lineCount();
    size_t pageCount = (total == 0) ? 1 : ((total - 1) / kLinesPerPage) + 1;
    if (s_threatPage >= pageCount)
        s_threatPage = pageCount - 1;

    size_t linesThisPage = linesOnThreatPage(s_threatPage, kLinesPerPage, total);

    static char title[72];
    snprintf(title, sizeof(title), "Threat log %u/%u", (unsigned)(s_threatPage + 1), (unsigned)pageCount);

    static char lineLbl[3][44];
    static const char *labels[8];
    static int enums[8];
    int n = 0;

    labels[n] = "Back";
    enums[n++] = OptBack;

    for (size_t i = 0; i < linesThisPage; ++i) {
        char raw[256];
        if (!ThreatLog::readViewerLine(s_threatPage, i, kLinesPerPage, raw, sizeof(raw)))
            break;
        ThreatType t = ThreatType::None;
        uint8_t mac[6] = {0};
        if (ThreatLog::decodeIdentityFromCsvLine(raw, &t, mac)) {
            snprintf(lineLbl[i], sizeof(lineLbl[i]), "%s %02X:%02X:%02X:%02X:%02X:%02X", threatTypeMenuLabel(t), mac[0], mac[1],
                     mac[2], mac[3], mac[4], mac[5]);
        } else {
            strncpy(lineLbl[i], raw, sizeof(lineLbl[0]) - 1);
            lineLbl[i][sizeof(lineLbl[0]) - 1] = '\0';
        }
        labels[n] = lineLbl[i];
        enums[n++] = OptLine0 + (int)i;
    }

    labels[n] = "Prev";
    enums[n++] = OptPrev;
    labels[n] = "Next";
    enums[n++] = OptNext;
    labels[n] = "Clear All";
    enums[n++] = OptClearAll;

    static char msg[96];
    if (total == 0)
        snprintf(msg, sizeof(msg), "%s\n(empty)", title);
    else
        snprintf(msg, sizeof(msg), "%s", title);

    graphics::BannerOverlayOptions bannerOptions{};
    bannerOptions.message = msg;
    bannerOptions.optionsArrayPtr = labels;
    bannerOptions.optionsEnumPtr = enums;
    bannerOptions.optionsCount = (uint8_t)n;
    bannerOptions.bannerCallback = [](int selected) -> void {
        size_t totalL = ThreatLog::lineCount();
        size_t pc = (totalL == 0) ? 1 : ((totalL - 1) / kLinesPerPage) + 1;
        size_t linesP = linesOnThreatPage(s_threatPage, kLinesPerPage, totalL);

        if (selected == OptBack) {
            graphics::menuHandler::menuQueue = graphics::menuHandler::ValkyrieRootMenu;
            screen->runNow();
        } else if (selected >= OptLine0 && selected <= OptLine2) {
            int li = selected - OptLine0;
            if (li >= 0 && (size_t)li < linesP) {
                threatLogEntryMenuOpen(s_threatPage, (size_t)li);
                graphics::menuHandler::menuQueue = graphics::menuHandler::ValkyrieThreatLogEntryMenu;
                screen->runNow();
            }
        } else if (selected == OptPrev) {
            if (s_threatPage > 0)
                s_threatPage--;
            graphics::menuHandler::menuQueue = graphics::menuHandler::ValkyrieThreatLogMenu;
            screen->runNow();
        } else if (selected == OptNext) {
            if (s_threatPage + 1 < pc)
                s_threatPage++;
            graphics::menuHandler::menuQueue = graphics::menuHandler::ValkyrieThreatLogMenu;
            screen->runNow();
        } else if (selected == OptClearAll) {
            s_pendingClearConfirm = true;
            graphics::menuHandler::menuQueue = graphics::menuHandler::ValkyrieThreatLogMenu;
            screen->runNow();
        }
    };
    screen->showOverlayBanner(bannerOptions);
}

} // namespace valkyrie

#endif
