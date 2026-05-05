#include "ValkyrieIgnoreListMenu.h"

#include "configuration.h"

#if defined(ARCH_ESP32) && defined(VALKYRIE_FORK)

#include "../ThreatTypeUi.h"
#include "../persist/ThreatIgnoreList.h"
#include "ValkyrieIgnoreListEntryMenu.h"
#include "graphics/Screen.h"
#include "graphics/draw/MenuHandler.h"

#include <cstddef>
#include <cstdio>

namespace valkyrie
{

static size_t s_ignorePage = 0;
static constexpr size_t kLinesPerPage = 3;

void ignoreListMenuResetPage()
{
    s_ignorePage = 0;
}

namespace
{

static size_t linesOnIgnorePage(size_t page, size_t perPage, size_t total)
{
    if (total == 0 || page * perPage >= total)
        return 0;
    size_t endExclusive = total - page * perPage;
    size_t startInclusive = endExclusive > perPage ? endExclusive - perPage : 0;
    return endExclusive - startInclusive;
}

static size_t storageIndexForLine(size_t page, size_t lineOnPage, size_t totalCount)
{
    size_t endExclusive = totalCount - page * kLinesPerPage;
    size_t startInclusive = endExclusive > kLinesPerPage ? endExclusive - kLinesPerPage : 0;
    size_t linesOnPage = endExclusive - startInclusive;
    if (lineOnPage >= linesOnPage)
        return SIZE_MAX;
    return endExclusive - 1 - lineOnPage;
}

enum opt : int {
    OptBack = 0,
    OptLine0 = 10,
    OptLine1 = 11,
    OptLine2 = 12,
    OptPrev = 20,
    OptNext = 21,
};

} // namespace

void showIgnoreListMenu()
{
    size_t total = ThreatIgnoreList::count();
    size_t pageCount = (total == 0) ? 1 : ((total - 1) / kLinesPerPage) + 1;
    if (s_ignorePage >= pageCount)
        s_ignorePage = pageCount - 1;

    size_t linesThisPage = linesOnIgnorePage(s_ignorePage, kLinesPerPage, total);

    static char title[72];
    snprintf(title, sizeof(title), "Ignored %u/%u", (unsigned)(s_ignorePage + 1), (unsigned)pageCount);

    static char lineLbl[3][44];
    static const char *labels[8];
    static int enums[8];
    int n = 0;

    labels[n] = "Back";
    enums[n++] = OptBack;

    for (size_t i = 0; i < linesThisPage; ++i) {
        size_t st = storageIndexForLine(s_ignorePage, i, total);
        ThreatType t = ThreatType::None;
        uint8_t mac[6] = {0};
        if (st == SIZE_MAX || !ThreatIgnoreList::getEntry(st, &t, mac))
            break;
        snprintf(lineLbl[i], sizeof(lineLbl[i]), "%s %02X:%02X:%02X:%02X:%02X:%02X", threatTypeMenuLabel(t), mac[0], mac[1], mac[2],
                 mac[3], mac[4], mac[5]);
        labels[n] = lineLbl[i];
        enums[n++] = OptLine0 + (int)i;
    }

    labels[n] = "Prev";
    enums[n++] = OptPrev;
    labels[n] = "Next";
    enums[n++] = OptNext;

    static char msg[96];
    if (total == 0)
        snprintf(msg, sizeof(msg), "%s\n(empty)", title);
    else
        snprintf(msg, sizeof(msg), "%s", title);

    graphics::BannerOverlayOptions banner{};
    banner.message = msg;
    banner.optionsArrayPtr = labels;
    banner.optionsEnumPtr = enums;
    banner.optionsCount = (uint8_t)n;
    banner.bannerCallback = [](int selected) -> void {
        size_t totalL = ThreatIgnoreList::count();
        size_t pc = (totalL == 0) ? 1 : ((totalL - 1) / kLinesPerPage) + 1;
        size_t linesP = linesOnIgnorePage(s_ignorePage, kLinesPerPage, totalL);

        if (selected == OptBack) {
            graphics::menuHandler::menuQueue = graphics::menuHandler::ValkyrieRootMenu;
            screen->runNow();
        } else if (selected >= OptLine0 && selected <= OptLine2) {
            int li = selected - OptLine0;
            if (li >= 0 && (size_t)li < linesP) {
                size_t st = storageIndexForLine(s_ignorePage, (size_t)li, totalL);
                if (st != SIZE_MAX) {
                    ignoreListEntryMenuOpen(st);
                    graphics::menuHandler::menuQueue = graphics::menuHandler::ValkyrieIgnoreListEntryMenu;
                    screen->runNow();
                }
            }
        } else if (selected == OptPrev) {
            if (s_ignorePage > 0)
                s_ignorePage--;
            graphics::menuHandler::menuQueue = graphics::menuHandler::ValkyrieIgnoreListMenu;
            screen->runNow();
        } else if (selected == OptNext) {
            if (s_ignorePage + 1 < pc)
                s_ignorePage++;
            graphics::menuHandler::menuQueue = graphics::menuHandler::ValkyrieIgnoreListMenu;
            screen->runNow();
        }
    };
    screen->showOverlayBanner(banner);
}

} // namespace valkyrie

#endif
