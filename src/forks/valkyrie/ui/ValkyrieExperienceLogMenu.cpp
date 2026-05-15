#include "ValkyrieExperienceLogMenu.h"

#include "configuration.h"

#if defined(ARCH_ESP32) && defined(VALKYRIE_FORK)

#include "../persist/ExperienceLog.h"
#include "graphics/Screen.h"
#include "graphics/draw/MenuHandler.h"
#include "main.h"

#include <cstdio>

namespace valkyrie
{

namespace
{

static size_t s_xpPage = 0;
static constexpr size_t kLinesPerPage = 3;

enum opt : int {
    OptBack = 0,
    OptLine0 = 10,
    OptLine1 = 11,
    OptLine2 = 12,
    OptPrev = 20,
    OptNext = 21,
};

static size_t linesOnPage(size_t page, size_t perPage, size_t total)
{
    const size_t first = page * perPage;
    if (first >= total)
        return 0;
    size_t remaining = total - first;
    return remaining > perPage ? perPage : remaining;
}

} // namespace

void experienceLogMenuResetPage()
{
    s_xpPage = 0;
}

void showExperienceLogMenu()
{
    const size_t total = ExperienceLog::count();
    const size_t pageCount = (total == 0) ? 1 : ((total - 1U) / kLinesPerPage) + 1U;
    if (s_xpPage >= pageCount)
        s_xpPage = pageCount - 1U;

    static char title[48];
    snprintf(title, sizeof(title), "Exp log %u/%u", (unsigned)(s_xpPage + 1U), (unsigned)pageCount);

    static char lineLbl[kLinesPerPage][52];
    static const char *labels[7];
    static int enums[7];
    int n = 0;

    labels[n] = "Back";
    enums[n++] = OptBack;

    const size_t linesThisPage = linesOnPage(s_xpPage, kLinesPerPage, total);
    for (size_t i = 0; i < linesThisPage; ++i) {
        const size_t recentIndex = s_xpPage * kLinesPerPage + i;
        if (!ExperienceLog::formatRecentLine(recentIndex, lineLbl[i], sizeof(lineLbl[i]))) {
            snprintf(lineLbl[i], sizeof(lineLbl[i]), "+? XP");
        }
        labels[n] = lineLbl[i];
        enums[n++] = OptLine0 + (int)i;
    }

    labels[n] = "Prev";
    enums[n++] = OptPrev;
    labels[n] = "Next";
    enums[n++] = OptNext;

    static char msg[72];
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
        const size_t totalNow = ExperienceLog::count();
        const size_t pc = (totalNow == 0) ? 1 : ((totalNow - 1U) / kLinesPerPage) + 1U;

        if (selected == OptBack) {
            graphics::menuHandler::menuQueue = graphics::menuHandler::ValkyrieRootMenu;
        } else if (selected == OptPrev) {
            if (s_xpPage > 0)
                s_xpPage--;
            graphics::menuHandler::menuQueue = graphics::menuHandler::ValkyrieExperienceLogMenu;
        } else if (selected == OptNext) {
            if (s_xpPage + 1U < pc)
                s_xpPage++;
            graphics::menuHandler::menuQueue = graphics::menuHandler::ValkyrieExperienceLogMenu;
        } else {
            graphics::menuHandler::menuQueue = graphics::menuHandler::ValkyrieExperienceLogMenu;
        }
        screen->runNow();
    };
    screen->showOverlayBanner(bannerOptions);
}

} // namespace valkyrie

#endif
