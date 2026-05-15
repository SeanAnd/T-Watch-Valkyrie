#include "ValkyrieWardriveMenu.h"

#include "configuration.h"

#if defined(ARCH_ESP32) && defined(VALKYRIE_FORK)

#include "../modules/WardriveSession.h"
#include "../persist/ThreatExperience.h"
#include "../prefs/ValkyriePrefs.h"
#include "ValkyrieFork.h"
#include "ValkyrieSettingsMenu.h"
#include "ValkyrieWardriveFrame.h"
#include "ValkyrieWardriveInput.h"
#include "graphics/Screen.h"
#include "graphics/draw/MenuHandler.h"
#include "main.h"

#include <cstdio>

namespace valkyrie
{

static constexpr uint16_t kWardrivePeriodChoicesMs[] = {5000, 10000, 15000, 30000};

static int8_t wardrivePeriodHighlightIndex(uint16_t currentMs)
{
    constexpr unsigned N = sizeof(kWardrivePeriodChoicesMs) / sizeof(kWardrivePeriodChoicesMs[0]);
    for (unsigned i = 0; i < N; i++) {
        if (currentMs == kWardrivePeriodChoicesMs[i])
            return (int8_t)i;
    }
    if (currentMs <= 7500)
        return 0;
    if (currentMs <= 12500)
        return 1;
    if (currentMs <= 22500)
        return 2;
    return 3;
}

void showWardriveMenu()
{
    static const char *labels[] = {"No", "Yes"};
    static const int enums[] = {0, 1};
    graphics::BannerOverlayOptions banner{};
    banner.message = "Start wardrive?\nTune scan period / GPS / BLE\nprefs in Wardrive settings.\n(Settings > Wardrive)";
    banner.optionsArrayPtr = labels;
    banner.optionsEnumPtr = const_cast<int *>(enums);
    banner.optionsCount = 2;
    banner.bannerCallback = [](int selected) -> void {
        if (selected != 1) {
            graphics::menuHandler::menuQueue = graphics::menuHandler::ValkyrieRootMenu;
            screen->runNow();
            return;
        }
        WardriveSession *session = getOrCreateWardriveSession();
        if (!session) {
            screen->showSimpleBanner("Wardrive: init failed", 4000);
            graphics::menuHandler::menuQueue = graphics::menuHandler::ValkyrieRootMenu;
            screen->runNow();
            return;
        }
        if (!session->begin()) {
            screen->showSimpleBanner("Wardrive: could not start", 4000);
            graphics::menuHandler::menuQueue = graphics::menuHandler::ValkyrieRootMenu;
            screen->runNow();
            return;
        }
        resetWardriveFrameState();
        setWardriveAlertUiActive(true);
        screen->startAlert(drawWardriveFrame);
    };
    screen->showOverlayBanner(banner);
}

void showWardriveScanPeriodMenu()
{
    ValkyriePrefs prefs = ValkyriePrefs::load();
    static const char *labels[] = {"5s", "10s", "15s", "30s", "Cancel"};
    graphics::BannerOverlayOptions banner{};
    banner.message = "Wardrive scan period\n(higher = better BLE position\nupdates from phone)";
    banner.optionsArrayPtr = labels;
    banner.optionsEnumPtr = nullptr;
    banner.optionsCount = 5;
    banner.InitialSelected = wardrivePeriodHighlightIndex(prefs.wardriveScanPeriodMs);
    banner.bannerCallback = [](int ix) -> void {
        constexpr unsigned N = sizeof(kWardrivePeriodChoicesMs) / sizeof(kWardrivePeriodChoicesMs[0]);
        if (ix >= 0 && (unsigned)ix < N) {
            ValkyriePrefs q = ValkyriePrefs::load();
            q.wardriveScanPeriodMs = kWardrivePeriodChoicesMs[(unsigned)ix];
            q.save();
            if (wardriveSession)
                wardriveSession->reloadPrefs(q);
        }
        graphics::menuHandler::menuQueue = graphics::menuHandler::ValkyrieWardriveSettingsMenu;
        screen->runNow();
    };
    screen->showOverlayBanner(banner);
}

void showWardriveSummaryMenu()
{
    static char message[160];
    static char doneLabel[12];

    uint32_t aps = 0, dist = 0, threats = 0, xpDelta = 0;
    bool aborted = false;
    if (hasFinalWardriveStats()) {
        const WardriveStats &st = getFinalWardriveStats();
        aps = st.apsLoggedDistinct;
        dist = st.distanceMeters;
        threats = st.threatsHit;
        aborted = wardriveSession ? wardriveSession->wasAborted() : false;
        xpDelta = ThreatExperience::onWardriveSessionEnded(aps, dist, threats);
    }

    snprintf(message, sizeof(message), "%sAPs: %u\nDist: %um\nThreats: %u\n+%u XP",
             aborted ? "Wardrive stopped (abort)\n" : "Wardrive stopped\n", (unsigned)aps, (unsigned)dist,
             (unsigned)threats, (unsigned)xpDelta);
    snprintf(doneLabel, sizeof(doneLabel), "Done");

    static const char *labels[1];
    labels[0] = doneLabel;
    static const int enums[] = {0};

    graphics::BannerOverlayOptions banner{};
    banner.message = message;
    banner.optionsArrayPtr = labels;
    banner.optionsEnumPtr = const_cast<int *>(enums);
    banner.optionsCount = 1;
    banner.bannerCallback = [](int) -> void {
        if (screen)
            screen->queueSwitchToValkyrieHubFrame();
    };
    screen->showOverlayBanner(banner);
}

void showWardriveSettingsMenu()
{
    ValkyriePrefs prefs = ValkyriePrefs::load();

    enum opt { OptBack, OptRequireFix, OptPeriod, OptPhone };
    static char reqFixLabel[32];
    static char periodLabel[32];
    static char phoneLabel[36];
    snprintf(reqFixLabel, sizeof(reqFixLabel), "Require GPS fix: %s", prefs.wardriveRequireFix ? "On" : "Off");
    snprintf(periodLabel, sizeof(periodLabel), "Scan period: %us", (unsigned)(prefs.wardriveScanPeriodMs / 1000U));
    snprintf(phoneLabel, sizeof(phoneLabel), "Phone threats: %s", prefs.wardrivePhoneNotify ? "On" : "Off");

    static const char *labels[] = {"Back", reqFixLabel, periodLabel, phoneLabel};
    static int enums[] = {OptBack, OptRequireFix, OptPeriod, OptPhone};

    graphics::BannerOverlayOptions banner{};
    banner.message = "Wardrive settings\nProtects BLE + phone GPS sync.";
    banner.optionsArrayPtr = labels;
    banner.optionsEnumPtr = enums;
    banner.optionsCount = 4;
    banner.bannerCallback = [](int selected) -> void {
        if (selected == OptBack) {
            graphics::menuHandler::menuQueue = graphics::menuHandler::ValkyrieSettingsMenu;
            screen->runNow();
            return;
        }
        ValkyriePrefs p = ValkyriePrefs::load();
        if (selected == OptRequireFix) {
            p.wardriveRequireFix = !p.wardriveRequireFix;
            p.save();
            if (wardriveSession)
                wardriveSession->reloadPrefs(p);
            graphics::menuHandler::menuQueue = graphics::menuHandler::ValkyrieWardriveSettingsMenu;
            screen->runNow();
            return;
        }
        if (selected == OptPhone) {
            p.wardrivePhoneNotify = !p.wardrivePhoneNotify;
            p.save();
            if (wardriveSession)
                wardriveSession->reloadPrefs(p);
            graphics::menuHandler::menuQueue = graphics::menuHandler::ValkyrieWardriveSettingsMenu;
            screen->runNow();
            return;
        }
        if (selected == OptPeriod) {
            graphics::menuHandler::menuQueue = graphics::menuHandler::ValkyrieWardriveScanPeriodMenu;
            screen->runNow();
            return;
        }
    };
    screen->showOverlayBanner(banner);
}

} // namespace valkyrie

#endif
