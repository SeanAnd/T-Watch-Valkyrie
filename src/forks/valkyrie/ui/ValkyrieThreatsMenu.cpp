#include "ValkyrieThreatsMenu.h"

#include "configuration.h"

#if defined(ARCH_ESP32) && defined(VALKYRIE_FORK)

#include "../ThreatTypeUi.h"
#include "../modules/BleClassifier.h"
#include "../modules/BleThreatDetectorModule.h"
#include "prefs/ValkyriePrefs.h"
#include "ValkyrieFork.h"
#include "graphics/Screen.h"
#include "graphics/draw/MenuHandler.h"
#include "main.h"

#include <cstdio>

namespace valkyrie
{

namespace
{

static constexpr ThreatType kThreatOrder[] = {
    ThreatType::Airtag, ThreatType::Flipper, ThreatType::HCSkimmer,
    ThreatType::Flock,  ThreatType::SmartGlasses, ThreatType::Drone,
};

enum opt : int {
    OptBack = 0,
    OptAirtag,
    OptFlipper,
    OptHCSkimmer,
    OptFlock,
    OptSmartGlasses,
    OptDrone,
};

static constexpr size_t kNumThreatTypes = sizeof(kThreatOrder) / sizeof(kThreatOrder[0]);

} // namespace

void showThreatsMenu()
{
    static char labelBuf[kNumThreatTypes][36];
    static const char *labels[1 + kNumThreatTypes];
    static int enums[1 + kNumThreatTypes];

    ValkyriePrefs prefs = ValkyriePrefs::load();

    labels[0] = "Back";
    enums[0] = OptBack;

    for (size_t i = 0; i < kNumThreatTypes; i++) {
        ThreatType tt = kThreatOrder[i];
        snprintf(labelBuf[i], sizeof(labelBuf[i]), "%s: %s", threatTypeMenuLabel(tt),
                 prefs.isThreatTypeEnabled(tt) ? "On" : "Off");
        labels[i + 1] = labelBuf[i];
        enums[i + 1] = OptAirtag + (int)i;
    }

    graphics::BannerOverlayOptions bannerOptions{};
    bannerOptions.message = "Threat types";
    bannerOptions.optionsArrayPtr = labels;
    bannerOptions.optionsEnumPtr = enums;
    bannerOptions.optionsCount = (uint8_t)(1 + kNumThreatTypes);
    bannerOptions.bannerCallback = [](int selected) -> void {
        if (selected == OptBack) {
            graphics::menuHandler::menuQueue = graphics::menuHandler::ValkyrieRootMenu;
            screen->runNow();
            return;
        }
        int ti = selected - OptAirtag;
        if (ti < 0 || ti >= (int)kNumThreatTypes)
            return;

        ValkyriePrefs p = ValkyriePrefs::load();
        ThreatType t = kThreatOrder[(size_t)ti];
        p.setThreatTypeEnabled(t, !p.isThreatTypeEnabled(t));
        p.save();
        if (bleThreatDetector)
            bleThreatDetector->reloadPrefs();

        graphics::menuHandler::menuQueue = graphics::menuHandler::ValkyrieThreatsMenu;
        screen->runNow();
    };
    screen->showOverlayBanner(bannerOptions);
}

} // namespace valkyrie

#endif
