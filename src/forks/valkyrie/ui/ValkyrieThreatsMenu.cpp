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

static constexpr ThreatType kBleThreatOrder[] = {
    ThreatType::Airtag, ThreatType::Flipper, ThreatType::HCSkimmer,
    ThreatType::Flock,  ThreatType::SmartGlasses, ThreatType::Drone,
};

static constexpr ThreatType kWifiThreatOrder[] = {
    ThreatType::WifiDeauth,      ThreatType::WifiEapol,       ThreatType::WifiPwnagotchi,
    ThreatType::WifiSuspiciousAp, ThreatType::WifiMultiSsid,
};

static constexpr size_t kNumBleThreatTypes = sizeof(kBleThreatOrder) / sizeof(kBleThreatOrder[0]);
static constexpr size_t kNumWifiThreatTypes = sizeof(kWifiThreatOrder) / sizeof(kWifiThreatOrder[0]);
static constexpr size_t kTotalRows = kNumBleThreatTypes + kNumWifiThreatTypes;

enum opt : int {
    OptBack = 0,
    OptFirstThreatRow = 1,
};

} // namespace

void showThreatsMenu()
{
    static char labelBuf[kTotalRows][40];
    static const char *labels[1 + kTotalRows];
    static int enums[1 + kTotalRows];

    ValkyriePrefs prefs = ValkyriePrefs::load();

    labels[0] = "Back";
    enums[0] = OptBack;

    for (size_t i = 0; i < kNumBleThreatTypes; i++) {
        ThreatType tt = kBleThreatOrder[i];
        snprintf(labelBuf[i], sizeof(labelBuf[i]), "%s: %s", threatTypeMenuLabel(tt),
                 prefs.isThreatTypeEnabled(tt) ? "On" : "Off");
        labels[i + 1] = labelBuf[i];
        enums[i + 1] = OptFirstThreatRow + (int)i;
    }

#if HAS_WIFI && !defined(ARCH_PORTDUINO)
    for (size_t i = 0; i < kNumWifiThreatTypes; i++) {
        ThreatType tt = kWifiThreatOrder[i];
        size_t idx = kNumBleThreatTypes + i;
        snprintf(labelBuf[idx], sizeof(labelBuf[idx]), "%s: %s", threatTypeMenuLabel(tt),
                 prefs.isWifiThreatTypeEnabled(tt) ? "On" : "Off");
        labels[idx + 1] = labelBuf[idx];
        enums[idx + 1] = OptFirstThreatRow + (int)idx;
    }
    const size_t menuRows = 1 + kTotalRows;
#else
    const size_t menuRows = 1 + kNumBleThreatTypes;
#endif

    graphics::BannerOverlayOptions bannerOptions{};
    bannerOptions.message = "Threat types";
    bannerOptions.optionsArrayPtr = labels;
    bannerOptions.optionsEnumPtr = enums;
    bannerOptions.optionsCount = (uint8_t)menuRows;
    bannerOptions.bannerCallback = [](int selected) -> void {
        if (selected == OptBack) {
            graphics::menuHandler::menuQueue = graphics::menuHandler::ValkyrieRootMenu;
            screen->runNow();
            return;
        }
        int row = selected - OptFirstThreatRow;
        if (row < 0)
            return;

        ValkyriePrefs p = ValkyriePrefs::load();

#if HAS_WIFI && !defined(ARCH_PORTDUINO)
        if (row < (int)kNumBleThreatTypes) {
            ThreatType t = kBleThreatOrder[(size_t)row];
            const bool wasEnabled = p.isThreatTypeEnabled(t);
            p.setThreatTypeEnabled(t, !wasEnabled);
            if (!wasEnabled && (t == ThreatType::Flock || t == ThreatType::Drone))
                p.wifiThreatPhaseEnabled = true;
        } else if (row < (int)kTotalRows) {
            ThreatType t = kWifiThreatOrder[(size_t)row - kNumBleThreatTypes];
            const bool wasEnabled = p.isWifiThreatTypeEnabled(t);
            p.setWifiThreatTypeEnabled(t, !wasEnabled);
            if (!wasEnabled)
                p.wifiThreatPhaseEnabled = true;
        } else {
            return;
        }
#else
        if (row >= (int)kNumBleThreatTypes)
            return;
        ThreatType t = kBleThreatOrder[(size_t)row];
        p.setThreatTypeEnabled(t, !p.isThreatTypeEnabled(t));
#endif

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
