#include "ValkyrieHubFrame.h"

#include "configuration.h"

#if defined(ARCH_ESP32) && defined(VALKYRIE_FORK)

#include "ValkyrieFork.h"
#include "ValkyrieHubChibiDraw.h"
#include "modules/BleThreatDetectorModule.h"
#include "main.h"
#include "persist/MeshExperience.h"
#include "persist/ThreatExperience.h"
#include "persist/ThreatLog.h"
#include "prefs/ValkyriePrefs.h"
#include "graphics/SharedUIDisplay.h"

#include <cstdint>
#include <cstdio>

namespace valkyrie
{

void drawHubFrame(OLEDDisplay *display, OLEDDisplayUiState *state, int16_t x, int16_t y)
{
    (void)state;
    display->clear();
    display->setTextAlignment(TEXT_ALIGN_LEFT);
    display->setFont(FONT_SMALL);

    const char *title = "Valkyrie";
    graphics::drawCommonHeader(display, x, y, title);

    const int *tp = graphics::getTextPositions(display);
    constexpr int16_t spritePadX = 2;
    constexpr int16_t kHubLvlExpPadX = 4;
    // Pull chibi up slightly so the block under it clears the bottom nav strip.
    constexpr int16_t kHubSpriteNudgeUp = 16;
    int16_t spriteTop = (int16_t)tp[1] - kHubSpriteNudgeUp;
    if (spriteTop < 0)
        spriteTop = 0;
    drawHubChibi(display, x + spritePadX, spriteTop, bleThreatDetector);

    const size_t threatLogLines = ThreatLog::lineCount();
    const uint32_t totalExp = MeshExperience::totalCombinedXp();
    const ThreatExperience::LevelProgress prog = ThreatExperience::levelProgress(totalExp);
    char lvlBuf[24], expBuf[24], reqBuf[28];
    snprintf(lvlBuf, sizeof(lvlBuf), "Lvl: %u", prog.level);
    snprintf(expBuf, sizeof(expBuf), "Exp: %lu", (unsigned long)prog.xpTowardNext);
    snprintf(reqBuf, sizeof(reqBuf), "Req: %lu", (unsigned long)prog.xpNeededThisLevel);
    const int lineStepHub = tp[2] - tp[1];
    // Keep stats below the common header — sprite uses spriteTop (nudged above tp[1]) but that
    // overlaps the header bar; align Lvl/exp with the first body line like other frames.
    const int16_t hubStatTop = (int16_t)tp[1];
    const int16_t statX = (int16_t)(x + spritePadX + (int16_t)hubChibiDestWidth() + kHubLvlExpPadX);
    display->drawString(statX, hubStatTop, lvlBuf);
    display->drawString(statX, (int16_t)(hubStatTop + lineStepHub), expBuf);
    display->drawString(statX, (int16_t)(hubStatTop + 2 * lineStepHub), reqBuf);

    ValkyriePrefs prefs = ValkyriePrefs::load();
    char line0[64], line1[64], line2[64], line3[64];

    snprintf(line0, sizeof(line0), "Detection: %s", prefs.bleThreatDetectorEnabled ? "On" : "Off");
    snprintf(line1, sizeof(line1), "Scan Mode: %s", prefs.constantBleScanMode ? "Constant" : "Interval");
    snprintf(line2, sizeof(line2), "Threats: %u", (unsigned)threatLogLines);

    if (bleThreatDetector) {
        const char *status;
        if (bleThreatDetector->isScanActive()) {
            status = "Scanning BLE";
        } else if (bleThreatDetector->isWifiThreatPassActive()) {
            status = "Scanning WiFi";
        } else if (!prefs.bleThreatPhaseEnabled && !prefs.wifiThreatPhaseEnabled) {
            status = "Threat phases off";
        } else if (!prefs.bleThreatPhaseEnabled) {
            status = "BLE phase off";
        } else if (!prefs.wifiThreatPhaseEnabled) {
            status = "WiFi phase off";
        } else if (!prefs.isWifiThreatPassConfigured()) {
            status = "WiFi types off";
        } else {
            status = "Sleeping";
        }
        snprintf(line3, sizeof(line3), "Status: %s", status);
    } else if (!prefs.bleThreatDetectorEnabled) {
        snprintf(line3, sizeof(line3), "Turn on in Settings");
    } else {
        snprintf(line3, sizeof(line3), "Detection: unavailable");
    }

    const char *lines[4] = {line0, line1, line2, line3};
    const int lineStep = tp[2] - tp[1];
    const int16_t statusTop = hubStatusRowTextTopY(display);
    const int yLine0 = (int)statusTop - 3 * lineStep;
    for (int j = 0; j < 4; j++) {
        display->drawString(x, (int16_t)(yLine0 + j * lineStep), lines[j]);
    }

    graphics::drawCommonFooter(display, x, y);
}

} // namespace valkyrie

#endif
