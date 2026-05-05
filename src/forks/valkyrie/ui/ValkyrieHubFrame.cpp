#include "ValkyrieHubFrame.h"

#include "configuration.h"

#if defined(ARCH_ESP32) && defined(VALKYRIE_FORK)

#include "ValkyrieFork.h"
#include "main.h"
#include "modules/BleThreatDetectorModule.h"
#include "persist/ThreatLog.h"
#include "prefs/ValkyriePrefs.h"
#include "graphics/SharedUIDisplay.h"
#include "sprites/idle_rgb565.h"
#include "sprites/scan_ble_loop_rgb565.h"
#include "sprites/start_ble_scan_rgb565.h"
#include "sprites/start_sleep_loop_rgb565.h"
#include "sprites/start_sleep_rgb565.h"

#include <cstdio>

namespace valkyrie
{

namespace
{

constexpr unsigned kStartFrameCount = 5;
constexpr unsigned kLoopFrameCount = 3;
/// Per-frame hold for BLE start/outro clips only (loops use kFrameMsLoop).
constexpr uint32_t kFrameMsIntro = 120;
constexpr uint32_t kFrameMsLoop = 80;
constexpr uint32_t kIntroTotalMs = kStartFrameCount * kFrameMsIntro;
constexpr uint32_t kOutroTotalMs = kStartFrameCount * kFrameMsIntro;

static const uint16_t *const kStartBleScanFrames[kStartFrameCount] = {
    startBleScan1_rgb565,
    startBleScan2_rgb565,
    startBleScan3_rgb565,
    startBleScan4_rgb565,
    startBleScan5_rgb565,
};

static const uint16_t *const kScanBleLoopFrames[kLoopFrameCount] = {
    scanBleLoop1_rgb565,
    scanBleLoop2_rgb565,
    scanBleLoop3_rgb565,
};

constexpr unsigned kSleepStartFrameCount = 5;
constexpr unsigned kSleepLoopFrameCount = 3;
/// Per-frame hold for sleep start / wake reverse only (loops use kFrameMsSleepLoop).
constexpr uint32_t kFrameMsSleepIntro = 120;
constexpr uint32_t kFrameMsSleepLoop = 80;
constexpr uint32_t kSleepIntroTotalMs = kSleepStartFrameCount * kFrameMsSleepIntro;
constexpr uint32_t kWakeReverseTotalMs = kSleepStartFrameCount * kFrameMsSleepIntro;

static const uint16_t *const kStartSleepFrames[kSleepStartFrameCount] = {
    startSleep1_rgb565,
    startSleep2_rgb565,
    startSleep3_rgb565,
    startSleep4_rgb565,
    startSleep5_rgb565,
};

static const uint16_t *const kStartSleepLoopFrames[kSleepLoopFrameCount] = {
    startSleepLoop1_rgb565,
    startSleepLoop2_rgb565,
    startSleepLoop3_rgb565,
};

constexpr uint16_t kAssetW = IDLE_WIDTH;
constexpr uint16_t kAssetH = IDLE_HEIGHT;
/// Hub chibi drawn 150% (nearest-neighbor) so 88×88 assets occupy 132×132 on screen.
constexpr uint16_t kDestW = kAssetW * 3 / 2;
constexpr uint16_t kDestH = kAssetH * 3 / 2;

/// TFT path uses a 1-bit buffer; map RGB565 art to lit pixels (0x0000 = transparent).
void drawRgb565SpriteHubScaled(OLEDDisplay *display, int16_t originX, int16_t originY, const uint16_t *pixels)
{
    for (uint16_t drow = 0; drow < kDestH; drow++) {
        const uint16_t srow = (uint16_t)(((uint32_t)drow * kAssetH) / kDestH);
        for (uint16_t dcol = 0; dcol < kDestW; dcol++) {
            const uint16_t scol = (uint16_t)(((uint32_t)dcol * kAssetW) / kDestW);
            uint16_t p = pixels[(uint32_t)srow * kAssetW + scol];
            if (p == 0)
                continue;
            uint16_t r = (p >> 11) << 3;
            uint16_t g = ((p >> 5) & 0x3F) << 2;
            uint16_t b = (p & 0x1F) << 3;
            unsigned y = (r * 299U + g * 587U + b * 114U) / 1000U;
            if (y < 28U)
                continue;
            display->setColor(WHITE);
            display->setPixel(originX + (int16_t)dcol, originY + (int16_t)drow);
        }
    }
}

const uint16_t *pickHubChibiPixels(const BleThreatDetectorModule *det)
{
    if (!det)
        return idle_rgb565;

    const uint32_t now = millis();

    if (det->isScanActive()) {
        const uint32_t tw = now - det->getScanStartedMs();
        if (tw < kWakeReverseTotalMs) {
            unsigned seg = (unsigned)(tw / kFrameMsSleepIntro);
            if (seg >= kSleepStartFrameCount)
                seg = kSleepStartFrameCount - 1;
            const unsigned revIdx = (kSleepStartFrameCount - 1) - seg;
            return kStartSleepFrames[revIdx];
        }
        const uint32_t tBle = tw - kWakeReverseTotalMs;
        if (tBle < kIntroTotalMs) {
            unsigned fi = (unsigned)(tBle / kFrameMsIntro);
            if (fi >= kStartFrameCount)
                fi = kStartFrameCount - 1;
            return kStartBleScanFrames[fi];
        }
        const uint32_t t2 = tBle - kIntroTotalMs;
        const uint32_t loopPeriod = kLoopFrameCount * kFrameMsLoop;
        unsigned fi = (unsigned)((t2 % loopPeriod) / kFrameMsLoop);
        if (fi >= kLoopFrameCount)
            fi = kLoopFrameCount - 1;
        return kScanBleLoopFrames[fi];
    }

    const uint32_t lastEnd = det->getLastScanWindowEndMs();
    if (lastEnd == 0)
        return idle_rgb565;

    const uint32_t te = now - lastEnd;
    if (te < kOutroTotalMs) {
        unsigned seg = (unsigned)(te / kFrameMsIntro);
        if (seg >= kStartFrameCount)
            seg = kStartFrameCount - 1;
        const unsigned revIdx = (kStartFrameCount - 1) - seg;
        return kStartBleScanFrames[revIdx];
    }

    const uint32_t tSleep = te - kOutroTotalMs;
    if (tSleep < kSleepIntroTotalMs) {
        unsigned fi = (unsigned)(tSleep / kFrameMsSleepIntro);
        if (fi >= kSleepStartFrameCount)
            fi = kSleepStartFrameCount - 1;
        return kStartSleepFrames[fi];
    }

    const uint32_t tLoop = tSleep - kSleepIntroTotalMs;
    const uint32_t sleepLoopPeriod = kSleepLoopFrameCount * kFrameMsSleepLoop;
    unsigned fi = (unsigned)((tLoop % sleepLoopPeriod) / kFrameMsSleepLoop);
    if (fi >= kSleepLoopFrameCount)
        fi = kSleepLoopFrameCount - 1;
    return kStartSleepLoopFrames[fi];
}

} // namespace

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
    // Pull chibi up slightly so the block under it clears the bottom nav strip.
    constexpr int16_t kHubSpriteNudgeUp = 16;
    int16_t spriteTop = (int16_t)tp[1] - kHubSpriteNudgeUp;
    if (spriteTop < 0)
        spriteTop = 0;
    drawRgb565SpriteHubScaled(display, x + spritePadX, spriteTop, pickHubChibiPixels(bleThreatDetector));

    ValkyriePrefs prefs = ValkyriePrefs::load();
    char line0[64], line1[64], line2[64], line3[64];

    snprintf(line0, sizeof(line0), "Detection: %s", prefs.bleThreatDetectorEnabled ? "On" : "Off");
    snprintf(line1, sizeof(line1), "Scan Mode: %s", prefs.constantBleScanMode ? "Constant" : "Interval");
    unsigned threatLines = (unsigned)ThreatLog::lineCount();
    snprintf(line2, sizeof(line2), "Threats: %u", threatLines);

    if (bleThreatDetector) {
        snprintf(line3, sizeof(line3), "Status: %s", bleThreatDetector->isScanActive() ? "Scanning" : "Sleeping");
    } else if (!prefs.bleThreatDetectorEnabled) {
        snprintf(line3, sizeof(line3), "Turn on in Settings");
    } else {
        snprintf(line3, sizeof(line3), "Detection: unavailable");
    }

    const char *lines[4] = {line0, line1, line2, line3};
    const int lineStep = tp[2] - tp[1];
    // Top-anchored block under the sprite (room for future level/exp). Avoid bottom-anchoring +
    // minYLast — that pinned the block low and ignored footer reserve.
    constexpr int kTextBelowSpriteGap = 4;
    const int spriteBottom = (int)spriteTop + (int)kDestH;
    const int yIdeal = spriteBottom + kTextBelowSpriteGap;
    const int screenH = (int)display->getHeight();
    // Nav bar + icon chrome (~22px) plus one text line of margin; see UIRenderer::drawNavigationBar.
    const int bottomNavReserve =
        (graphics::currentResolution == graphics::ScreenResolution::High) ? 52 : 34;
    const int approxLastLineBottom = yIdeal + 3 * lineStep + lineStep;
    const int ySafeTopMax = screenH - bottomNavReserve - 3 * lineStep - lineStep;
    int yLine0 = yIdeal;
    if (approxLastLineBottom > screenH - bottomNavReserve && ySafeTopMax >= spriteBottom + kTextBelowSpriteGap) {
        yLine0 = ySafeTopMax;
    }
    for (int j = 0; j < 4; j++) {
        display->drawString(x, (int16_t)(yLine0 + j * lineStep), lines[j]);
    }

    graphics::drawCommonFooter(display, x, y);
}

} // namespace valkyrie

#endif
