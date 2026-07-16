#include "configuration.h"
#include "ValkyrieWardriveFrame.h"

#if defined(ARCH_ESP32) && defined(VALKYRIE_FORK)

#include "../modules/WardriveSession.h"
#include "ValkyrieFork.h"
#include "ValkyrieWardriveInput.h"
#include "graphics/Screen.h"
#include "graphics/SharedUIDisplay.h"
#if defined(VALKYRIE_TFT_RGB565)
#include "graphics/TFTDisplay.h"
#endif
#include "graphics/draw/MenuHandler.h"
#include <OLEDDisplay.h>
#include <OLEDDisplayUi.h>
#include "sprites/start_wardrive_rgb565.h"
#include "sprites/wardrive_idle_rgb565.h"
#include "sprites/wardrive_loop_rgb565.h"

namespace valkyrie
{

namespace
{

constexpr unsigned kIntroFrameCount = 5;
constexpr uint32_t kIntroFrameMs = 360;
/// Intro advances one cel per redraw when due so long gaps between paints never skip frames.
constexpr uint32_t kIdleHoldMs = 1500;
/// Held before start sequence (wardriveIdle.png).

constexpr unsigned kLoopFrameCount = 3;

constexpr uint16_t kAssetW = WARDRIVE_LOOP_WIDTH;
constexpr uint16_t kAssetH = WARDRIVE_LOOP_HEIGHT;
// Slightly smaller than 1:1 — wardrive screen needs vertical room for five info lines.
constexpr uint16_t kDestW = kAssetW * 5 / 4;
constexpr uint16_t kDestH = kAssetH * 5 / 4;

static const uint16_t *const kStartFrames[kIntroFrameCount] = {
    startWardrive1_rgb565, startWardrive2_rgb565, startWardrive3_rgb565, startWardrive4_rgb565,
    startWardrive5_rgb565,
};

static const uint16_t *const kLoopFrames[kLoopFrameCount] = {
    wardriveLoop1_rgb565,
    wardriveLoop2_rgb565,
    wardriveLoop3_rgb565,
};

enum class UiPhase : uint8_t { Idle, Intro, Steady, Dead };

UiPhase s_phase = UiPhase::Dead;
uint32_t s_phaseAnchorMs = 0;
uint32_t s_steadyAnimMs = 0;
unsigned s_introFrameIndex = 0;
uint32_t s_introNextAdvanceMs = 0;
WardriveStats s_finalStats{};
bool s_finalStatsCaptured = false;

void drawRgb565SpriteScaled(OLEDDisplay *display, int16_t originX, int16_t originY, const uint16_t *pixels)
{
#if defined(VALKYRIE_TFT_RGB565)
    static_cast<TFTDisplay *>(display)->drawRGB565Sprite(originX, originY, pixels, kAssetW, kAssetH, kDestW, kDestH);
#else
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
#endif
}

static void finishWardriveUiExit()
{
    setWardriveAlertUiActive(false);
    s_phase = UiPhase::Dead;

    // Capture stats before tearing the session down so the summary banner can read them.
    if (wardriveSession) {
        s_finalStats = wardriveSession->stats();
        s_finalStatsCaptured = true;
        wardriveSession->end(/*aborted=*/false);
    }

    if (screen)
        screen->endAlert();
    if (screen)
        screen->runNow();

    // Hand off to the summary menu (queued so it appears after STOP_ALERT drains).
    graphics::menuHandler::menuQueue = graphics::menuHandler::ValkyrieWardriveSummary;
    if (screen)
        screen->runNow();
    if (screen)
        screen->queueSwitchToValkyrieHubFrame();
}

static const uint16_t *pickPixels(uint32_t nowMs)
{
    if (consumeWardriveUiExitTap()) {
        if (s_phase == UiPhase::Idle || s_phase == UiPhase::Intro || s_phase == UiPhase::Steady) {
            finishWardriveUiExit();
            return kLoopFrames[0];
        }
    }

    UiPhase ph = s_phase;
    uint32_t inPhase = nowMs - s_phaseAnchorMs;

    if (ph == UiPhase::Idle) {
        if (inPhase >= kIdleHoldMs) {
            s_phase = UiPhase::Intro;
            const uint32_t t = nowMs;
            s_phaseAnchorMs = t;
            s_introFrameIndex = 0;
            s_introNextAdvanceMs = t + kIntroFrameMs;
        } else {
            return wardriveIdle_rgb565;
        }
    }

    ph = s_phase;
    inPhase = nowMs - s_phaseAnchorMs;

    if (ph == UiPhase::Intro) {
        // At most one advance per paint so every intro cel is shown even when millis() jumps.
        if ((int32_t)(nowMs - s_introNextAdvanceMs) >= 0) {
            if (s_introFrameIndex + 1U >= kIntroFrameCount) {
                s_phase = UiPhase::Steady;
                s_phaseAnchorMs = nowMs;
                s_steadyAnimMs = nowMs;
                ph = UiPhase::Steady;
            } else {
                s_introFrameIndex++;
                s_introNextAdvanceMs += kIntroFrameMs;
            }
        }
        if (ph == UiPhase::Intro)
            return kStartFrames[s_introFrameIndex];
    }

    if (ph != UiPhase::Steady) {
        return kLoopFrames[0];
    }

    // Cycle all wardrive loop frames; speed up slightly once scans produce APs.
    uint32_t raw = wardriveSession ? wardriveSession->stats().apsSeenTotalRaw : 0;
    uint32_t frameMs = 390;
    if (raw > 0)
        frameMs = 270;
    if (raw > 20)
        frameMs = 180;

    const uint32_t t = (nowMs - s_steadyAnimMs) / frameMs;
    const unsigned idx = (unsigned)(t % kLoopFrameCount);
    return kLoopFrames[idx];
}

} // namespace

void resetWardriveFrameState()
{
    s_phase = UiPhase::Idle;
    const uint32_t m = millis();
    s_phaseAnchorMs = m;
    s_steadyAnimMs = m;
    s_introFrameIndex = 0;
    s_introNextAdvanceMs = m;
    s_finalStatsCaptured = false;
    s_finalStats = WardriveStats{};
}

const WardriveStats &getFinalWardriveStats()
{
    return s_finalStats;
}

bool hasFinalWardriveStats()
{
    return s_finalStatsCaptured;
}

void drawWardriveFrame(OLEDDisplay *display, OLEDDisplayUiState *state, int16_t x, int16_t y)
{
    (void)state;
    if (s_phase == UiPhase::Dead)
        return;

    const uint32_t now = millis();

    // Snapshot stats before pickPixels(), which may call finishWardriveUiExit() on tap.
    WardriveStats snap{};
    if (wardriveSession)
        snap = wardriveSession->stats();

    const uint16_t *pix = pickPixels(now);
    if (s_phase == UiPhase::Dead)
        return;

    display->clear();
    display->setTextAlignment(TEXT_ALIGN_LEFT);
    display->setFont(FONT_SMALL);

    graphics::drawCommonHeader(display, x, y, "Wardrive");

    const int *tp = graphics::getTextPositions(display);
    constexpr int16_t kSpriteNudgeUp = 8;
    int16_t spriteTop = (int16_t)tp[1] - kSpriteNudgeUp;
    if (spriteTop < 0)
        spriteTop = 0;
    const int16_t contentW = (int16_t)display->getWidth();
    const int16_t spriteLeft = x + (contentW - (int16_t)kDestW) / 2;
    drawRgb565SpriteScaled(display, spriteLeft, spriteTop, pix);

    char apsLine[40];
    char distLine[40];
    char fixLine[48];
    char threatLine[40];

    snprintf(apsLine, sizeof(apsLine), "APs: %u", (unsigned)snap.apsLoggedDistinct);
    snprintf(distLine, sizeof(distLine), "Dist: %um", (unsigned)snap.distanceMeters);

    bool fixInverse = false;
    if (wardriveSession)
        wardriveSession->formatFixStatusLine(fixLine, sizeof(fixLine), &fixInverse);
    else
        snprintf(fixLine, sizeof(fixLine), "Fix: None");

    snprintf(threatLine, sizeof(threatLine), "Threats: %u", (unsigned)snap.threatsHit);

    const int lineStep = tp[2] - tp[1];
    const int spriteBottom = (int)spriteTop + (int)kDestH;
    constexpr int kGap = 2;
    int yText = spriteBottom + kGap;
    const int16_t textCenterX = x + contentW / 2;
    display->setTextAlignment(TEXT_ALIGN_CENTER);
    display->drawString(textCenterX, (int16_t)yText, apsLine);
    display->drawString(textCenterX, (int16_t)(yText + lineStep), distLine);
    if (fixInverse) {
        display->setColor(INVERSE);
        display->drawString(textCenterX, (int16_t)(yText + 2 * lineStep), fixLine);
        display->setColor(WHITE);
    } else {
        display->drawString(textCenterX, (int16_t)(yText + 2 * lineStep), fixLine);
    }
    display->drawString(textCenterX, (int16_t)(yText + 3 * lineStep), threatLine);
    display->drawString(textCenterX, (int16_t)(yText + 4 * lineStep), "Tap to stop");
    display->setTextAlignment(TEXT_ALIGN_LEFT);

    graphics::drawCommonFooter(display, x, y);
}

} // namespace valkyrie

#endif
