#include "configuration.h"
#include "ValkyrieHeartbeatFrame.h"

#if defined(ARCH_ESP32) && defined(VALKYRIE_FORK)

#include "../HeartbeatSignalTier.h"
#include "../modules/BleThreatDetectorModule.h"
#include "ValkyrieFork.h"
#include "ValkyrieHeartbeatFeedback.h"
#include "ValkyrieHeartbeatInput.h"
#include "ValkyrieThreatLogEntryMenu.h"
#include "graphics/Screen.h"
#include "graphics/SharedUIDisplay.h"
#include "sprites/heartbeat_loop_rgb565.h"
#include "sprites/start_heartbeat_scan_rgb565.h"

#include <cstdio>

namespace valkyrie
{

namespace
{

constexpr unsigned kIntroFrameCount = 5;
constexpr uint32_t kIntroFrameMs = 120;
constexpr uint32_t kIntroTotalMs = kIntroFrameCount * kIntroFrameMs;

constexpr uint16_t kAssetW = HEARTBEAT_LOOP_WIDTH;
constexpr uint16_t kAssetH = HEARTBEAT_LOOP_HEIGHT;
constexpr uint16_t kDestW = kAssetW * 3 / 2;
constexpr uint16_t kDestH = kAssetH * 3 / 2;

static const uint16_t *const kStartFrames[kIntroFrameCount] = {
    startHeartbeatScan1_rgb565,
    startHeartbeatScan2_rgb565,
    startHeartbeatScan3_rgb565,
    startHeartbeatScan4_rgb565,
    startHeartbeatScan5_rgb565,
};

static const uint16_t *const kLoopFrames[6] = {
    heartbeatLoop1_rgb565,
    heartbeatLoop2_rgb565,
    heartbeatLoop3_rgb565,
    heartbeatLoop4_rgb565,
    heartbeatLoop5_rgb565,
    heartbeatLoop6_rgb565,
};

enum class UiPhase : uint8_t { Intro, Steady, Outro, Dead };

UiPhase s_phase = UiPhase::Dead;
uint32_t s_phaseAnchorMs = 0;
uint32_t s_steadyAnimMs = 0;

void drawRgb565SpriteScaled(OLEDDisplay *display, int16_t originX, int16_t originY, const uint16_t *pixels)
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

static void finishHeartbeatUiExit()
{
    stopHeartbeatFeedback();
    setHeartbeatAlertUiActive(false);
    s_phase = UiPhase::Dead;
    screen->endAlert();
    // Drain STOP_ALERT before showThreatLogEntryMenu: setFrames() resets overlays and would wipe the banner.
    if (screen)
        screen->runNow();
    showThreatLogEntryMenu();
    if (bleThreatDetector)
        bleThreatDetector->stopHeartbeat();
    if (screen)
        screen->runNow();
    if (screen)
        screen->switchToValkyrieHubFrame();
}

static const uint16_t *pickPixels(uint32_t nowMs)
{
    if (consumeHeartbeatUiExitTap()) {
        if (s_phase == UiPhase::Intro || s_phase == UiPhase::Steady) {
            s_phase = UiPhase::Outro;
            s_phaseAnchorMs = nowMs;
        }
    }

    UiPhase ph = s_phase;
    uint32_t inPhase = nowMs - s_phaseAnchorMs;

    if (ph == UiPhase::Intro) {
        if (inPhase >= kIntroTotalMs) {
            s_phase = UiPhase::Steady;
            s_phaseAnchorMs = nowMs;
            s_steadyAnimMs = nowMs;
            ph = UiPhase::Steady;
            inPhase = 0;
        } else {
            unsigned fi = (unsigned)(inPhase / kIntroFrameMs);
            if (fi >= kIntroFrameCount)
                fi = kIntroFrameCount - 1;
            return kStartFrames[fi];
        }
    }

    if (ph == UiPhase::Outro) {
        if (inPhase >= kIntroTotalMs) {
            finishHeartbeatUiExit();
            return kLoopFrames[0];
        }
        unsigned seg = (unsigned)(inPhase / kIntroFrameMs);
        if (seg >= kIntroFrameCount)
            seg = kIntroFrameCount - 1;
        const unsigned revIdx = (kIntroFrameCount - 1) - seg;
        return kStartFrames[revIdx];
    }

    if (ph != UiPhase::Steady || !bleThreatDetector) {
        return kLoopFrames[0];
    }

    HeartbeatSignalTier tier = bleThreatDetector->getHeartbeatSignalTier();
    if (tier == HeartbeatSignalTier::None) {
        return kLoopFrames[0];
    }

    unsigned first = 0, last = 5;
    uint32_t frameMs = 110;
    if (tier == HeartbeatSignalTier::Medium) {
        first = 2;
        last = 5;
        frameMs = 85;
    } else if (tier == HeartbeatSignalTier::Strong) {
        first = 4;
        last = 5;
        frameMs = 55;
    }

    const uint32_t span = (uint32_t)(last - first + 1);
    const uint32_t t = (nowMs - s_steadyAnimMs) / frameMs;
    const unsigned idx = (unsigned)(first + (t % span));
    return kLoopFrames[idx];
}

} // namespace

void resetHeartbeatAlertUiState()
{
    s_phase = UiPhase::Intro;
    const uint32_t m = millis();
    s_phaseAnchorMs = m;
    s_steadyAnimMs = m;
}

void drawHeartbeatFrame(OLEDDisplay *display, OLEDDisplayUiState *state, int16_t x, int16_t y)
{
    (void)state;
    if (s_phase == UiPhase::Dead)
        return;

    const uint32_t now = millis();
    // pickPixels() may call finishHeartbeatUiExit() on the last outro frame, which stops BLE and
    // clears seen/RSSI — snapshot before so this frame's text stays consistent.
    const bool snapEverSeen = bleThreatDetector && bleThreatDetector->getHeartbeatEverSeenTarget();
    const int32_t snapRssi = bleThreatDetector ? bleThreatDetector->getHeartbeatSmoothedRssi() : -128;
    const HeartbeatSignalTier snapTier =
        bleThreatDetector ? bleThreatDetector->getHeartbeatSignalTier() : HeartbeatSignalTier::None;

    const uint16_t *pix = pickPixels(now);

    display->clear();
    display->setTextAlignment(TEXT_ALIGN_LEFT);
    display->setFont(FONT_SMALL);

    const char *title = "Heartbeat";
    graphics::drawCommonHeader(display, x, y, title);

    const int *tp = graphics::getTextPositions(display);
    constexpr int16_t kSpriteNudgeUp = 12;
    int16_t spriteTop = (int16_t)tp[1] - kSpriteNudgeUp;
    if (spriteTop < 0)
        spriteTop = 0;
    const int16_t contentW = (int16_t)display->getWidth();
    const int16_t spriteLeft = x + (contentW - (int16_t)kDestW) / 2;
    drawRgb565SpriteScaled(display, spriteLeft, spriteTop, pix);

    char rssiLine[32];
    if (snapEverSeen) {
        snprintf(rssiLine, sizeof(rssiLine), "RSSI: %d dBm", (int)snapRssi);
    } else {
        snprintf(rssiLine, sizeof(rssiLine), "RSSI: --");
    }

    char strengthLine[40];
    snprintf(strengthLine, sizeof(strengthLine), "Signal strength: %s", heartbeatTierLabel(snapTier));

    const int lineStep = tp[2] - tp[1];
    const int spriteBottom = (int)spriteTop + (int)kDestH;
    constexpr int kGap = 4;
    int yText = spriteBottom + kGap;
    const int16_t textCenterX = x + contentW / 2;
    display->setTextAlignment(TEXT_ALIGN_CENTER);
    display->drawString(textCenterX, (int16_t)yText, rssiLine);
    display->drawString(textCenterX, (int16_t)(yText + lineStep), strengthLine);
    display->drawString(textCenterX, (int16_t)(yText + 2 * lineStep), "Tap screen to stop");
    display->setTextAlignment(TEXT_ALIGN_LEFT);

    graphics::drawCommonFooter(display, x, y);
}

} // namespace valkyrie

#endif
