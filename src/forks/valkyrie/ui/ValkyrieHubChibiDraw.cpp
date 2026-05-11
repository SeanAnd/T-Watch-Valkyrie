#include "configuration.h"
#include "ValkyrieHubChibiDraw.h"

#if defined(ARCH_ESP32) && defined(VALKYRIE_FORK)

#include "modules/BleThreatDetectorModule.h"
#include "../modules/HubThreatAnimTiming.h"
#include "graphics/Screen.h"
#include "graphics/SharedUIDisplay.h"
#include "sprites/idle_rgb565.h"
#include "sprites/scan_ble_loop_rgb565.h"
#include "sprites/scan_wifi_loop_rgb565.h"
#include "sprites/start_ble_scan_rgb565.h"
#include "sprites/start_wifi_scan_rgb565.h"
#include "sprites/start_sleep_loop_rgb565.h"
#include "sprites/start_sleep_rgb565.h"

namespace
{

constexpr unsigned kBleStartFrameCount = 6;
constexpr unsigned kLoopFrameCount = 3;
constexpr uint32_t kFrameMsIntro = 160;
constexpr uint32_t kFrameMsLoop = 80;
constexpr uint32_t kIntroTotalMs = valkyrie::kHubBleScanStripOutroMs;
constexpr uint32_t kOutroTotalMs = valkyrie::kHubBleScanStripOutroMs;

static const uint16_t *const kStartBleScanFrames[kBleStartFrameCount] = {
    idle_rgb565,
    startBleScan1_rgb565,
    startBleScan2_rgb565,
    startBleScan3_rgb565,
    startBleScan4_rgb565,
    startBleScan5_rgb565,
};

static const uint16_t *const kHubIdlePose = kStartBleScanFrames[0];

static const uint16_t *const kScanBleLoopFrames[kLoopFrameCount] = {
    scanBleLoop1_rgb565,
    scanBleLoop2_rgb565,
    scanBleLoop3_rgb565,
};

static const uint16_t *const kStartWifiScanFrames[kBleStartFrameCount] = {
    kHubIdlePose,
    startWifiScan1_rgb565,
    startWifiScan2_rgb565,
    startWifiScan3_rgb565,
    startWifiScan4_rgb565,
    startWifiScan5_rgb565,
};

static const uint16_t *const kScanWifiLoopFrames[kLoopFrameCount] = {
    scanWifiLoop1_rgb565,
    scanWifiLoop2_rgb565,
    scanWifiLoop3_rgb565,
};

constexpr unsigned kSleepStartFrameCount = 6;
constexpr unsigned kSleepLoopFrameCount = 3;
constexpr uint32_t kFrameMsSleepIntro = 160;
constexpr uint32_t kFrameMsSleepLoop = 80;
constexpr uint32_t kSleepIntroTotalMs = kSleepStartFrameCount * kFrameMsSleepIntro;
constexpr uint32_t kWakeReverseTotalMs = kSleepStartFrameCount * kFrameMsSleepIntro;

static const uint16_t *const kStartSleepFrames[kSleepStartFrameCount] = {
    kHubIdlePose,
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
constexpr uint16_t kDestW = kAssetW * 3 / 2;
constexpr uint16_t kDestH = kAssetH * 3 / 2;

static void drawRgb565SpriteHubScaledTo(OLEDDisplay *display, int16_t originX, int16_t originY, const uint16_t *pixels,
                                        uint16_t destW, uint16_t destH)
{
    if (destW == 0 || destH == 0)
        return;
    for (uint16_t drow = 0; drow < destH; drow++) {
        const uint16_t srow = (uint16_t)(((uint32_t)drow * kAssetH) / destH);
        for (uint16_t dcol = 0; dcol < destW; dcol++) {
            const uint16_t scol = (uint16_t)(((uint32_t)dcol * kAssetW) / destW);
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

static void drawRgb565SpriteHubScaled(OLEDDisplay *display, int16_t originX, int16_t originY, const uint16_t *pixels)
{
    drawRgb565SpriteHubScaledTo(display, originX, originY, pixels, kDestW, kDestH);
}

static const uint16_t *pickHubChibiPixels(const valkyrie::BleThreatDetectorModule *det)
{
    if (!det)
        return kHubIdlePose;

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
            if (fi >= kBleStartFrameCount)
                fi = kBleStartFrameCount - 1;
            return kStartBleScanFrames[fi];
        }
        const uint32_t t2 = tBle - kIntroTotalMs;
        const uint32_t loopPeriod = kLoopFrameCount * kFrameMsLoop;
        unsigned fi = (unsigned)((t2 % loopPeriod) / kFrameMsLoop);
        if (fi >= kLoopFrameCount)
            fi = kLoopFrameCount - 1;
        return kScanBleLoopFrames[fi];
    }

    if (det->isWifiThreatPassActive()) {
        const uint32_t bleEnd = det->getHubBleWindowEndMs();
        const uint32_t tw = bleEnd ? (now - bleEnd) : 0;
        if (tw < kOutroTotalMs) {
            unsigned seg = (unsigned)(tw / kFrameMsIntro);
            if (seg >= kBleStartFrameCount)
                seg = kBleStartFrameCount - 1;
            const unsigned revIdx = (kBleStartFrameCount - 1) - seg;
            return kStartBleScanFrames[revIdx];
        }
        const uint32_t tAfterBleOutro = tw - kOutroTotalMs;
        if (tAfterBleOutro < kIntroTotalMs) {
            unsigned fi = (unsigned)(tAfterBleOutro / kFrameMsIntro);
            if (fi >= kBleStartFrameCount)
                fi = kBleStartFrameCount - 1;
            return kStartWifiScanFrames[fi];
        }
        const uint32_t tLoop = tAfterBleOutro - kIntroTotalMs;
        const uint32_t loopPeriod = kLoopFrameCount * kFrameMsLoop;
        unsigned fi = (unsigned)((tLoop % loopPeriod) / kFrameMsLoop);
        if (fi >= kLoopFrameCount)
            fi = kLoopFrameCount - 1;
        return kScanWifiLoopFrames[fi];
    }

    const uint32_t passEnd = det->getLastScanWindowEndMs();
    if (passEnd == 0)
        return kHubIdlePose;

    const uint32_t te = now - passEnd;
    const uint32_t bleEnd = det->getHubBleWindowEndMs();
    const uint32_t passWifiSpan = (passEnd > bleEnd) ? (passEnd - bleEnd) : 0;
    constexpr uint32_t kWifiPhaseSkipThresholdMs = 80;
    const bool wifiPhaseRanLong = passWifiSpan > kWifiPhaseSkipThresholdMs;

    if (!wifiPhaseRanLong) {
        if (te < kOutroTotalMs) {
            unsigned seg = (unsigned)(te / kFrameMsIntro);
            if (seg >= kBleStartFrameCount)
                seg = kBleStartFrameCount - 1;
            const unsigned revIdx = (kBleStartFrameCount - 1) - seg;
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

    if (te < kOutroTotalMs) {
        unsigned seg = (unsigned)(te / kFrameMsIntro);
        if (seg >= kBleStartFrameCount)
            seg = kBleStartFrameCount - 1;
        const unsigned revIdx = (kBleStartFrameCount - 1) - seg;
        return kStartWifiScanFrames[revIdx];
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

namespace valkyrie
{

uint16_t hubChibiDestWidth()
{
    return kDestW;
}

uint16_t hubChibiDestHeight()
{
    return kDestH;
}

uint16_t hubChibiClockCompactWidth()
{
    return (uint16_t)((hubChibiDestWidth() * 3 + 2) / 5);
}

uint16_t hubChibiClockCompactHeight()
{
    return (uint16_t)((hubChibiDestHeight() * 3 + 2) / 5);
}

void drawHubChibiClockCompact(OLEDDisplay *display, int16_t originX, int16_t originY, const BleThreatDetectorModule *det)
{
    const uint16_t dw = hubChibiClockCompactWidth();
    const uint16_t dh = hubChibiClockCompactHeight();
    drawRgb565SpriteHubScaledTo(display, originX, originY, pickHubChibiPixels(det), dw, dh);
}

int16_t hubStatusRowTextTopY(OLEDDisplay *display)
{
    const int *tp = graphics::getTextPositions(display);
    constexpr int16_t kHubSpriteNudgeUp = 16;
    int16_t spriteTop = (int16_t)tp[1] - kHubSpriteNudgeUp;
    if (spriteTop < 0)
        spriteTop = 0;
    const int hubSpriteBottom = (int)spriteTop + (int)hubChibiDestHeight();
    constexpr int kTextBelowSpriteGap = 4;
    const int yIdeal = hubSpriteBottom + kTextBelowSpriteGap;
    const int lineStep = tp[2] - tp[1];
    const int screenH = (int)display->getHeight();
    const int bottomNavReserve =
        (graphics::currentResolution == graphics::ScreenResolution::High) ? 52 : 34;
    const int approxLastLineBottom = yIdeal + 3 * lineStep + lineStep;
    const int ySafeTopMax = screenH - bottomNavReserve - 3 * lineStep - lineStep;
    int yLine0 = yIdeal;
    if (approxLastLineBottom > screenH - bottomNavReserve && ySafeTopMax >= hubSpriteBottom + kTextBelowSpriteGap) {
        yLine0 = ySafeTopMax;
    }
    return (int16_t)(yLine0 + 3 * lineStep);
}

void drawHubChibi(OLEDDisplay *display, int16_t originX, int16_t originY, const BleThreatDetectorModule *det)
{
    drawRgb565SpriteHubScaled(display, originX, originY, pickHubChibiPixels(det));
}

} // namespace valkyrie

#endif
