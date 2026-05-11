#include "ValkyrieDigitalClockLayout.h"

#include "configuration.h"

#if defined(ARCH_ESP32) && defined(VALKYRIE_FORK)

#include "ValkyrieHubChibiDraw.h"
#include "graphics/Screen.h"
#include "graphics/ScreenFonts.h"
#include "graphics/SharedUIDisplay.h"
#include "graphics/draw/ClockRenderer.h"
#include "ValkyrieFork.h"

#include <cstring>

namespace valkyrie
{

namespace
{
// Shared with face + chibi overlay (must match ClockRenderer stock digital path).
static bool scaleInitialized = false;
static float gScale = 0.75f;
static float gSegmentWidth = SEGMENT_WIDTH * 0.75f;
static float gSegmentHeight = SEGMENT_HEIGHT * 0.75f;

static void ensureScaleInitialized(OLEDDisplay *display)
{
    if (scaleInitialized) {
        return;
    }

    float screenwidth_target_ratio = 0.80f;
    float max_scale = 3.5f;
    float step = 0.05f;

    float target_width = display->getWidth() * screenwidth_target_ratio;
    float target_height =
        (float)display->getHeight() -
        (float)((graphics::currentResolution == graphics::ScreenResolution::High) ? 46 : 33);

    float calculated_width_size = 0.0f;
    float calculated_height_size = 0.0f;

    while (true) {
        gSegmentWidth = SEGMENT_WIDTH * gScale;
        gSegmentHeight = SEGMENT_HEIGHT * gScale;

        calculated_width_size = gSegmentHeight + ((gSegmentWidth + (gSegmentHeight * 2) + 4) * 4);
        calculated_height_size = gSegmentHeight + ((gSegmentHeight + (gSegmentHeight * 2) + 4) * 2);

        if (calculated_width_size >= target_width || calculated_height_size >= target_height || gScale >= max_scale) {
            break;
        }

        gScale += step;
    }

    if (calculated_width_size > target_width || calculated_height_size > target_height) {
        gScale -= step;
        gSegmentWidth = SEGMENT_WIDTH * gScale;
        gSegmentHeight = SEGMENT_HEIGHT * gScale;
    }

    scaleInitialized = true;
}

} // namespace

void drawValkyrieDigitalClockFace(OLEDDisplay *display, int16_t x, int16_t y, const char *timeString,
                                 const char *secondString, bool use12hClock, bool isPM, int hourForLayout)
{
    (void)x;
    (void)y;
    ensureScaleInitialized(display);

    const size_t len = strlen(timeString);
    uint16_t timeStringWidth = len * 5;

    for (size_t i = 0; i < len; i++) {
        char character = timeString[i];

        if (character == ':') {
            timeStringWidth += gSegmentHeight;
        } else {
            timeStringWidth += gSegmentWidth + (gSegmentHeight * 2) + 4;
        }
    }

    uint16_t hourMinuteTextX = (display->getWidth() / 2) - (timeStringWidth / 2);
    const uint16_t startingHourMinuteTextX = hourMinuteTextX;

    const uint16_t hourMinuteTextY =
        (uint16_t)(((int)display->getHeight() / 2) -
                   (int)(((gSegmentWidth * 2) + (gSegmentHeight * 3) + 8) / 2) + 2);

    for (size_t i = 0; i < len; i++) {
        char character = timeString[i];

        if (character == ':') {
            graphics::ClockRenderer::drawSegmentedDisplayColon(display, hourMinuteTextX, hourMinuteTextY, gScale);

            hourMinuteTextX += gSegmentHeight + 6;
            if (gScale >= 2.0f) {
                hourMinuteTextX += (uint16_t)(4.5f * gScale);
            }
        } else {
            graphics::ClockRenderer::drawSegmentedDisplayCharacter(display, hourMinuteTextX, hourMinuteTextY,
                                                                   (uint8_t)(character - '0'), gScale);

            hourMinuteTextX += gSegmentWidth + (gSegmentHeight * 2) + 4;
        }

        hourMinuteTextX += 5;
    }

    display->setFont(FONT_SMALL);
    int xOffset = -1;
    if (graphics::currentResolution == graphics::ScreenResolution::High) {
        xOffset = 0;
    }
    if (hourForLayout >= 10) {
        if (graphics::currentResolution == graphics::ScreenResolution::High) {
            xOffset += 32;
        } else {
            xOffset += 18;
        }
    }

    const int16_t metaY = (int16_t)((display->getHeight() - hourMinuteTextY) - 1);

    if (use12hClock) {
        display->drawString((int16_t)(startingHourMinuteTextX + xOffset), metaY, isPM ? "pm" : "am");
    }

#ifndef USE_EINK
    xOffset = (graphics::currentResolution == graphics::ScreenResolution::High) ? 18 : 10;
    if (gScale >= 2.0f) {
        xOffset -= (int)(4.5f * gScale);
    }
    display->drawString((int16_t)(startingHourMinuteTextX + timeStringWidth - xOffset), metaY, secondString);
#endif
}

void drawValkyrieDigitalClockChibiOverlay(OLEDDisplay *display, int16_t x, int16_t y)
{
    // UIRenderer::drawNavigationBar paints the icon row at `h - iconSize - 1` and the
    // background rect 2px above that, so its top edge sits at `h - iconSize - 3`. We nudge the
    // chibi bottom into that strip for ~1-2px more clearance under the clock; raise
    // kChibiBottomNudgePx if the feet clip.
    constexpr int kChibiBottomNudgePx = 10;

    const int iconSize =
        (graphics::currentResolution == graphics::ScreenResolution::High) ? 16 : 8;
    const int chibiH = (int)hubChibiClockCompactHeight();
    const int spriteBottom = (int)display->getHeight() - iconSize - 3 + kChibiBottomNudgePx;
    int spriteY = spriteBottom - chibiH;
    if (spriteY < 0)
        spriteY = 0;

    const int16_t spriteDrawX =
        (int16_t)(x + ((int)display->getWidth() - (int)hubChibiClockCompactWidth()) / 2);
    drawHubChibiClockCompact(display, spriteDrawX, (int16_t)(y + spriteY), bleThreatDetector);
}

} // namespace valkyrie

#endif
