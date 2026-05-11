#pragma once

#if defined(ARCH_ESP32) && defined(VALKYRIE_FORK)

#include "configuration.h"
#include <OLEDDisplay.h>
#include <cstdint>

namespace valkyrie
{

/// Segmented time + am/pm + seconds (stock layout). Call before `drawCommonFooter`.
void drawValkyrieDigitalClockFace(OLEDDisplay *display, int16_t x, int16_t y, const char *timeString,
                                 const char *secondString, bool use12hClock, bool isPM, int hourForLayout);

/// Compact hub chibi just above the real bottom icon strip. Call after `drawCommonFooter` so the API
/// footer bar does not paint over the sprite.
void drawValkyrieDigitalClockChibiOverlay(OLEDDisplay *display, int16_t x, int16_t y);

} // namespace valkyrie

#endif
