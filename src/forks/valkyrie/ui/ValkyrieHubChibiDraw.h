#pragma once

#if defined(ARCH_ESP32) && defined(VALKYRIE_FORK)

#include "configuration.h"
#include <OLEDDisplay.h>
#include <cstdint>

namespace valkyrie
{

class BleThreatDetectorModule;

uint16_t hubChibiDestWidth();
uint16_t hubChibiDestHeight();

/// Smaller chibi for the digital clock (between centered time and bottom bar).
uint16_t hubChibiClockCompactWidth();
uint16_t hubChibiClockCompactHeight();
void drawHubChibiClockCompact(OLEDDisplay *display, int16_t originX, int16_t originY, const BleThreatDetectorModule *det);

/// Top Y passed to drawString for the hub "Status:" row (matches ValkyrieHubFrame layout).
int16_t hubStatusRowTextTopY(OLEDDisplay *display);

void drawHubChibi(OLEDDisplay *display, int16_t originX, int16_t originY, const BleThreatDetectorModule *det);

} // namespace valkyrie

#endif
