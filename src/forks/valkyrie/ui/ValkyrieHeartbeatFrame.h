#pragma once

#include "configuration.h"

#if defined(ARCH_ESP32) && defined(VALKYRIE_FORK)

#include <OLEDDisplay.h>
#include <OLEDDisplayUi.h>

namespace valkyrie
{

void resetHeartbeatAlertUiState();
void drawHeartbeatFrame(OLEDDisplay *display, OLEDDisplayUiState *state, int16_t x, int16_t y);

} // namespace valkyrie

#endif
