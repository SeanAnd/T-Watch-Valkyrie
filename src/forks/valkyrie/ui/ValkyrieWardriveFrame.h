#pragma once

#include "configuration.h"

#if defined(ARCH_ESP32) && defined(VALKYRIE_FORK)

#include <OLEDDisplay.h>
#include <OLEDDisplayUi.h>

namespace valkyrie
{

struct WardriveStats;

/// Reset frame state so the next draw begins idle → start → loop. Call right before startAlert().
void resetWardriveFrameState();

/// Fullscreen wardrive frame: idle art, start sequence, then loop sprites with live session counters
/// (APs / Dist / Fix / Threats / "Tap to stop"). Tap ends the session immediately and brings up the summary menu.
void drawWardriveFrame(OLEDDisplay *display, OLEDDisplayUiState *state, int16_t x, int16_t y);

/// Captured at session-stop time so the summary menu can read the numbers after `wardriveSession`
/// has cleared its internal stats (end() resets them on next begin()).
const WardriveStats &getFinalWardriveStats();
bool hasFinalWardriveStats();

} // namespace valkyrie

#endif
