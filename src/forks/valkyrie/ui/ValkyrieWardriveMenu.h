#pragma once

#include "configuration.h"

#if defined(ARCH_ESP32) && defined(VALKYRIE_FORK)

namespace valkyrie
{

/// Show a confirmation banner ("Start wardrive?") and, on confirm, begin a session +
/// jump to the wardrive fullscreen frame. Wired into upstream MenuHandler under the
/// `ValkyrieWardriveMenu` enum value (see graphics::menuHandler).
void showWardriveMenu();

/// Show the post-stop summary banner. Reads counters captured by the wardrive frame's
/// outro (see ValkyrieWardriveFrame::getFinalWardriveStats). The banner reports APs /
/// Dist / Threats / XP awarded; the single confirm option returns to the Valkyrie hub.
/// Also dispatches the XP credit via ThreatExperience::onWardriveSessionEnded.
void showWardriveSummaryMenu();

/// Wi-Fi burst spacing picker (`wd_per_ms`). Opened via menu queue so it is not nested inside
/// the notification SELECT handler (which resets the overlay afterward).
void showWardriveScanPeriodMenu();

} // namespace valkyrie

#endif
