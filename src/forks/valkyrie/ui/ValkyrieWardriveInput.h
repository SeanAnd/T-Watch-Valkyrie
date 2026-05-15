#pragma once

#include "configuration.h"

#if defined(ARCH_ESP32) && defined(VALKYRIE_FORK)

#include "input/InputBroker.h"

namespace valkyrie
{

/// Input gate for the fullscreen wardrive frame. Mirrors heartbeat's pattern:
/// a single short tap exits immediately (session stop), and frame-navigation events are
/// swallowed so the user can't accidentally swipe off the screen mid-drive.
bool handleWardriveScreenInput(const InputEvent *event);

void setWardriveAlertUiActive(bool active);

void requestWardriveUiExit();
bool consumeWardriveUiExitTap();

} // namespace valkyrie

#endif
