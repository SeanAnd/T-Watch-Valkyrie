#pragma once

#include "configuration.h"

#if defined(ARCH_ESP32) && defined(VALKYRIE_FORK)

#include "input/InputBroker.h"

namespace valkyrie
{

/// Heartbeat input gate: called from InputBroker before other observers; also safe if unused elsewhere.
bool handleHeartbeatScreenInput(const InputEvent *event);

void setHeartbeatAlertUiActive(bool active);

/// Set by input handler; consumed by heartbeat draw frame to begin outro.
void requestHeartbeatUiExit();
bool consumeHeartbeatUiExitTap();

} // namespace valkyrie

#endif
