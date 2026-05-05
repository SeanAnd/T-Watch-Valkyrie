#pragma once

#include "configuration.h"

#if defined(ARCH_ESP32) && defined(VALKYRIE_FORK)

namespace valkyrie
{

void startHeartbeatFeedback();
void stopHeartbeatFeedback();

} // namespace valkyrie

#endif
