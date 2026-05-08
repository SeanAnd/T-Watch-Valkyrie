#pragma once

#include "configuration.h"

#if defined(ARCH_ESP32) && defined(VALKYRIE_FORK)

class BleThreatDetectorModule;

namespace valkyrie
{

/// Start a chunked Wi‑Fi promiscuous pass (returns immediately). Returns false if prefs skip Wi‑Fi or alloc fails.
bool beginWifiThreatPass(BleThreatDetectorModule *mod);

/// Advance the pass by one scheduler tick. Returns true when the pass has fully finished (success, error, or abort).
bool tickWifiThreatPass(BleThreatDetectorModule *mod);

/// Tear down radio state if a pass was in progress (sleep / heartbeat handoff).
void abortWifiThreatPass();

} // namespace valkyrie

#endif
