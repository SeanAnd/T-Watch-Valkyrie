#pragma once

#include "configuration.h"

#if defined(ARCH_ESP32) && defined(VALKYRIE_FORK)

#include <stdint.h>

class BleThreatDetectorModule;

namespace valkyrie
{

/// Start a chunked Wi‑Fi promiscuous pass (returns immediately). Returns false if prefs skip Wi‑Fi or alloc fails.
bool beginWifiThreatPass(BleThreatDetectorModule *mod);

/// Advance the pass by one scheduler tick. Returns true when the pass has fully finished (success, error, or abort).
bool tickWifiThreatPass(BleThreatDetectorModule *mod);

/// Tear down radio state if a pass was in progress (sleep / heartbeat handoff).
void abortWifiThreatPass();

/// Wi‑Fi heartbeat hunt: stay in promiscuous mode forever (no time budget) and call
/// `mod->onWifiHeartbeatFrame(...)` only when a frame's source MAC matches `targetMac`.
/// `lockChannel` of 1/6/11 stays parked on that channel; 0 falls back to hopping 1/6/11
/// at `prefs.wifiThreatChannelDwellMs`. Returns false if a duty pass is already in flight
/// or the radio path is unavailable.
bool beginWifiHeartbeat(BleThreatDetectorModule *mod, const uint8_t targetMac[6], uint8_t lockChannel);

/// Advance the heartbeat state machine. Always returns false (heartbeat runs until ended).
bool tickWifiHeartbeat(BleThreatDetectorModule *mod);

/// Stop the heartbeat hunt and power the modem down (driver kept alive per the cold/hot policy).
void endWifiHeartbeat();

/// True while heartbeat hunt is using the Wi‑Fi radio (independent of the duty pass machine).
bool isWifiHeartbeatActive();

} // namespace valkyrie

#endif
