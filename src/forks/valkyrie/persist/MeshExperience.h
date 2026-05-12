#pragma once

#include <stdint.h>

namespace valkyrie
{

/// Passive Meshtastic-participation XP, sampled at the 60 s `DeviceTelemetryModule::runOnce()` tick.
/// Reads `RadioLibInterface::instance` + `router` counters directly (same fields used by
/// `getLocalStatsTelemetry()`), computes deltas vs a RAM-only snapshot, and awards weighted XP.
/// Stored in NVS in the same `valkyrie` namespace as `thr_xp` (see `ThreatExperience`).
namespace MeshExperience
{

/// Cumulative passive mesh XP (mesh-only; does not include threat XP).
uint32_t totalPoints();

/// Hook called from upstream `DeviceTelemetryModule::runOnce()` (see firmware/README.md patch table).
/// First call after boot just baselines; subsequent calls credit the delta with the configured weights.
/// A counter going backwards (boot reset) re-baselines without awarding XP.
void onRadioCountersTick();

/// Combined lifetime XP across all sources (`ThreatExperience::totalPoints()` + mesh XP). Drives the
/// unified level shown on the Valkyrie hub HUD.
uint32_t totalCombinedXp();

/// Wipe mesh XP only; threat XP is untouched. Future "reset progress" UI surface.
void resetMeshXp();

} // namespace MeshExperience

} // namespace valkyrie
