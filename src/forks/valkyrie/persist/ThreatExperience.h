#pragma once

#include <stdint.h>

namespace valkyrie
{

/// Cumulative XP for distinct logged threats (`ThreatLog` upserts: one XP award per MAC+type
/// lifetime until the clear action). Stored in NVS; values scale with rarity (see ThreatExperience.cpp).
namespace ThreatExperience
{

/// Current level (1-based) and XP toward the next level; each tier needs more total XP than the last.
struct LevelProgress {
    unsigned level;
    uint32_t xpTowardNext;
    uint32_t xpNeededThisLevel;
};

/// Map lifetime `totalXp` to level + fraction toward next (for HUD `Exp: cur / need`).
LevelProgress levelProgress(uint32_t totalXp);

/// Total accumulated experience (readable from UI). Runs one-time backfill from `threats.log` after upgrade.
uint32_t totalPoints();

/// Call when `ThreatLog::append` records a genuinely new `(type wire token, MAC)` row (append path —
/// not rewrite-in-place renewals).
void onDistinctThreatLogged(const char *threatWireTypeToken);

/// Call when `/valkyrie/threats.log` is wiped so HUD stays coherent.
void onThreatLogCleared();

/// Called from `WardriveSession::end` (via the summary menu) once per session. Awards XP using
/// the same hub-HUD `levelProgress()` curve as threat-log XP:
///   * 2 XP per distinct BSSID (capped at 256 distinct so a single very long drive can't outrun
///     years of normal threat XP);
///   * 1 XP per 100 m of validated movement (haversine, time-gated upstream);
///   * 10 XP per threat classifier hit during the drive (in addition to the per-row `onDistinctThreatLogged`
///     XP those threats also earn via the normal `emitWifiThreat` path).
/// Returns the delta added so the UI can show "+N XP" in the summary banner.
/// NVS-wear-safe: at most one write per session (the function exits early when delta is 0).
uint32_t onWardriveSessionEnded(uint32_t distinctAps, uint32_t distanceMeters, uint32_t threatHits);

} // namespace ThreatExperience

} // namespace valkyrie
