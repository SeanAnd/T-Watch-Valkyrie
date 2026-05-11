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

} // namespace ThreatExperience

} // namespace valkyrie
