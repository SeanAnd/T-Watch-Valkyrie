#pragma once

// Single entry point for the Valkyrie fork overlay. Included from
// firmware/src/modules/Modules.cpp when VALKYRIE_FORK is defined (and the
// header is present). Stock PlatformIO envs exclude forks/valkyrie/ from
// compilation via arduino_base.build_src_filter.
//
// Everything fork-specific is reachable from here. Upstream code never
// references any other forks/valkyrie/ symbol.

namespace valkyrie
{

// Called once near the end of setupModules(). Reads ValkyriePrefs from
// the private NVS namespace and instantiates the Valkyrie modules that
// are enabled. Safe to call on any architecture: on non-ESP32 builds
// (or when VALKYRIE_FORK is not defined) this is a stub.
void setupFork();

#if defined(ARCH_ESP32) && defined(VALKYRIE_FORK)
class BleThreatDetectorModule;
extern BleThreatDetectorModule *bleThreatDetector;

class WardriveSession;
/// Wardrive session singleton. Lazily created the first time the menu opens the session
/// (so the OSThread isn't spun up on watches that never wardrive). Nullable.
extern WardriveSession *wardriveSession;

// Create or destroy the BLE threat detector to match `bleThreatDetectorEnabled`
// in NVS (e.g. after the user toggles it in settings). No reboot required.
void syncBleThreatDetectorFromPrefs();
#endif

} // namespace valkyrie
