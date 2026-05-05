#include "configuration.h"
#include "ValkyriePrefs.h"

#if defined(ARCH_ESP32) && defined(VALKYRIE_FORK)

#include <Preferences.h>

namespace valkyrie
{

// Private NVS namespace. Must be <= 15 chars (NVS limit).
static constexpr const char *kNvsNamespace = "valkyrie";
static constexpr const char *kKeyEnabled = "ble_en";
static constexpr const char *kKeyScanInterval = "scan_int";
static constexpr const char *kKeyScanWindow = "scan_win";
static constexpr const char *kKeyMinBattery = "min_batt";
static constexpr const char *kKeyDedupe = "dedup";
static constexpr const char *kKeySeeded = "seeded";
static constexpr const char *kKeyScanMask = "scan_msk";
static constexpr const char *kKeyConstScan = "const_scn";

ValkyriePrefs ValkyriePrefs::defaults()
{
    // Mirrored in forks/valkyrie/userPrefs.valkyrie.jsonc — keep these
    // in sync when changing.
    ValkyriePrefs p{};
    p.bleThreatDetectorEnabled = true;
    // ~30 s between scan starts, 10 s window → ~20 s idle.
    p.scanIntervalSecs = 30;
    p.scanWindowSecs = 10;
    p.minBatteryPct = 20;     // do not scan below 20% battery
    p.dedupeWindowSecs = 60;  // re-emit a given mac+type at most once/minute
    p.threatScanMask = ValkyriePrefs::kThreatScanMaskAll;
    p.constantBleScanMode = false;
    return p;
}

ValkyriePrefs ValkyriePrefs::load()
{
    ValkyriePrefs def = defaults();
    Preferences prefs;

    if (!prefs.begin(kNvsNamespace, /*readOnly=*/false)) {
        LOG_WARN("ValkyriePrefs: NVS namespace '%s' open failed; using compiled defaults", kNvsNamespace);
        return def;
    }

    bool seeded = prefs.getBool(kKeySeeded, false);
    if (!seeded) {
        LOG_INFO("ValkyriePrefs: first boot, seeding defaults into '%s'", kNvsNamespace);
        prefs.putBool(kKeyEnabled, def.bleThreatDetectorEnabled);
        prefs.putUShort(kKeyScanInterval, def.scanIntervalSecs);
        prefs.putUShort(kKeyScanWindow, def.scanWindowSecs);
        prefs.putUChar(kKeyMinBattery, def.minBatteryPct);
        prefs.putUShort(kKeyDedupe, def.dedupeWindowSecs);
        prefs.putUChar(kKeyScanMask, def.threatScanMask);
        prefs.putBool(kKeyConstScan, def.constantBleScanMode);
        prefs.putBool(kKeySeeded, true);
    }

    ValkyriePrefs out{};
    out.bleThreatDetectorEnabled = prefs.getBool(kKeyEnabled, def.bleThreatDetectorEnabled);
    out.scanIntervalSecs = prefs.getUShort(kKeyScanInterval, def.scanIntervalSecs);
    out.scanWindowSecs = prefs.getUShort(kKeyScanWindow, def.scanWindowSecs);
    out.minBatteryPct = prefs.getUChar(kKeyMinBattery, def.minBatteryPct);
    out.dedupeWindowSecs = prefs.getUShort(kKeyDedupe, def.dedupeWindowSecs);
    out.threatScanMask = static_cast<uint8_t>(prefs.getUChar(kKeyScanMask, def.threatScanMask) & ValkyriePrefs::kThreatScanMaskAll);
    out.constantBleScanMode = prefs.getBool(kKeyConstScan, def.constantBleScanMode);
    prefs.end();

    // Sanity-clamp: a zero-window or zero-interval would cause us to
    // pin the radio.
    if (out.scanIntervalSecs < 30)
        out.scanIntervalSecs = 30;
    if (out.scanWindowSecs == 0)
        out.scanWindowSecs = def.scanWindowSecs;
    if (out.scanWindowSecs > out.scanIntervalSecs)
        out.scanWindowSecs = out.scanIntervalSecs / 2;
    if (out.minBatteryPct > 100)
        out.minBatteryPct = def.minBatteryPct;
    if ((out.threatScanMask & ValkyriePrefs::kThreatScanMaskAll) == 0)
        out.threatScanMask = def.threatScanMask;

    return out;
}

void ValkyriePrefs::save() const
{
    Preferences prefs;
    if (!prefs.begin(kNvsNamespace, /*readOnly=*/false)) {
        LOG_WARN("ValkyriePrefs: NVS namespace '%s' open failed on save", kNvsNamespace);
        return;
    }
    prefs.putBool(kKeyEnabled, bleThreatDetectorEnabled);
    prefs.putUShort(kKeyScanInterval, scanIntervalSecs);
    prefs.putUShort(kKeyScanWindow, scanWindowSecs);
    prefs.putUChar(kKeyMinBattery, minBatteryPct);
    prefs.putUShort(kKeyDedupe, dedupeWindowSecs);
    prefs.putUChar(kKeyScanMask, static_cast<uint8_t>(threatScanMask & ValkyriePrefs::kThreatScanMaskAll));
    prefs.putBool(kKeyConstScan, constantBleScanMode);
    prefs.putBool(kKeySeeded, true);
    prefs.end();
}

} // namespace valkyrie

#else // !ARCH_ESP32 || !VALKYRIE_FORK

namespace valkyrie
{
ValkyriePrefs ValkyriePrefs::defaults()
{
    ValkyriePrefs p{};
    p.bleThreatDetectorEnabled = false;
    p.scanIntervalSecs = 30;
    p.scanWindowSecs = 10;
    p.minBatteryPct = 20;
    p.dedupeWindowSecs = 60;
    p.threatScanMask = ValkyriePrefs::kThreatScanMaskAll;
    p.constantBleScanMode = false;
    return p;
}
ValkyriePrefs ValkyriePrefs::load() { return defaults(); }
void ValkyriePrefs::save() const {}
} // namespace valkyrie

#endif
