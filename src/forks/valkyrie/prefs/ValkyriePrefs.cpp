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
static constexpr const char *kKeyThreatHaptic = "thr_hapt";
static constexpr const char *kKeyThreatSound = "thr_snd";
static constexpr const char *kKeyStalkSight = "stk_sig";
static constexpr const char *kKeyStalkPlaces = "stk_plc";
static constexpr const char *kKeyStalkSepM = "stk_sep";
static constexpr const char *kKeyStalkTtl = "stk_ttl";

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
    p.threatDetectionHapticEnabled = true;
    p.threatDetectionSoundEnabled = true;
    p.stalkMinSightings = 3;
    p.stalkMinDistinctPlaces = 2;
    p.stalkMinSeparationM = 75;
    p.stalkEntryTtlSecs = 48UL * 3600UL;
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
        prefs.putBool(kKeyThreatHaptic, def.threatDetectionHapticEnabled);
        prefs.putBool(kKeyThreatSound, def.threatDetectionSoundEnabled);
        prefs.putUChar(kKeyStalkSight, def.stalkMinSightings);
        prefs.putUChar(kKeyStalkPlaces, def.stalkMinDistinctPlaces);
        prefs.putUShort(kKeyStalkSepM, def.stalkMinSeparationM);
        prefs.putUInt(kKeyStalkTtl, def.stalkEntryTtlSecs);
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
    out.threatDetectionHapticEnabled = prefs.getBool(kKeyThreatHaptic, def.threatDetectionHapticEnabled);
    out.threatDetectionSoundEnabled = prefs.getBool(kKeyThreatSound, def.threatDetectionSoundEnabled);
    out.stalkMinSightings = prefs.getUChar(kKeyStalkSight, def.stalkMinSightings);
    out.stalkMinDistinctPlaces = prefs.getUChar(kKeyStalkPlaces, def.stalkMinDistinctPlaces);
    out.stalkMinSeparationM = prefs.getUShort(kKeyStalkSepM, def.stalkMinSeparationM);
    out.stalkEntryTtlSecs = prefs.getUInt(kKeyStalkTtl, def.stalkEntryTtlSecs);
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

    if (out.stalkMinSightings < 2)
        out.stalkMinSightings = 2;
    if (out.stalkMinSightings > 50)
        out.stalkMinSightings = 50;
    if (out.stalkMinDistinctPlaces < 2)
        out.stalkMinDistinctPlaces = 2;
    if (out.stalkMinDistinctPlaces > 8)
        out.stalkMinDistinctPlaces = 8;
    if (out.stalkMinSeparationM < 20)
        out.stalkMinSeparationM = 20;
    if (out.stalkMinSeparationM > 500)
        out.stalkMinSeparationM = 500;
    if (out.stalkEntryTtlSecs < 3600UL)
        out.stalkEntryTtlSecs = 3600UL;
    if (out.stalkEntryTtlSecs > 7UL * 24UL * 3600UL)
        out.stalkEntryTtlSecs = 7UL * 24UL * 3600UL;

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
    prefs.putBool(kKeyThreatHaptic, threatDetectionHapticEnabled);
    prefs.putBool(kKeyThreatSound, threatDetectionSoundEnabled);
    prefs.putUChar(kKeyStalkSight, stalkMinSightings);
    prefs.putUChar(kKeyStalkPlaces, stalkMinDistinctPlaces);
    prefs.putUShort(kKeyStalkSepM, stalkMinSeparationM);
    prefs.putUInt(kKeyStalkTtl, stalkEntryTtlSecs);
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
    p.threatDetectionHapticEnabled = true;
    p.threatDetectionSoundEnabled = true;
    p.stalkMinSightings = 3;
    p.stalkMinDistinctPlaces = 2;
    p.stalkMinSeparationM = 75;
    p.stalkEntryTtlSecs = 48UL * 3600UL;
    return p;
}
ValkyriePrefs ValkyriePrefs::load() { return defaults(); }
void ValkyriePrefs::save() const {}
} // namespace valkyrie

#endif
