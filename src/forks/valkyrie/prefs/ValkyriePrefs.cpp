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
static constexpr const char *kKeyPhoneNotif = "phn_notif";
static constexpr const char *kKeyStalkSight = "stk_sig";
static constexpr const char *kKeyStalkPlaces = "stk_plc";
static constexpr const char *kKeyStalkSepM = "stk_sep";
static constexpr const char *kKeyStalkTtl = "stk_ttl";
static constexpr const char *kKeyBleThreatPhase = "ble_phs";
static constexpr const char *kKeyWifiThreatEn = "wifi_en";
static constexpr const char *kKeyWifiThreatMsk = "wifi_msk";
static constexpr const char *kKeyWifiThreatMs = "wifi_ms";
static constexpr const char *kKeyWifiThreatDw = "wifi_dw";
/// One-shot NVS upgrade marker: sync legacy installs where wifi_msk had types on but wifi_en stayed false.
static constexpr const char *kKeyWifiMig = "wifi_mig1";

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
    p.bleThreatPhaseEnabled = true;
    p.constantBleScanMode = false;
    p.threatDetectionHapticEnabled = true;
    p.threatDetectionSoundEnabled = true;
    p.phoneNotificationsEnabled = true;
    p.stalkMinSightings = 3;
    p.stalkMinDistinctPlaces = 2;
    p.stalkMinSeparationM = 75;
    p.stalkEntryTtlSecs = 48UL * 3600UL;
    // Match full wifiThreatScanMask default: run Wi‑Fi phase unless user disables it in Settings.
    p.wifiThreatPhaseEnabled = true;
    p.wifiThreatScanMask = ValkyriePrefs::kWifiThreatScanMaskAll;
    // Default promiscuous scan budget: match default scanWindowSecs (10 s).
    p.wifiThreatPassMs = 10000;
    p.wifiThreatChannelDwellMs = 350;
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
        prefs.putBool(kKeyBleThreatPhase, def.bleThreatPhaseEnabled);
        prefs.putBool(kKeyConstScan, def.constantBleScanMode);
        prefs.putBool(kKeyThreatHaptic, def.threatDetectionHapticEnabled);
        prefs.putBool(kKeyThreatSound, def.threatDetectionSoundEnabled);
        prefs.putBool(kKeyPhoneNotif, def.phoneNotificationsEnabled);
        prefs.putUChar(kKeyStalkSight, def.stalkMinSightings);
        prefs.putUChar(kKeyStalkPlaces, def.stalkMinDistinctPlaces);
        prefs.putUShort(kKeyStalkSepM, def.stalkMinSeparationM);
        prefs.putUInt(kKeyStalkTtl, def.stalkEntryTtlSecs);
        prefs.putBool(kKeyWifiThreatEn, def.wifiThreatPhaseEnabled);
        prefs.putUChar(kKeyWifiThreatMsk, def.wifiThreatScanMask);
        prefs.putUShort(kKeyWifiThreatMs, def.wifiThreatPassMs);
        prefs.putUShort(kKeyWifiThreatDw, def.wifiThreatChannelDwellMs);
        prefs.putBool(kKeySeeded, true);
    }

    ValkyriePrefs out{};
    out.bleThreatDetectorEnabled = prefs.getBool(kKeyEnabled, def.bleThreatDetectorEnabled);
    out.scanIntervalSecs = prefs.getUShort(kKeyScanInterval, def.scanIntervalSecs);
    out.scanWindowSecs = prefs.getUShort(kKeyScanWindow, def.scanWindowSecs);
    out.minBatteryPct = prefs.getUChar(kKeyMinBattery, def.minBatteryPct);
    out.dedupeWindowSecs = prefs.getUShort(kKeyDedupe, def.dedupeWindowSecs);
    out.threatScanMask = static_cast<uint8_t>(prefs.getUChar(kKeyScanMask, def.threatScanMask) & ValkyriePrefs::kThreatScanMaskAll);
    out.bleThreatPhaseEnabled = prefs.getBool(kKeyBleThreatPhase, def.bleThreatPhaseEnabled);
    out.constantBleScanMode = prefs.getBool(kKeyConstScan, def.constantBleScanMode);
    out.threatDetectionHapticEnabled = prefs.getBool(kKeyThreatHaptic, def.threatDetectionHapticEnabled);
    out.threatDetectionSoundEnabled = prefs.getBool(kKeyThreatSound, def.threatDetectionSoundEnabled);
    out.phoneNotificationsEnabled = prefs.getBool(kKeyPhoneNotif, def.phoneNotificationsEnabled);
    out.stalkMinSightings = prefs.getUChar(kKeyStalkSight, def.stalkMinSightings);
    out.stalkMinDistinctPlaces = prefs.getUChar(kKeyStalkPlaces, def.stalkMinDistinctPlaces);
    out.stalkMinSeparationM = prefs.getUShort(kKeyStalkSepM, def.stalkMinSeparationM);
    out.stalkEntryTtlSecs = prefs.getUInt(kKeyStalkTtl, def.stalkEntryTtlSecs);
    out.wifiThreatPhaseEnabled = prefs.getBool(kKeyWifiThreatEn, def.wifiThreatPhaseEnabled);
    out.wifiThreatScanMask =
        static_cast<uint8_t>(prefs.getUChar(kKeyWifiThreatMsk, def.wifiThreatScanMask) & ValkyriePrefs::kWifiThreatScanMaskAll);
    out.wifiThreatPassMs = prefs.getUShort(kKeyWifiThreatMs, def.wifiThreatPassMs);
    out.wifiThreatChannelDwellMs = prefs.getUShort(kKeyWifiThreatDw, def.wifiThreatChannelDwellMs);
#if HAS_WIFI && !defined(ARCH_PORTDUINO)
    const uint8_t wifiMigLegacy = prefs.getUChar(kKeyWifiMig, 0);
#else
    const uint8_t wifiMigLegacy = 1;
#endif
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

    if (out.wifiThreatPassMs < 500)
        out.wifiThreatPassMs = 500;
    if (out.wifiThreatPassMs > 15000)
        out.wifiThreatPassMs = 15000;
    if (out.wifiThreatChannelDwellMs < 50)
        out.wifiThreatChannelDwellMs = 50;
    if (out.wifiThreatChannelDwellMs > 600)
        out.wifiThreatChannelDwellMs = 600;
    if ((out.wifiThreatScanMask & ValkyriePrefs::kWifiThreatScanMaskAll) == 0)
        out.wifiThreatScanMask = def.wifiThreatScanMask;

#if HAS_WIFI && !defined(ARCH_PORTDUINO)
    // Legacy contradiction: threat toggles (wifi_msk / Flock) implied Wi‑Fi work while wifi_en stayed false from older seeds.
    if (wifiMigLegacy == 0) {
        bool wantsWifiPass = false;
        if (out.isThreatTypeEnabled(ThreatType::Flock))
            wantsWifiPass = true;
        else {
            for (unsigned u = 7; u <= 11; ++u) {
                if (out.isWifiThreatTypeEnabled(static_cast<ThreatType>((uint8_t)u))) {
                    wantsWifiPass = true;
                    break;
                }
            }
        }
        const bool needMasterOn = !out.wifiThreatPhaseEnabled && wantsWifiPass;
        if (needMasterOn)
            out.wifiThreatPhaseEnabled = true;

        Preferences pw;
        if (pw.begin(kNvsNamespace, /*readOnly=*/false)) {
            if (needMasterOn)
                pw.putBool(kKeyWifiThreatEn, true);
            pw.putUChar(kKeyWifiMig, 1);
            pw.end();
        }
        if (needMasterOn)
            LOG_INFO("ValkyriePrefs: synced wifi_en on (Wi‑Fi/Flock toggles were enabled; master was off)");
    }
#endif

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
    prefs.putBool(kKeyBleThreatPhase, bleThreatPhaseEnabled);
    prefs.putBool(kKeyConstScan, constantBleScanMode);
    prefs.putBool(kKeyThreatHaptic, threatDetectionHapticEnabled);
    prefs.putBool(kKeyThreatSound, threatDetectionSoundEnabled);
    prefs.putBool(kKeyPhoneNotif, phoneNotificationsEnabled);
    prefs.putUChar(kKeyStalkSight, stalkMinSightings);
    prefs.putUChar(kKeyStalkPlaces, stalkMinDistinctPlaces);
    prefs.putUShort(kKeyStalkSepM, stalkMinSeparationM);
    prefs.putUInt(kKeyStalkTtl, stalkEntryTtlSecs);
    prefs.putBool(kKeyWifiThreatEn, wifiThreatPhaseEnabled);
    prefs.putUChar(kKeyWifiThreatMsk, static_cast<uint8_t>(wifiThreatScanMask & ValkyriePrefs::kWifiThreatScanMaskAll));
    prefs.putUShort(kKeyWifiThreatMs, wifiThreatPassMs);
    prefs.putUShort(kKeyWifiThreatDw, wifiThreatChannelDwellMs);
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
    p.bleThreatPhaseEnabled = true;
    p.constantBleScanMode = false;
    p.threatDetectionHapticEnabled = true;
    p.threatDetectionSoundEnabled = true;
    p.phoneNotificationsEnabled = true;
    p.stalkMinSightings = 3;
    p.stalkMinDistinctPlaces = 2;
    p.stalkMinSeparationM = 75;
    p.stalkEntryTtlSecs = 48UL * 3600UL;
    p.wifiThreatPhaseEnabled = false;
    p.wifiThreatScanMask = ValkyriePrefs::kWifiThreatScanMaskAll;
    // Same default as ESP32 path (mirrors 10 s scan window when enabled).
    p.wifiThreatPassMs = 10000;
    p.wifiThreatChannelDwellMs = 350;
    return p;
}
ValkyriePrefs ValkyriePrefs::load() { return defaults(); }
void ValkyriePrefs::save() const {}
} // namespace valkyrie

#endif
