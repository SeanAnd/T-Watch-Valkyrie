#pragma once

#include <stddef.h>
#include <stdint.h>

namespace valkyrie
{

// Threat classes recognised by Phase 1.
//
// Kept as a plain C++ enum here — DO NOT include the nanopb header
// from this classifier, so the classifier can be unit-tested on the
// host without a working nanopb tree. The mapping to
// `valkyrie_ThreatType` (the wire enum from threat_event.pb.h) lives
// inside BleThreatDetectorModule.cpp where we encode the protobuf.
enum class ThreatType : uint8_t {
    None = 0,
    Airtag = 1,
    Flipper = 2,
    HCSkimmer = 3,
    Flock = 4,
    SmartGlasses = 5,
    Drone = 6,
    // Wi‑Fi promiscuous phase (gated by wifiThreatPhaseEnabled + wifiThreatScanMask; Flock uses BLE mask).
    WifiDeauth = 7,
    WifiEapol = 8,
    WifiPwnagotchi = 9,
    WifiSuspiciousAp = 10,
    WifiMultiSsid = 11,
};

// Which radio path observed the threat. Persisted in the threat log so the
// heartbeat hunt can pick the right radio (and Wi‑Fi heartbeat can lock to
// the seen channel). Wire tokens are "BLE" / "WIFI" (see ThreatLog).
enum class ThreatSource : uint8_t {
    Ble = 0,
    Wifi = 1,
};

// Result of classifying a single BLE advertisement.
struct ClassificationResult {
    ThreatType type;
    // Short human-readable note about WHY we matched, e.g.
    // "Apple Find My", "manuf 0x0FBA", "HC-05", "OUI 70:c9:4e". Always
    // NUL-terminated. Empty on no-match.
    char detail[48];
};

// Pure function: raw advertisement bytes, local name (may be empty),
// and optional 6-byte BLE address in **canonical order** (MSB first,
// same as printed MAC). When `mac` is null, OUI-only Flock detection
// is skipped (host tests); firmware always passes the advertiser MAC.
//
// Ordering matters: AirTag before Flipper (Find My bytes vs Flipper
// manuf). Flock uses flock-you OUI list + ESP32Marauder-style BLE
// XUNTONG (0x09C8) / name heuristics (see BleClassifier.cpp).
//
// `name` is case-insensitive for FLIPPER/FLOCK substrings; HC-* skimmer
// names are case-sensitive exact match.
ClassificationResult classifyAdvertisement(const uint8_t *payload, size_t payloadLen, const char *name,
                                         const uint8_t *mac = nullptr);

} // namespace valkyrie
