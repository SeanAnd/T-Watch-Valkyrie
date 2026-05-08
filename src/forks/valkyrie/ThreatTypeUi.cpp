#include "ThreatTypeUi.h"

namespace valkyrie
{

const char *threatTypeWireName(ThreatType t)
{
    switch (t) {
    case ThreatType::Airtag:
        return "AIRTAG";
    case ThreatType::Flipper:
        return "FLIPPER";
    case ThreatType::HCSkimmer:
        return "HC_SKIMMER";
    case ThreatType::Flock:
        return "FLOCK";
    case ThreatType::SmartGlasses:
        return "SMART_GLASSES";
    case ThreatType::Drone:
        return "DRONE";
    case ThreatType::WifiDeauth:
        return "WIFI_DEAUTH";
    case ThreatType::WifiEapol:
        return "WIFI_EAPOL";
    case ThreatType::WifiPwnagotchi:
        return "WIFI_PWNAGOTCHI";
    case ThreatType::WifiSuspiciousAp:
        return "WIFI_SUSPICIOUS_AP";
    case ThreatType::WifiMultiSsid:
        return "WIFI_MULTI_SSID";
    case ThreatType::None:
    default:
        return "NONE";
    }
}

const char *threatTypeMenuLabel(ThreatType t)
{
    switch (t) {
    case ThreatType::Airtag:
        return "AirTag";
    case ThreatType::Flipper:
        return "Flipper";
    case ThreatType::HCSkimmer:
        return "HC skimmer";
    case ThreatType::Flock:
        return "Flock";
    case ThreatType::SmartGlasses:
        return "Glasses";
    case ThreatType::Drone:
        return "Drone";
    case ThreatType::WifiDeauth:
        return "WiFi deauth";
    case ThreatType::WifiEapol:
        return "WiFi EAPOL";
    case ThreatType::WifiPwnagotchi:
        return "Pwnagotchi";
    case ThreatType::WifiSuspiciousAp:
        return "Suspicious AP";
    case ThreatType::WifiMultiSsid:
        return "Multi-SSID";
    case ThreatType::None:
    default:
        return "?";
    }
}

} // namespace valkyrie
