#include "WigleFormat.h"

#include <math.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

namespace valkyrie
{
namespace wigle_format
{

uint16_t channelToFrequencyMhz(uint8_t channel)
{
    if (channel >= 1 && channel <= 13)
        return (uint16_t)(2407 + 5 * channel);
    if (channel == 14)
        return 2484;
    return 0;
}

void formatAuthMode(AuthMode mode, char *out, size_t outCap)
{
    if (!out || outCap == 0)
        return;
    out[0] = '\0';
    // Wigle convention: bracketed cipher tokens, ending with [ESS] for an infrastructure AP.
    const char *body = nullptr;
    switch (mode) {
    case AuthMode::Open:
        body = "[OPEN]";
        break;
    case AuthMode::Wep:
        body = "[WEP]";
        break;
    case AuthMode::WpaPsk:
        body = "[WPA-PSK-CCMP]";
        break;
    case AuthMode::Wpa2Psk:
        body = "[WPA2-PSK-CCMP]";
        break;
    case AuthMode::WpaWpa2Psk:
        body = "[WPA-PSK-CCMP][WPA2-PSK-CCMP]";
        break;
    case AuthMode::Wpa2Enterprise:
        body = "[WPA2-EAP-CCMP]";
        break;
    case AuthMode::Wpa3Psk:
        body = "[WPA3-SAE-CCMP]";
        break;
    case AuthMode::Wpa2Wpa3Psk:
        body = "[WPA2-PSK-CCMP][WPA3-SAE-CCMP]";
        break;
    case AuthMode::WapiPsk:
        body = "[WAPI-PSK-SMS4]";
        break;
    case AuthMode::Owe:
        body = "[OWE]";
        break;
    case AuthMode::Wpa3Ent192:
        body = "[WPA3-EAP-SUITE-B-192]";
        break;
    case AuthMode::Unknown:
    default:
        body = "";
        break;
    }
    snprintf(out, outCap, "%s[ESS]", body);
}

size_t formatIso8601Utc(uint32_t unixSecs, char *out, size_t outCap)
{
    if (!out || outCap < 20) {
        if (out && outCap)
            out[0] = '\0';
        return 0;
    }
    time_t t = (time_t)unixSecs;
    struct tm tmv;
#if defined(_WIN32)
    gmtime_s(&tmv, &t);
#else
    gmtime_r(&t, &tmv);
#endif
    size_t n = strftime(out, outCap, "%Y-%m-%d %H:%M:%S", &tmv);
    if (n == 0) {
        out[0] = '\0';
        return 0;
    }
    return n;
}

// Inline RFC-4180 double-quote escape into a fixed-cap buffer. Output is NOT wrapped in quotes here;
// the row formatter wraps each user field in quotes itself.
static size_t escapeCsvField(const char *in, char *out, size_t outCap)
{
    if (!out || outCap == 0)
        return 0;
    out[0] = '\0';
    if (!in)
        return 0;
    size_t j = 0;
    for (size_t i = 0; in[i] && j + 1 < outCap; ++i) {
        unsigned char c = (unsigned char)in[i];
        if (c == '\n' || c == '\r' || c < 0x20) {
            out[j++] = ' ';
        } else if (c == '"') {
            if (j + 2 >= outCap)
                break;
            out[j++] = '"';
            out[j++] = '"';
        } else {
            out[j++] = (char)c;
        }
    }
    out[j] = '\0';
    return j;
}

size_t formatRow(const uint8_t bssid[6], const char *ssid, AuthMode authMode, uint32_t unixSecs, uint8_t channel,
                 int32_t rssi, int32_t lat_i, int32_t lon_i, double altitudeMeters, double accuracyMeters,
                 RowType rowType, char *out, size_t outCap)
{
    if (!out || outCap < 80 || !bssid)
        return 0;

    char macStr[18];
    snprintf(macStr, sizeof(macStr), "%02X:%02X:%02X:%02X:%02X:%02X", bssid[0], bssid[1], bssid[2], bssid[3], bssid[4],
             bssid[5]);

    char ssidEsc[64];
    escapeCsvField(ssid ? ssid : "", ssidEsc, sizeof(ssidEsc));

    char authBuf[48];
    formatAuthMode(authMode, authBuf, sizeof(authBuf));

    char tsBuf[24];
    formatIso8601Utc(unixSecs, tsBuf, sizeof(tsBuf));

    const uint16_t freqMhz = channelToFrequencyMhz(channel);

    const double lat = (double)lat_i / 1e7;
    const double lon = (double)lon_i / 1e7;

    const char *typeStr = (rowType == RowType::Ble) ? "BLE" : "WIFI";

    // Wigle 1.6 column order: MAC,SSID,AuthMode,FirstSeen,Channel,Frequency,RSSI,Lat,Lon,Alt,Accuracy,RCOIs,MfgrId,Type
    int n = snprintf(out, outCap, "%s,\"%s\",%s,%s,%u,%u,%d,%.6f,%.6f,%.2f,%.2f,,,%s\n", macStr, ssidEsc, authBuf, tsBuf,
                     (unsigned)channel, (unsigned)freqMhz, (int)rssi, lat, lon, altitudeMeters, accuracyMeters, typeStr);
    if (n < 0)
        return 0;
    if ((size_t)n >= outCap) {
        out[outCap - 1] = '\0';
        return outCap - 1;
    }
    return (size_t)n;
}

size_t formatHeader(const char *appReleaseSuffix, char *out, size_t outCap)
{
    if (!out || outCap < 96)
        return 0;
    const char *suffix = (appReleaseSuffix && appReleaseSuffix[0]) ? appReleaseSuffix : "";
    const char *sep = suffix[0] ? "-" : "";
    int n = snprintf(out, outCap,
                     "WigleWifi-1.6,appRelease=Valkyrie%s%s,model=T-Watch-S3,release=Meshtastic,device=t-watch-s3,"
                     "display=NONE,board=ESP32-S3,brand=LilyGo\n"
                     "MAC,SSID,AuthMode,FirstSeen,Channel,Frequency,RSSI,CurrentLatitude,CurrentLongitude,"
                     "AltitudeMeters,AccuracyMeters,RCOIs,MfgrId,Type\n",
                     sep, suffix);
    if (n < 0)
        return 0;
    if ((size_t)n >= outCap) {
        out[outCap - 1] = '\0';
        return outCap - 1;
    }
    return (size_t)n;
}

double haversineMeters(int32_t lat1_i, int32_t lon1_i, int32_t lat2_i, int32_t lon2_i)
{
    if ((lat1_i == 0 && lon1_i == 0) || (lat2_i == 0 && lon2_i == 0))
        return 0.0;
    const double kEarthRadiusM = 6371000.0;
    const double kDeg2Rad = M_PI / 180.0;
    const double lat1 = (double)lat1_i / 1e7 * kDeg2Rad;
    const double lon1 = (double)lon1_i / 1e7 * kDeg2Rad;
    const double lat2 = (double)lat2_i / 1e7 * kDeg2Rad;
    const double lon2 = (double)lon2_i / 1e7 * kDeg2Rad;
    const double dlat = lat2 - lat1;
    const double dlon = lon2 - lon1;
    const double sdlat2 = sin(dlat / 2.0);
    const double sdlon2 = sin(dlon / 2.0);
    const double a = sdlat2 * sdlat2 + cos(lat1) * cos(lat2) * sdlon2 * sdlon2;
    const double c = 2.0 * atan2(sqrt(a), sqrt(1.0 - a));
    return kEarthRadiusM * c;
}

AuthMode authFromArduinoEspWifi(uint8_t arduinoEspAuthEnum)
{
    // Mirrors arduino-esp32's wifi_auth_mode_t. Kept inline so the host test compiles.
    switch (arduinoEspAuthEnum) {
    case 0:
        return AuthMode::Open;
    case 1:
        return AuthMode::Wep;
    case 2:
        return AuthMode::WpaPsk;
    case 3:
        return AuthMode::Wpa2Psk;
    case 4:
        return AuthMode::WpaWpa2Psk;
    case 5:
        return AuthMode::Wpa2Enterprise;
    case 6:
        return AuthMode::Wpa3Psk;
    case 7:
        return AuthMode::Wpa2Wpa3Psk;
    case 8:
        return AuthMode::WapiPsk;
    case 9:
        return AuthMode::Owe;
    case 10:
        return AuthMode::Wpa3Ent192;
    default:
        return AuthMode::Unknown;
    }
}

} // namespace wigle_format
} // namespace valkyrie
