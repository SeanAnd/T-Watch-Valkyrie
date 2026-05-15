#pragma once

#include <stddef.h>
#include <stdint.h>

namespace valkyrie
{
namespace wigle_format
{

/// Auth-mode buckets used by the Wigle CSV `AuthMode` column. Decoupled from
/// arduino-esp32's `wifi_auth_mode_t` so the helpers compile in the native
/// host test harness with no Wi-Fi headers in scope.
enum class AuthMode : uint8_t {
    Open = 0,
    Wep = 1,
    WpaPsk = 2,
    Wpa2Psk = 3,
    WpaWpa2Psk = 4,
    Wpa2Enterprise = 5,
    Wpa3Psk = 6,
    Wpa2Wpa3Psk = 7,
    WapiPsk = 8,
    Owe = 9,
    Wpa3Ent192 = 10,
    Unknown = 0xFF,
};

/// Standardized "type" field for Wigle rows. WIFI today; BLE planned for the follow-up phase.
enum class RowType : uint8_t {
    Wifi = 0,
    Ble = 1,
};

/// 2.4 GHz channel → MHz. Returns 0 when `channel` is out of the 1..14 range.
uint16_t channelToFrequencyMhz(uint8_t channel);

/// Format `mode` into a Wigle bracketed-cipher string (e.g. `[WPA2-PSK-CCMP][ESS]`).
/// Always NUL-terminates `out`. Output is empty when `outCap == 0`.
void formatAuthMode(AuthMode mode, char *out, size_t outCap);

/// Format a Unix-epoch second count as `YYYY-MM-DD HH:MM:SS` (UTC). Always NUL-terminates.
/// Returns the strlen written (0 if `outCap < 20`).
size_t formatIso8601Utc(uint32_t unixSecs, char *out, size_t outCap);

/// Format a single Wigle CSV row.
///   - bssid: 6 raw bytes (uppercased AA:BB:... in the output)
///   - ssid: NUL-terminated UTF-8. Commas/quotes inside it are escaped per RFC 4180 (double-quoted).
///   - authMode: bucket above
///   - unixSecs: detection time, UTC seconds since epoch
///   - channel: Wi-Fi channel (1..14)
///   - rssi: dBm (negative integer typically)
///   - lat / lon: degrees * 1e7 (Meshtastic-style fixed-point)
///   - altitudeMeters / accuracyMeters: floats
///   - rowType: WIFI / BLE
/// Returns bytes written (excluding terminator), 0 on encode error. Always writes a trailing '\n' on success.
size_t formatRow(const uint8_t bssid[6], const char *ssid, AuthMode authMode, uint32_t unixSecs, uint8_t channel,
                 int32_t rssi, int32_t lat_i, int32_t lon_i, double altitudeMeters, double accuracyMeters,
                 RowType rowType, char *out, size_t outCap);

/// Wigle 1.6 two-line header. `appReleaseSuffix` is appended to the `appRelease=` field
/// (e.g. a short git hash); pass nullptr to leave as `appRelease=Valkyrie`.
/// Returns bytes written (excluding terminator). Always writes a trailing '\n' on success.
size_t formatHeader(const char *appReleaseSuffix, char *out, size_t outCap);

/// Great-circle distance between two Meshtastic-style fixed-point coordinates, in meters.
/// Returns 0 when either input is invalid (0,0). Time-gating against teleport spikes is the caller's job.
double haversineMeters(int32_t lat1_i, int32_t lon1_i, int32_t lat2_i, int32_t lon2_i);

/// Map an arduino-esp32 `wifi_auth_mode_t` value (passed as uint8 to keep this header host-buildable)
/// to our `AuthMode` enum. Caller is responsible for guaranteeing the value really came from
/// `wifi_auth_mode_t`; unknown numerics map to `AuthMode::Unknown`.
AuthMode authFromArduinoEspWifi(uint8_t arduinoEspAuthEnum);

} // namespace wigle_format
} // namespace valkyrie
