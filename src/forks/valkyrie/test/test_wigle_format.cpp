// Native unit tests for valkyrie::wigle_format helpers.
//
// Build & run on host:
//   cd firmware/src/forks/valkyrie/test
//   c++ -std=gnu++17 -O0 -g \
//       ../persist/WigleFormat.cpp \
//       test_wigle_format.cpp \
//       -o /tmp/valkyrie_wigle_format_test && /tmp/valkyrie_wigle_format_test
//
// Excluded from the t-watch-s3-valkyrie firmware build via `build_src_filter -<forks/valkyrie/test/>`.

#include "../persist/WigleFormat.h"

#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>

namespace
{

int g_failures = 0;

#define EXPECT(cond, msg)                                                                                                        \
    do {                                                                                                                         \
        if (!(cond)) {                                                                                                           \
            std::fprintf(stderr, "FAIL: %s (line %d)\n", (msg), __LINE__);                                                       \
            ++g_failures;                                                                                                        \
        }                                                                                                                        \
    } while (0)

namespace wf = valkyrie::wigle_format;

void test_channel_to_frequency()
{
    EXPECT(wf::channelToFrequencyMhz(1) == 2412, "ch1 -> 2412");
    EXPECT(wf::channelToFrequencyMhz(6) == 2437, "ch6 -> 2437");
    EXPECT(wf::channelToFrequencyMhz(11) == 2462, "ch11 -> 2462");
    EXPECT(wf::channelToFrequencyMhz(13) == 2472, "ch13 -> 2472");
    EXPECT(wf::channelToFrequencyMhz(14) == 2484, "ch14 -> 2484");
    EXPECT(wf::channelToFrequencyMhz(0) == 0, "ch0 -> 0");
    EXPECT(wf::channelToFrequencyMhz(15) == 0, "ch15 -> 0");
}

void test_format_auth_mode()
{
    char buf[64];
    wf::formatAuthMode(wf::AuthMode::Open, buf, sizeof(buf));
    EXPECT(std::strcmp(buf, "[OPEN][ESS]") == 0, "OPEN");

    wf::formatAuthMode(wf::AuthMode::Wpa2Psk, buf, sizeof(buf));
    EXPECT(std::strcmp(buf, "[WPA2-PSK-CCMP][ESS]") == 0, "WPA2-PSK");

    wf::formatAuthMode(wf::AuthMode::Wpa3Psk, buf, sizeof(buf));
    EXPECT(std::strcmp(buf, "[WPA3-SAE-CCMP][ESS]") == 0, "WPA3-SAE");

    wf::formatAuthMode(wf::AuthMode::WpaWpa2Psk, buf, sizeof(buf));
    EXPECT(std::strcmp(buf, "[WPA-PSK-CCMP][WPA2-PSK-CCMP][ESS]") == 0, "WPA/WPA2 mixed");

    wf::formatAuthMode(wf::AuthMode::Unknown, buf, sizeof(buf));
    EXPECT(std::strcmp(buf, "[ESS]") == 0, "unknown -> just [ESS]");
}

void test_iso8601()
{
    char buf[24];
    // 2026-05-13 00:00:00 UTC -> 1778630400
    size_t n = wf::formatIso8601Utc(1778630400U, buf, sizeof(buf));
    EXPECT(n == 19, "iso8601 length 19");
    EXPECT(std::strcmp(buf, "2026-05-13 00:00:00") == 0, "iso8601 string");

    // Output unchanged when buffer is too small.
    char tiny[8];
    n = wf::formatIso8601Utc(1778630400U, tiny, sizeof(tiny));
    EXPECT(n == 0, "tiny buf returns 0");
    EXPECT(tiny[0] == '\0', "tiny buf NUL-terminated");
}

void test_format_row_basic()
{
    const uint8_t bssid[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    char out[320];
    size_t n = wf::formatRow(bssid, "MyWifi", wf::AuthMode::Wpa2Psk, 1778630415U, 6, -65, 407128000, -740060000, 12.5,
                             5.0, wf::RowType::Wifi, out, sizeof(out));
    EXPECT(n > 0 && out[n - 1] == '\n', "row ends in newline");
    // Spot-check substrings rather than the full line to keep the test robust to printf rounding.
    EXPECT(std::strstr(out, "AA:BB:CC:DD:EE:FF") != nullptr, "row contains MAC");
    EXPECT(std::strstr(out, "\"MyWifi\"") != nullptr, "row contains quoted SSID");
    EXPECT(std::strstr(out, "[WPA2-PSK-CCMP][ESS]") != nullptr, "row contains auth");
    EXPECT(std::strstr(out, "2026-05-13 00:00:15") != nullptr, "row contains timestamp");
    EXPECT(std::strstr(out, ",6,2437,-65,") != nullptr, "row contains channel/freq/rssi");
    EXPECT(std::strstr(out, ",WIFI\n") != nullptr, "row ends with WIFI type");
}

void test_format_row_ssid_escaping()
{
    const uint8_t bssid[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    char out[320];
    // SSID with a comma + quote + control char.
    size_t n =
        wf::formatRow(bssid, "Hello, \"world\"\nbye", wf::AuthMode::Open, 1778630400U, 1, -80, 0, 0, 0.0, 25.0,
                      wf::RowType::Wifi, out, sizeof(out));
    EXPECT(n > 0, "escaped row encodes");
    // Quote inside SSID must be doubled to "" per RFC 4180. Newline collapses to space.
    EXPECT(std::strstr(out, "\"Hello, \"\"world\"\" bye\"") != nullptr, "ssid escaped correctly");
}

void test_haversine()
{
    // Manhattan (40.7128, -74.0060) -> Brooklyn (40.6782, -73.9442) ~ 6.9 km
    int32_t lat1 = 407128000;
    int32_t lon1 = -740060000;
    int32_t lat2 = 406782000;
    int32_t lon2 = -739442000;
    double m = wf::haversineMeters(lat1, lon1, lat2, lon2);
    EXPECT(m > 5500.0 && m < 8500.0, "manhattan-brooklyn ~ 5.5-8.5 km");

    // Same point -> 0.
    EXPECT(wf::haversineMeters(lat1, lon1, lat1, lon1) < 0.01, "same point ~ 0");

    // Either zero -> 0 (sentinel for invalid).
    EXPECT(wf::haversineMeters(0, 0, lat1, lon1) == 0.0, "zero left -> 0");
    EXPECT(wf::haversineMeters(lat1, lon1, 0, 0) == 0.0, "zero right -> 0");
}

void test_auth_from_arduino()
{
    EXPECT(wf::authFromArduinoEspWifi(0) == wf::AuthMode::Open, "0 -> Open");
    EXPECT(wf::authFromArduinoEspWifi(3) == wf::AuthMode::Wpa2Psk, "3 -> Wpa2Psk");
    EXPECT(wf::authFromArduinoEspWifi(6) == wf::AuthMode::Wpa3Psk, "6 -> Wpa3Psk");
    EXPECT(wf::authFromArduinoEspWifi(255) == wf::AuthMode::Unknown, "255 -> Unknown");
}

void test_header_format()
{
    char buf[320];
    size_t n = wf::formatHeader("abcd123", buf, sizeof(buf));
    EXPECT(n > 0, "header encodes");
    EXPECT(std::strstr(buf, "WigleWifi-1.6,") == buf, "starts with WigleWifi-1.6");
    EXPECT(std::strstr(buf, "appRelease=Valkyrie-abcd123,") != nullptr, "header appRelease suffix applied");
    EXPECT(std::strstr(buf, "MAC,SSID,AuthMode,FirstSeen,Channel,Frequency,RSSI,") != nullptr, "header column row");

    // Empty suffix omits dash.
    n = wf::formatHeader(nullptr, buf, sizeof(buf));
    EXPECT(std::strstr(buf, "appRelease=Valkyrie,") != nullptr, "header no-suffix appRelease");
}

} // namespace

int main()
{
    test_channel_to_frequency();
    test_format_auth_mode();
    test_iso8601();
    test_format_row_basic();
    test_format_row_ssid_escaping();
    test_haversine();
    test_auth_from_arduino();
    test_header_format();
    if (g_failures == 0) {
        std::fprintf(stderr, "OK: all wigle_format tests passed\n");
        return 0;
    }
    std::fprintf(stderr, "FAIL: %d wigle_format check(s) failed\n", g_failures);
    return 1;
}
