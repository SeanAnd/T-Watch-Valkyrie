// Native unit tests for valkyrie::threatlog_decode (CSV decode helpers).
//
// Build & run on host:
//   cd firmware/src/forks/valkyrie/test
//   c++ -std=gnu++17 -O0 -g \
//       ../persist/ThreatLogDecode.cpp \
//       ../ThreatTypeUi.cpp \
//       test_threat_log_decode.cpp \
//       -o /tmp/valkyrie_threat_log_decode_test && /tmp/valkyrie_threat_log_decode_test
//
// Excluded from the t-watch-s3-valkyrie firmware build via `build_src_filter -<forks/valkyrie/test/>`.

#include "../persist/ThreatLogDecode.h"

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

using valkyrie::ThreatSource;
using valkyrie::ThreatType;
namespace tld = valkyrie::threatlog_decode;

static const uint8_t kMac[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};

static bool macsEq(const uint8_t a[6], const uint8_t b[6])
{
    return std::memcmp(a, b, 6) == 0;
}

void test_legacy_ble_row_infers_source()
{
    const char *line = "AIRTAG,1234,AA:BB:CC:DD:EE:FF,\"some name\",-50,\"Apple Find My\"";
    ThreatType type = ThreatType::None;
    uint8_t mac[6] = {0};
    ThreatSource src = ThreatSource::Wifi;
    uint8_t ch = 99;
    EXPECT(tld::decodeFullIdentity(line, &type, mac, &src, &ch), "legacy ble row decodes");
    EXPECT(type == ThreatType::Airtag, "legacy ble row type");
    EXPECT(macsEq(mac, kMac), "legacy ble row mac");
    EXPECT(src == ThreatSource::Ble, "legacy ble row source inferred to BLE");
    EXPECT(ch == 0, "legacy ble row channel defaults 0");
}

void test_legacy_wifi_row_infers_source()
{
    // Pre-schema-bump row from the old WiFi pass: lacks trailing source/channel columns.
    const char *line = "WIFI_DEAUTH,5678,AA:BB:CC:DD:EE:FF,\"\",-65,\"deauth_or_disassoc\"";
    ThreatType type = ThreatType::None;
    uint8_t mac[6] = {0};
    ThreatSource src = ThreatSource::Ble;
    uint8_t ch = 99;
    EXPECT(tld::decodeFullIdentity(line, &type, mac, &src, &ch), "legacy wifi row decodes");
    EXPECT(type == ThreatType::WifiDeauth, "legacy wifi row type");
    EXPECT(src == ThreatSource::Wifi, "legacy wifi row source inferred to WIFI");
    EXPECT(ch == 0, "legacy wifi row channel defaults 0");
}

void test_new_ble_row_uses_stored_columns()
{
    const char *line = "AIRTAG,1234,AA:BB:CC:DD:EE:FF,\"some name\",-50,\"Apple Find My\",BLE,0";
    ThreatType type = ThreatType::None;
    uint8_t mac[6] = {0};
    ThreatSource src = ThreatSource::Wifi;
    uint8_t ch = 99;
    EXPECT(tld::decodeFullIdentity(line, &type, mac, &src, &ch), "new ble row decodes");
    EXPECT(type == ThreatType::Airtag, "new ble row type");
    EXPECT(src == ThreatSource::Ble, "new ble row source stored BLE");
    EXPECT(ch == 0, "new ble row channel stored 0");
}

void test_new_wifi_row_uses_stored_channel()
{
    const char *line = "WIFI_DEAUTH,5678,AA:BB:CC:DD:EE:FF,\"\",-65,\"deauth_or_disassoc\",WIFI,6";
    ThreatType type = ThreatType::None;
    uint8_t mac[6] = {0};
    ThreatSource src = ThreatSource::Ble;
    uint8_t ch = 0;
    EXPECT(tld::decodeFullIdentity(line, &type, mac, &src, &ch), "new wifi row decodes");
    EXPECT(type == ThreatType::WifiDeauth, "new wifi row type");
    EXPECT(src == ThreatSource::Wifi, "new wifi row source stored WIFI");
    EXPECT(ch == 6, "new wifi row channel stored 6");
}

void test_new_wifi_row_channel_eleven()
{
    const char *line = "WIFI_PWNAGOTCHI,9999,AA:BB:CC:DD:EE:FF,\"pwnd\",-72,\"beacon_json_heuristic\",WIFI,11";
    ThreatType type = ThreatType::None;
    uint8_t mac[6] = {0};
    ThreatSource src = ThreatSource::Ble;
    uint8_t ch = 0;
    EXPECT(tld::decodeFullIdentity(line, &type, mac, &src, &ch), "new wifi row ch11 decodes");
    EXPECT(ch == 11, "new wifi row ch11 stored");
}

void test_quoted_field_with_comma_does_not_break_decode()
{
    // detail intentionally contains a comma; trailing source/channel must still parse.
    const char *line = "FLOCK,4242,AA:BB:CC:DD:EE:FF,\"name\",-58,\"label,with comma\",WIFI,1";
    ThreatType type = ThreatType::None;
    uint8_t mac[6] = {0};
    ThreatSource src = ThreatSource::Ble;
    uint8_t ch = 0;
    EXPECT(tld::decodeFullIdentity(line, &type, mac, &src, &ch), "quoted comma row decodes");
    EXPECT(type == ThreatType::Flock, "quoted comma row type Flock");
    EXPECT(src == ThreatSource::Wifi, "quoted comma row source still WIFI");
    EXPECT(ch == 1, "quoted comma row channel still 1");
}

void test_unknown_trailing_token_falls_back_to_inference()
{
    // Looks like new schema but trailing tokens are bogus -> caller treats as legacy.
    const char *line = "WIFI_DEAUTH,1,AA:BB:CC:DD:EE:FF,\"\",-70,\"deauth_or_disassoc\",FOO,bar";
    ThreatType type = ThreatType::None;
    uint8_t mac[6] = {0};
    ThreatSource src = ThreatSource::Ble;
    uint8_t ch = 99;
    EXPECT(tld::decodeFullIdentity(line, &type, mac, &src, &ch), "bogus trailing decodes");
    EXPECT(src == ThreatSource::Wifi, "bogus trailing falls back to type-inferred WIFI");
    EXPECT(ch == 0, "bogus trailing falls back to channel 0");
}

void test_legacy_ts_first_row_still_decodes()
{
    // Even older format: ts first, type second.
    const char *line = "1234,AIRTAG,AA:BB:CC:DD:EE:FF,\"name\",-50,\"Apple Find My\"";
    ThreatType type = ThreatType::None;
    uint8_t mac[6] = {0};
    ThreatSource src = ThreatSource::Wifi;
    uint8_t ch = 99;
    EXPECT(tld::decodeFullIdentity(line, &type, mac, &src, &ch), "legacy ts-first row decodes");
    EXPECT(type == ThreatType::Airtag, "legacy ts-first row type");
    EXPECT(src == ThreatSource::Ble, "legacy ts-first row source inferred BLE");
}

void test_extract_trailing_with_trailing_newline()
{
    // Lines from the file may include a trailing '\n'.
    const char *line = "WIFI_DEAUTH,5,AA:BB:CC:DD:EE:FF,\"\",-65,\"x\",WIFI,11\n";
    ThreatSource src = ThreatSource::Ble;
    uint8_t ch = 0;
    EXPECT(tld::extractTrailingSourceAndChannel(line, &src, &ch), "trailing newline still parses");
    EXPECT(src == ThreatSource::Wifi, "newline preserved WIFI");
    EXPECT(ch == 11, "newline preserved ch11");
}

void test_extract_trailing_rejects_non_numeric_channel()
{
    const char *line = "AIRTAG,1,AA:BB:CC:DD:EE:FF,\"\",-50,\"x\",BLE,abc";
    ThreatSource src = ThreatSource::Ble;
    uint8_t ch = 0;
    EXPECT(!tld::extractTrailingSourceAndChannel(line, &src, &ch), "non-numeric channel rejected");
}

void test_extract_trailing_bare_legacy_returns_false()
{
    const char *line = "AIRTAG,1,AA:BB:CC:DD:EE:FF,\"\",-50,\"x\"";
    ThreatSource src = ThreatSource::Ble;
    uint8_t ch = 0;
    // Last comma is between -50 and "x"; second-to-last is between "" and -50. srcBuf would be "-50",
    // which isn't BLE/WIFI, so this returns false -> caller infers from type.
    EXPECT(!tld::extractTrailingSourceAndChannel(line, &src, &ch), "legacy rows return false");
}

void test_infer_source_from_type()
{
    EXPECT(tld::inferSourceFromType(ThreatType::Airtag) == ThreatSource::Ble, "Airtag -> BLE");
    EXPECT(tld::inferSourceFromType(ThreatType::Flock) == ThreatSource::Ble, "Flock -> BLE (ambiguous, defaults BLE)");
    EXPECT(tld::inferSourceFromType(ThreatType::WifiDeauth) == ThreatSource::Wifi, "WifiDeauth -> WIFI");
    EXPECT(tld::inferSourceFromType(ThreatType::WifiMultiSsid) == ThreatSource::Wifi, "WifiMultiSsid -> WIFI");
}

} // namespace

int main()
{
    test_legacy_ble_row_infers_source();
    test_legacy_wifi_row_infers_source();
    test_new_ble_row_uses_stored_columns();
    test_new_wifi_row_uses_stored_channel();
    test_new_wifi_row_channel_eleven();
    test_quoted_field_with_comma_does_not_break_decode();
    test_unknown_trailing_token_falls_back_to_inference();
    test_legacy_ts_first_row_still_decodes();
    test_extract_trailing_with_trailing_newline();
    test_extract_trailing_rejects_non_numeric_channel();
    test_extract_trailing_bare_legacy_returns_false();
    test_infer_source_from_type();

    if (g_failures == 0) {
        std::printf("OK: all threat log decode tests passed\n");
        return 0;
    }
    std::fprintf(stderr, "FAILED: %d threat log decode tests failed\n", g_failures);
    return 1;
}
