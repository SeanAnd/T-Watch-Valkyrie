// Native unit tests for valkyrie::classifyAdvertisement().
//
// Build & run on host (no PlatformIO required, no firmware deps):
//   c++ -std=gnu++17 -O0 -g  ../modules/BleClassifier.cpp test_ble_classifier.cpp -o /tmp/valkyrie_test && /tmp/valkyrie_test
//
// The classifier is a pure function over byte buffers and a
// NUL-terminated name; it has no dependency on nanopb, NimBLE, or
// upstream Meshtastic headers.
//
// NOTE: this file is excluded from the t-watch-s3-valkyrie build via
// `build_src_filter -<forks/valkyrie/test/>`.

#include "../modules/BleClassifier.h"

#include <cassert>
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

using valkyrie::ThreatType;

void test_empty_payload_no_match()
{
    auto r = valkyrie::classifyAdvertisement(nullptr, 0, "");
    EXPECT(r.type == ThreatType::None, "empty payload no match");
}

void test_airtag_pattern_1e_ff_4c_00()
{
    const uint8_t adv[] = {0x02, 0x01, 0x06, 0x1E, 0xFF, 0x4C, 0x00, 0x12, 0x19, 0x10};
    auto r = valkyrie::classifyAdvertisement(adv, sizeof(adv), "");
    EXPECT(r.type == ThreatType::Airtag, "airtag 1E FF 4C 00");
}

void test_airtag_pattern_4c_00_12_19()
{
    const uint8_t adv[] = {0x02, 0x01, 0x06, 0x4C, 0x00, 0x12, 0x19, 0x10};
    auto r = valkyrie::classifyAdvertisement(adv, sizeof(adv), "");
    EXPECT(r.type == ThreatType::Airtag, "airtag 4C 00 12 19");
}

void test_airtag_extended_1a_ff_4c_00_12()
{
    const uint8_t adv[] = {0x1A, 0xFF, 0x4C, 0x00, 0x12, 0x02, 0x00};
    auto r = valkyrie::classifyAdvertisement(adv, sizeof(adv), "");
    EXPECT(r.type == ThreatType::Airtag, "airtag 1A FF 4C 00 12");
}

void test_airtag_runs_before_flipper()
{
    // Apple-ish payload that would match Find My, with a name containing
    // FLIPPER substring. The original code's comment explicitly calls
    // out this false-positive case, so we lock in the order.
    const uint8_t adv[] = {0x1E, 0xFF, 0x4C, 0x00, 0x12, 0x19, 0x10};
    auto r = valkyrie::classifyAdvertisement(adv, sizeof(adv), "MyFlipperZero");
    EXPECT(r.type == ThreatType::Airtag, "airtag wins over flipper-name");
}

void test_flipper_by_name()
{
    auto r1 = valkyrie::classifyAdvertisement(nullptr, 0, "Flipper Zero");
    EXPECT(r1.type == ThreatType::Flipper, "flipper name (mixed case)");
    auto r2 = valkyrie::classifyAdvertisement(nullptr, 0, "FLIPPER123");
    EXPECT(r2.type == ThreatType::Flipper, "flipper name (upper)");
    auto r3 = valkyrie::classifyAdvertisement(nullptr, 0, "flipperX");
    EXPECT(r3.type == ThreatType::Flipper, "flipper name (lower)");
}

void test_flipper_by_manuf()
{
    const uint8_t adv[] = {0x05, 0xFF, 0xBA, 0x0F, 0x01, 0x02};
    auto r = valkyrie::classifyAdvertisement(adv, sizeof(adv), "");
    EXPECT(r.type == ThreatType::Flipper, "flipper 0x0FBA");
}

void test_skimmer_exact_names()
{
    EXPECT(valkyrie::classifyAdvertisement(nullptr, 0, "HC-03").type == ThreatType::HCSkimmer, "HC-03");
    EXPECT(valkyrie::classifyAdvertisement(nullptr, 0, "HC-05").type == ThreatType::HCSkimmer, "HC-05");
    EXPECT(valkyrie::classifyAdvertisement(nullptr, 0, "HC-06").type == ThreatType::HCSkimmer, "HC-06");
    EXPECT(valkyrie::classifyAdvertisement(nullptr, 0, "HC-04").type != ThreatType::HCSkimmer, "HC-04 not");
    EXPECT(valkyrie::classifyAdvertisement(nullptr, 0, "hc-05").type != ThreatType::HCSkimmer,
           "lowercase hc-05 not"); // upstream uses ==, so case-sensitive
}

void test_flock_by_name()
{
    auto r = valkyrie::classifyAdvertisement(nullptr, 0, "FlockSafety-CAM-12");
    EXPECT(r.type == ThreatType::Flock, "flock name");
}

// flock-you OUI 70:c9:4e — canonical MAC order (MSB first).
static const uint8_t kMacFlockOui[] = {0x70, 0xc9, 0x4e, 0xaa, 0xbb, 0xcc};

void test_flock_by_ble_mac_oui()
{
    auto r = valkyrie::classifyAdvertisement(nullptr, 0, "NoSuchName", kMacFlockOui);
    EXPECT(r.type == ThreatType::Flock, "flock BLE MAC OUI");
}

void test_flock_xuntong_empty_name()
{
    // [len=2 flags] [len=3 manuf 0x09C8] — AD lengths are octets after the length byte.
    const uint8_t adv[] = {0x02, 0x01, 0x06, 0x03, 0xFF, 0xC8, 0x09};
    auto r = valkyrie::classifyAdvertisement(adv, sizeof(adv), "", nullptr);
    EXPECT(r.type == ThreatType::Flock, "xuntong + empty name");
}

void test_flock_xuntong_penguin_name()
{
    const uint8_t adv[] = {0x02, 0x01, 0x06, 0x03, 0xFF, 0xC8, 0x09};
    auto r = valkyrie::classifyAdvertisement(adv, sizeof(adv), "Penguin-1234567890", nullptr);
    EXPECT(r.type == ThreatType::Flock, "xuntong + Penguin-##########");
}

void test_flock_xuntong_fs_ext_battery_ci()
{
    const uint8_t adv[] = {0x02, 0x01, 0x06, 0x03, 0xFF, 0xC8, 0x09};
    auto r = valkyrie::classifyAdvertisement(adv, sizeof(adv), "fs ext battery", nullptr);
    EXPECT(r.type == ThreatType::Flock, "xuntong + FS Ext Battery (ci)");
}

void test_flock_xuntong_ten_digit_name()
{
    const uint8_t adv[] = {0x02, 0x01, 0x06, 0x03, 0xFF, 0xC8, 0x09};
    auto r = valkyrie::classifyAdvertisement(adv, sizeof(adv), "1234567890", nullptr);
    EXPECT(r.type == ThreatType::Flock, "xuntong + 10-digit name");
}

void test_flock_xuntong_nonqualifying_name()
{
    const uint8_t adv[] = {0x02, 0x01, 0x06, 0x03, 0xFF, 0xC8, 0x09};
    auto r = valkyrie::classifyAdvertisement(adv, sizeof(adv), "GenericSensor", nullptr);
    EXPECT(r.type == ThreatType::None, "xuntong without Marauder name qualify");
}

void test_flock_ff0105_no_longer_classifies()
{
    const uint8_t adv[] = {0x02, 0x01, 0x06, 0x03, 0xFF, 0x01, 0x05};
    auto r = valkyrie::classifyAdvertisement(adv, sizeof(adv), "Anonymous", nullptr);
    EXPECT(r.type == ThreatType::None, "FF 01 05 sliding match removed");
}

void test_random_advert_no_match()
{
    const uint8_t adv[] = {0x02, 0x01, 0x06, 0x07, 0x09, 'F', 'o', 'o', 'B', 'a', 'r'};
    auto r = valkyrie::classifyAdvertisement(adv, sizeof(adv), "FooBar");
    EXPECT(r.type == ThreatType::None, "random not classified");
}

// ----- Meta smart-glasses (Ray-Ban / Quest) ---------------------------------

void test_smart_glasses_by_manuf_01ab()
{
    // [Flags AD 02 01 06] [len=5 type=FF AB 01 27 16] -- manuf data with
    // company id 0x01AB (Meta), payload bytes from banrays sample capture.
    const uint8_t adv[] = {0x02, 0x01, 0x06, 0x05, 0xFF, 0xAB, 0x01, 0x27, 0x16};
    auto r = valkyrie::classifyAdvertisement(adv, sizeof(adv), "");
    EXPECT(r.type == ThreatType::SmartGlasses, "smart-glasses manuf 0x01AB");
}

void test_smart_glasses_by_uuid_list_complete()
{
    // [len=3 type=03 5F FD] -- complete list of 16-bit Service UUIDs.
    const uint8_t adv[] = {0x02, 0x01, 0x06, 0x03, 0x03, 0x5F, 0xFD};
    auto r = valkyrie::classifyAdvertisement(adv, sizeof(adv), "");
    EXPECT(r.type == ThreatType::SmartGlasses, "smart-glasses svc-UUID list (complete)");
}

void test_smart_glasses_by_uuid_list_incomplete()
{
    // [len=3 type=02 5F FD] -- incomplete list of 16-bit Service UUIDs.
    const uint8_t adv[] = {0x03, 0x02, 0x5F, 0xFD};
    auto r = valkyrie::classifyAdvertisement(adv, sizeof(adv), "");
    EXPECT(r.type == ThreatType::SmartGlasses, "smart-glasses svc-UUID list (incomplete)");
}

void test_smart_glasses_by_service_data()
{
    // [len=5 type=16 5F FD AA BB] -- Service Data 16-bit UUID.
    const uint8_t adv[] = {0x02, 0x01, 0x06, 0x05, 0x16, 0x5F, 0xFD, 0xAA, 0xBB};
    auto r = valkyrie::classifyAdvertisement(adv, sizeof(adv), "");
    EXPECT(r.type == ThreatType::SmartGlasses, "smart-glasses svc-data 0xFD5F");
}

// ----- Drone (ASTM F3411 RemoteID) ------------------------------------------

void test_drone_by_uuid_list()
{
    // [len=3 type=03 FA FF] -- Service UUID 0xFFFA in 16-bit UUID list.
    const uint8_t adv[] = {0x02, 0x01, 0x06, 0x03, 0x03, 0xFA, 0xFF};
    auto r = valkyrie::classifyAdvertisement(adv, sizeof(adv), "");
    EXPECT(r.type == ThreatType::Drone, "drone svc-UUID 0xFFFA list");
}

void test_drone_by_service_data_opendroneid()
{
    // [len=6 type=16 FA FF 0D ..] -- Service Data 0xFFFA with OpenDroneID
    // app code 0x0D and a couple of payload bytes.
    const uint8_t adv[] = {0x02, 0x01, 0x06, 0x06, 0x16, 0xFA, 0xFF, 0x0D, 0x00, 0x12};
    auto r = valkyrie::classifyAdvertisement(adv, sizeof(adv), "");
    EXPECT(r.type == ThreatType::Drone, "drone svc-data 0xFFFA (OpenDroneID)");
}

// ----- Negatives ------------------------------------------------------------

void test_unrelated_uuid_no_match()
{
    // 0xFD60 is adjacent to Meta's 0xFD5F but NOT theirs; ensure we don't
    // match by accidental wildcard.
    const uint8_t adv[] = {0x02, 0x01, 0x06, 0x03, 0x03, 0x60, 0xFD};
    auto r = valkyrie::classifyAdvertisement(adv, sizeof(adv), "");
    EXPECT(r.type == ThreatType::None, "0xFD60 svc-UUID is not smart-glasses");
}

void test_smart_glasses_walker_no_false_positive_in_payload()
{
    // Service Data record (type 0x16, UUID 0x3412) whose data happens to
    // contain the bytes FF AB 01. The TLV walker must NOT reinterpret
    // those payload bytes as a fresh manuf record. (A naive sliding-window
    // search over raw bytes would false-positive here.)
    const uint8_t adv[] = {0x06, 0x16, 0x12, 0x34, 0xFF, 0xAB, 0x01};
    auto r = valkyrie::classifyAdvertisement(adv, sizeof(adv), "");
    EXPECT(r.type == ThreatType::None, "FF AB 01 inside svc-data payload not classified");
}

void test_walker_handles_malformed_length()
{
    // Claims 0x0F bytes follow the type byte but only 1 actually does.
    // Walker must terminate without reading past the buffer.
    const uint8_t adv[] = {0x02, 0x01, 0x06, 0x0F, 0xFF};
    auto r = valkyrie::classifyAdvertisement(adv, sizeof(adv), "");
    EXPECT(r.type == ThreatType::None, "malformed AD length terminates walker");
}

} // namespace

int main()
{
    test_empty_payload_no_match();
    test_airtag_pattern_1e_ff_4c_00();
    test_airtag_pattern_4c_00_12_19();
    test_airtag_extended_1a_ff_4c_00_12();
    test_airtag_runs_before_flipper();
    test_flipper_by_name();
    test_flipper_by_manuf();
    test_skimmer_exact_names();
    test_flock_by_name();
    test_flock_by_ble_mac_oui();
    test_flock_xuntong_empty_name();
    test_flock_xuntong_penguin_name();
    test_flock_xuntong_fs_ext_battery_ci();
    test_flock_xuntong_ten_digit_name();
    test_flock_xuntong_nonqualifying_name();
    test_flock_ff0105_no_longer_classifies();
    test_random_advert_no_match();
    test_smart_glasses_by_manuf_01ab();
    test_smart_glasses_by_uuid_list_complete();
    test_smart_glasses_by_uuid_list_incomplete();
    test_smart_glasses_by_service_data();
    test_drone_by_uuid_list();
    test_drone_by_service_data_opendroneid();
    test_unrelated_uuid_no_match();
    test_smart_glasses_walker_no_false_positive_in_payload();
    test_walker_handles_malformed_length();

    if (g_failures == 0) {
        std::printf("OK: all classifier tests passed\n");
        return 0;
    }
    std::fprintf(stderr, "FAILED: %d classifier tests failed\n", g_failures);
    return 1;
}
