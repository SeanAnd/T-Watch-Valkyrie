// Native unit tests for valkyrie Wi‑Fi 802.11 helpers
// (WifiFrameClassifier.cpp).
//
// Build & run:
//   c++ -std=gnu++17 -O0 -g ../modules/WifiFrameClassifier.cpp
//   test_wifi_frame_classifier.cpp -o /tmp/valkyrie_wifi_test &&
//   /tmp/valkyrie_wifi_test

#include "../modules/FlockOuiTable.h"
#include "../modules/WifiFrameClassifier.h"

#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>

namespace
{

int g_failures = 0;

#define EXPECT(cond, msg)                                                                                              \
    do {                                                                                                               \
        if (!(cond)) {                                                                                                 \
            std::fprintf(stderr, "FAIL: %s (line %d)\n", (msg), __LINE__);                                             \
            ++g_failures;                                                                                              \
        }                                                                                                              \
    } while (0)

void build_probe_wildcard(uint8_t *out, size_t cap)
{
    // FC: type 0 mgmt, subtype 4 probe req -> fc = 0x0040 little-endian -> 40 00
    memset(out, 0, cap);
    out[0] = 0x40;
    out[1] = 0x00;
    // DA broadcast, SA flock OUI + trailing
    static const uint8_t da[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    static const uint8_t sa[6] = {0x70, 0xc9, 0x4e, 0x01, 0x02, 0x03};
    memcpy(out + 4, da, 6);
    memcpy(out + 10, sa, 6);
    memcpy(out + 16, da, 6); // BSSID broadcast
    // SSID IE tag 0 len 0 at offset 24
    out[24] = 0;
    out[25] = 0;
}

void test_wildcard_probe_flock_sa()
{
    uint8_t buf[64];
    build_probe_wildcard(buf, sizeof(buf));
    EXPECT(valkyrie::wifi80211IsWildcardProbeRequest(buf, 26), "wildcard probe");
    EXPECT(valkyrie::macMatchesFlockInfraOui(buf + 10), "SA flock OUI");
}

void test_deauth_subtype()
{
    uint8_t buf[32]{};
    buf[0] = 0xC0; // mgmt + deauth subtype 12 -> check: type0 subtype C -> fc =
                   // subtype<<4 -> 0x00C0?
    // Frame control: bits 2-3 type, 4-7 subtype. type=0 subtype=12 (0xC) -> fc =
    // (12<<4) = 0x00C0 -> low byte 0xC0
    buf[1] = 0x00;
    EXPECT(valkyrie::wifi80211MgmtIsDeauthDisassoc(buf, 24), "deauth fc");
}

void test_addr1_filter_broadcast()
{
    uint8_t bcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    EXPECT(valkyrie::wifi80211IsBroadcastMac(bcast), "bcast");
    uint8_t mcast[6] = {0x01, 0x00, 0x00, 0x00, 0x00, 0x00};
    EXPECT(valkyrie::wifi80211IsMulticastMac(mcast), "mcast");
    uint8_t rnd[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x00};
    EXPECT(valkyrie::wifi80211IsLocallyAdministeredMac(rnd), "local admin");
}

void test_eapol_llc()
{
    uint8_t buf[64]{};
    buf[0] = 0x08; // data QoS? type 2 subtype 8 -> fc bytes — simplified: use
                   // type 2 subtype 0 data
    buf[0] = 0x02; // version/protocol — wrong
    // Build proper data frame: Type 2 Data, subtype 0 -> FC = 0x0208? Standard
    // Data subtype 0: bits type=10 binary =2, subtype=0000 fc = subtype<<4 |
    // type<<2 -> for Data frame Type=2 (binary 10) Subtype 0: In wireshark: Data
    // frame 0x0802 for FromDS - skip — use pattern from Bruce: type 2 subtype 8
    // QoS data
    buf[0] = 0x88;
    buf[1] = 0x00;
    memset(buf + 4, 0xAA, 6 * 3); // addrs
    // LLC at offset 26 for QoS
    buf[26] = 0xAA;
    buf[27] = 0xAA;
    buf[28] = 0x03;
    buf[29] = 0;
    buf[30] = 0;
    buf[31] = 0;
    buf[32] = 0x88;
    buf[33] = 0x8E;
    size_t hdr = 0;
    EXPECT(valkyrie::wifi80211DataHasEapol(buf, 40, &hdr), "eapol qos data");
    EXPECT(hdr == 26, "qos hdr 26");
    EXPECT(!valkyrie::wifi80211DataExtractEapolInfo(buf, 40, nullptr), "bare eapol ethertype is not sane key frame");
}

void build_qos_eapol_key(uint8_t *buf, size_t cap, uint16_t keyInfo, bool fromDs)
{
    memset(buf, 0, cap);
    buf[0] = 0x88;                 // QoS data
    buf[1] = fromDs ? 0x02 : 0x01; // FromDS or ToDS
    static const uint8_t ap[6] = {0x10, 0x22, 0x33, 0x44, 0x55, 0x66};
    static const uint8_t sta[6] = {0x20, 0x30, 0x40, 0x50, 0x60, 0x70};
    if (fromDs) {
        memcpy(buf + 4, sta, 6); // DA / RA
        memcpy(buf + 10, ap, 6); // BSSID / TA
        memcpy(buf + 16, ap, 6);
    } else {
        memcpy(buf + 4, ap, 6);   // BSSID / RA
        memcpy(buf + 10, sta, 6); // SA / TA
        memcpy(buf + 16, ap, 6);
    }

    size_t pos = 26;
    buf[pos + 0] = 0xAA;
    buf[pos + 1] = 0xAA;
    buf[pos + 2] = 0x03;
    buf[pos + 3] = 0;
    buf[pos + 4] = 0;
    buf[pos + 5] = 0;
    buf[pos + 6] = 0x88;
    buf[pos + 7] = 0x8E;

    uint8_t *eapol = buf + pos + 8;
    eapol[0] = 2; // 802.1X-2004
    eapol[1] = 3; // EAPOL-Key
    eapol[2] = 0;
    eapol[3] = 95;
    eapol[4] = 2; // RSN key descriptor
    eapol[5] = (uint8_t)(keyInfo >> 8);
    eapol[6] = (uint8_t)(keyInfo & 0xFF);
}

void test_eapol_key_sanity_and_pair()
{
    uint8_t buf[160]{};
    constexpr size_t frameLen = 26 + 8 + 4 + 95;
    build_qos_eapol_key(buf, sizeof(buf), 0x008a, true);

    valkyrie::WifiEapolInfo info{};
    EXPECT(valkyrie::wifi80211DataExtractEapolInfo(buf, frameLen, &info), "strict eapol key");
    EXPECT(info.isKey, "eapol key marked");
    EXPECT(info.pairwiseKey, "eapol pairwise key");
    EXPECT(info.phase == valkyrie::WifiEapolKeyPhase::Msg1, "eapol msg1 phase");

    uint8_t bssid[6]{};
    uint8_t sta[6]{};
    EXPECT(valkyrie::wifi80211DataExtractBssidStation(buf, frameLen, bssid, sta), "fromds pair extracted");
    static const uint8_t ap[6] = {0x10, 0x22, 0x33, 0x44, 0x55, 0x66};
    static const uint8_t client[6] = {0x20, 0x30, 0x40, 0x50, 0x60, 0x70};
    EXPECT(memcmp(bssid, ap, 6) == 0, "fromds bssid");
    EXPECT(memcmp(sta, client, 6) == 0, "fromds station");

    build_qos_eapol_key(buf, sizeof(buf), 0x010a, false);
    EXPECT(valkyrie::wifi80211DataExtractEapolInfo(buf, frameLen, &info), "todS eapol key");
    EXPECT(info.phase == valkyrie::WifiEapolKeyPhase::Msg2, "eapol msg2 phase");
    EXPECT(valkyrie::wifi80211DataExtractBssidStation(buf, frameLen, bssid, sta), "tods pair extracted");
    EXPECT(memcmp(bssid, ap, 6) == 0, "tods bssid");
    EXPECT(memcmp(sta, client, 6) == 0, "tods station");
}

void test_eapol_rejects_malformed()
{
    uint8_t buf[160]{};
    constexpr size_t frameLen = 26 + 8 + 4 + 95;
    build_qos_eapol_key(buf, sizeof(buf), 0x008a, true);
    buf[34] = 0;
    EXPECT(!valkyrie::wifi80211DataExtractEapolInfo(buf, frameLen, nullptr), "reject bad eapol version");

    build_qos_eapol_key(buf, sizeof(buf), 0x008a, true);
    buf[36] = 0x01;
    buf[37] = 0x00;
    EXPECT(!valkyrie::wifi80211DataExtractEapolInfo(buf, frameLen, nullptr), "reject truncated eapol body");
}

void test_beacon_ssid_open()
{
    uint8_t buf[128]{};
    buf[0] = 0x80;
    buf[1] = 0x00;
    // addr1 bcast addr2 AP addr3 AP
    memset(buf + 4, 0xFF, 6);
    static const uint8_t ap[6] = {0x00, 0x13, 0x37, 0x01, 0x02, 0x03};
    memcpy(buf + 10, ap, 6);
    memcpy(buf + 16, ap, 6);
    // timestamp 8, interval 2, caps 2 (open = privacy bit clear)
    memset(buf + 24, 0, 8);
    buf[32] = 0x64;
    buf[33] = 0x00;
    buf[34] = 0x00;
    buf[35] = 0x00;
    // SSID IE "test"
    buf[36] = 0;
    buf[37] = 4;
    memcpy(buf + 38, "test", 4);
    char ssid[16]{};
    bool priv = true;
    EXPECT(valkyrie::wifi80211BeaconExtractSsidAndPrivacy(buf, 42, ssid, sizeof(ssid), &priv), "beacon parse");
    EXPECT(strcmp(ssid, "test") == 0, "ssid match");
    EXPECT(!priv, "open ap");
}

void test_multissid_hash_distinct()
{
    uint16_t h1 = valkyrie::wifi80211HashSsidBytes((const uint8_t *)"a", 1);
    uint16_t h2 = valkyrie::wifi80211HashSsidBytes((const uint8_t *)"b", 1);
    EXPECT(h1 != h2, "hash differs");
}

void test_remoteid_nan_signature()
{
    uint8_t buf[64]{};
    buf[0] = 0xD0; // mgmt + action
    buf[1] = 0x00;
    static const uint8_t nanDa[6] = {0x51, 0x6f, 0x9a, 0x01, 0x00, 0x00};
    memcpy(buf + 4, nanDa, 6);
    memset(buf + 10, 0xAA, 6);
    memset(buf + 16, 0xBB, 6);
    EXPECT(valkyrie::wifi80211MgmtRemoteIdNanSignature(buf, 24), "NAN RemoteID dest MAC");
    buf[4] = 0xFF;
    EXPECT(!valkyrie::wifi80211MgmtRemoteIdNanSignature(buf, 24), "wrong DA rejects");
}

void test_remoteid_beacon_vendor_ie()
{
    uint8_t buf[128]{};
    buf[0] = 0x80;
    buf[1] = 0x00;
    memset(buf + 4, 0xFF, 6);
    static const uint8_t ap[6] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
    memcpy(buf + 10, ap, 6);
    memcpy(buf + 16, ap, 6);
    memset(buf + 24, 0, 8);
    buf[32] = 0x64;
    buf[33] = 0x00;
    buf[34] = 0x00;
    buf[35] = 0x00;
    // SSID IE len 0 (hidden)
    buf[36] = 0;
    buf[37] = 0;
    // Vendor IE 0xDD: OUI 90:3a:e6 + type + padding
    buf[38] = 0xDD;
    buf[39] = 8;
    buf[40] = 0x90;
    buf[41] = 0x3a;
    buf[42] = 0xe6;
    buf[43] = 0;
    memset(buf + 44, 0, 5);
    EXPECT(valkyrie::wifi80211BeaconHasRemoteIdVendorIe(buf, 49), "beacon ASTM vendor OUI");
    buf[40] = 0xfa;
    buf[41] = 0x0b;
    buf[42] = 0xbc;
    EXPECT(valkyrie::wifi80211BeaconHasRemoteIdVendorIe(buf, 49), "beacon alt vendor OUI");
    buf[40] = 0x00;
    EXPECT(!valkyrie::wifi80211BeaconHasRemoteIdVendorIe(buf, 49), "wrong OUI rejects");
}

} // namespace

int main()
{
    test_wildcard_probe_flock_sa();
    test_deauth_subtype();
    test_addr1_filter_broadcast();
    test_eapol_llc();
    test_eapol_key_sanity_and_pair();
    test_eapol_rejects_malformed();
    test_beacon_ssid_open();
    test_multissid_hash_distinct();
    test_remoteid_nan_signature();
    test_remoteid_beacon_vendor_ie();
    if (g_failures == 0)
        std::printf("All WiFi frame classifier tests passed.\n");
    else
        std::fprintf(stderr, "%d test(s) failed.\n", g_failures);
    return g_failures ? 1 : 0;
}
