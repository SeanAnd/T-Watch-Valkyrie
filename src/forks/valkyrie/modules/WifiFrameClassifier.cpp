#include "WifiFrameClassifier.h"

#include <string.h>

namespace valkyrie
{

bool wifi80211ParseFrameControl(const uint8_t *frame, size_t len, uint8_t *typeOut, uint8_t *subtypeOut)
{
    if (!frame || len < 2 || !typeOut || !subtypeOut)
        return false;
    uint16_t fc = (uint16_t)frame[0] | ((uint16_t)frame[1] << 8);
    *typeOut = (uint8_t)((fc >> 2) & 0x3);
    *subtypeOut = (uint8_t)((fc >> 4) & 0xF);
    return true;
}

bool wifi80211CopyAddr123(const uint8_t *frame, size_t len, uint8_t addr1[6], uint8_t addr2[6], uint8_t addr3[6])
{
    if (!frame || len < 24)
        return false;
    memcpy(addr1, frame + 4, 6);
    memcpy(addr2, frame + 10, 6);
    memcpy(addr3, frame + 16, 6);
    return true;
}

bool wifi80211IsBroadcastMac(const uint8_t mac[6])
{
    if (!mac)
        return false;
    static const uint8_t bcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    return memcmp(mac, bcast, 6) == 0;
}

bool wifi80211IsMulticastMac(const uint8_t mac[6])
{
    return mac && (mac[0] & 0x01) != 0;
}

bool wifi80211IsLocallyAdministeredMac(const uint8_t mac[6])
{
    return mac && (mac[0] & 0x02) != 0;
}

bool wifi80211IsWildcardProbeRequest(const uint8_t *frame, size_t len)
{
    uint8_t t, st;
    if (!wifi80211ParseFrameControl(frame, len, &t, &st))
        return false;
    if (t != 0 || st != 4) // Probe Request
        return false;
    if (len < 26)
        return false;
    // IEs start after 24-byte MAC header + 2-byte capability (Probe Req has no duration in fixed? 
    // Standard: Mgmt MAC header 24 bytes, then IEs — no fixed fields for Probe Req.)
    size_t pos = 24;
    while (pos + 2 <= len) {
        uint8_t id = frame[pos];
        uint8_t elen = frame[pos + 1];
        if (pos + 2 + elen > len)
            break;
        if (id == 0)
            return elen == 0; // SSID wildcard
        pos += 2 + elen;
    }
    return false;
}

bool wifi80211MgmtIsDeauthDisassoc(const uint8_t *frame, size_t len)
{
    uint8_t t, st;
    if (!wifi80211ParseFrameControl(frame, len, &t, &st))
        return false;
    return t == 0 && (st == 0x0A || st == 0x0C);
}

static size_t wifi80211DataMacHdrLen(const uint8_t *frame, size_t len, uint8_t type, uint8_t subtype)
{
    (void)type;
    size_t hdr = 24;
    // QoS Data subtypes: 0x8, 0x9, 0xa, 0xb (lower nibble 8-11 with type 2)
    if ((subtype & 0x08) != 0 && len >= 26)
        hdr = 26;
    // 4-address not handled (rare for our sniff use)
    return hdr <= len ? hdr : 0;
}

bool wifi80211DataHasEapol(const uint8_t *frame, size_t len, size_t *hdrBytesOut)
{
    uint8_t t, st;
    if (!wifi80211ParseFrameControl(frame, len, &t, &st))
        return false;
    if (t != 2) // Data
        return false;
    size_t hdr = wifi80211DataMacHdrLen(frame, len, t, st);
    if (hdr == 0 || len < hdr + 8)
        return false;
    const uint8_t *llc = frame + hdr;
    bool ok = llc[0] == 0xAA && llc[1] == 0xAA && llc[2] == 0x03 && llc[3] == 0 && llc[4] == 0 && llc[5] == 0 &&
              llc[6] == 0x88 && llc[7] == 0x8E;
    if (hdrBytesOut)
        *hdrBytesOut = hdr;
    return ok;
}

bool wifi80211BeaconExtractSsidAndPrivacy(const uint8_t *frame, size_t len, char *ssidOut, size_t ssidCap,
                                          bool *privacyOnOut)
{
    uint8_t t, st;
    if (!wifi80211ParseFrameControl(frame, len, &t, &st) || t != 0 || st != 8)
        return false; // Beacon
    if (len < 38)
        return false;
    uint16_t cap = (uint16_t)frame[34] | ((uint16_t)frame[35] << 8);
    if (privacyOnOut)
        *privacyOnOut = (cap & 0x0010) != 0;

    if (ssidOut && ssidCap > 0)
        ssidOut[0] = '\0';

    size_t pos = 36; // IEs
    while (pos + 2 <= len) {
        uint8_t id = frame[pos];
        uint8_t elen = frame[pos + 1];
        if (pos + 2 + elen > len)
            break;
        if (id == 0 && ssidOut && ssidCap > 0) {
            size_t copy = elen < ssidCap - 1 ? elen : ssidCap - 1;
            memcpy(ssidOut, frame + pos + 2, copy);
            ssidOut[copy] = '\0';
            return true;
        }
        pos += 2 + elen;
    }
    return true; // beacon parsed; SSID may be missing / hidden
}

uint16_t wifi80211HashSsidBytes(const uint8_t *ssid, size_t ssidLen)
{
    uint16_t h = 5381;
    for (size_t i = 0; i < ssidLen; ++i)
        h = (uint16_t)((h << 5) + h + ssid[i]);
    return h == 0 ? 1 : h;
}

namespace
{
struct SuspiciousVendor {
    const char *label;
    uint8_t oui[3];
    bool onlyWhenOpen;
};

static const SuspiciousVendor kSus[] = {
    {"Alfa", {0x00, 0xc0, 0xca}, true},
    {"Pineapple/Orient", {0x00, 0x13, 0x37}, false},
    {"Hak5", {0x02, 0xc0, 0xca}, false},
    {"Hak5", {0x02, 0x13, 0x37}, false},
    {"MediaTek*", {0x00, 0x0c, 0x43}, false},
    {"MediaTek*", {0x00, 0x0c, 0xe7}, false},
};

} // namespace

bool wifi80211MacMatchesSuspiciousVendorOui(const uint8_t mac[6], bool privacyOn, const char **vendorLabelOut)
{
    if (!mac)
        return false;
    for (size_t i = 0; i < sizeof(kSus) / sizeof(kSus[0]); ++i) {
        if (memcmp(mac, kSus[i].oui, 3) != 0)
            continue;
        if (kSus[i].onlyWhenOpen && privacyOn)
            continue;
        if (vendorLabelOut)
            *vendorLabelOut = kSus[i].label;
        return true;
    }
    return false;
}

bool wifi80211BeaconLooksLikePwnagotchi(const uint8_t *frame, size_t len)
{
    uint8_t t, st;
    if (!wifi80211ParseFrameControl(frame, len, &t, &st) || t != 0 || st != 8)
        return false;
    if (len <= 36)
        return false;
    const char *blob = reinterpret_cast<const char *>(frame + 36);
    size_t blobLen = len - 36;
    const char *p1 = "pwnd_tot";
    const char *p2 = "\"name\"";
    auto findSub = [&](const char *pat) -> bool {
        size_t pl = strlen(pat);
        if (blobLen < pl)
            return false;
        for (size_t i = 0; i + pl <= blobLen; ++i) {
            if (memcmp(blob + i, pat, pl) == 0)
                return true;
        }
        return false;
    };
    return findSub(p1) && findSub(p2);
}

} // namespace valkyrie
