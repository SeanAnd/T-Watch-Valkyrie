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

bool wifi80211IsMulticastMac(const uint8_t mac[6]) { return mac && (mac[0] & 0x01) != 0; }

bool wifi80211IsZeroMac(const uint8_t mac[6])
{
    if (!mac)
        return false;
    static const uint8_t zero[6] = {0, 0, 0, 0, 0, 0};
    return memcmp(mac, zero, 6) == 0;
}

bool wifi80211IsLocallyAdministeredMac(const uint8_t mac[6]) { return mac && (mac[0] & 0x02) != 0; }

bool wifi80211IsWildcardProbeRequest(const uint8_t *frame, size_t len)
{
    uint8_t t, st;
    if (!wifi80211ParseFrameControl(frame, len, &t, &st))
        return false;
    if (t != 0 || st != 4) // Probe Request
        return false;
    if (len < 26)
        return false;
    // IEs start after 24-byte MAC header + 2-byte capability (Probe Req has no
    // duration in fixed? Standard: Mgmt MAC header 24 bytes, then IEs — no fixed
    // fields for Probe Req.)
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
    const bool toDs = (frame[1] & 0x01) != 0;
    const bool fromDs = (frame[1] & 0x02) != 0;
    if (toDs && fromDs)
        hdr += 6;
    // QoS Data subtypes: 0x8, 0x9, 0xa, 0xb (lower nibble 8-11 with type 2)
    if ((subtype & 0x08) != 0)
        hdr += 2;
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

bool wifi80211DataExtractBssidStation(const uint8_t *frame, size_t len, uint8_t bssidOut[6], uint8_t stationOut[6])
{
    if (!bssidOut || !stationOut)
        return false;

    uint8_t t, st;
    if (!wifi80211ParseFrameControl(frame, len, &t, &st) || t != 2)
        return false;
    size_t hdr = wifi80211DataMacHdrLen(frame, len, t, st);
    if (hdr == 0)
        return false;

    uint8_t addr1[6], addr2[6], addr3[6];
    if (!wifi80211CopyAddr123(frame, len, addr1, addr2, addr3))
        return false;

    const bool toDs = (frame[1] & 0x01) != 0;
    const bool fromDs = (frame[1] & 0x02) != 0;
    if (toDs && fromDs)
        return false;

    if (toDs) {
        memcpy(bssidOut, addr1, 6);
        memcpy(stationOut, addr2, 6);
    } else if (fromDs) {
        memcpy(bssidOut, addr2, 6);
        memcpy(stationOut, addr1, 6);
    } else {
        memcpy(bssidOut, addr3, 6);
        if (memcmp(addr1, addr3, 6) == 0)
            memcpy(stationOut, addr2, 6);
        else
            memcpy(stationOut, addr1, 6);
    }

    if (wifi80211IsZeroMac(bssidOut) || wifi80211IsMulticastMac(bssidOut) || wifi80211IsZeroMac(stationOut) ||
        wifi80211IsMulticastMac(stationOut))
        return false;
    return true;
}

bool wifi80211DataExtractEapolInfo(const uint8_t *frame, size_t len, WifiEapolInfo *infoOut)
{
    size_t hdr = 0;
    if (!wifi80211DataHasEapol(frame, len, &hdr))
        return false;

    const size_t eapolOffset = hdr + 8;
    if (len < eapolOffset + 4)
        return false;

    const uint8_t *eapol = frame + eapolOffset;
    const uint8_t version = eapol[0];
    const uint8_t packetType = eapol[1];
    const uint16_t bodyLen = ((uint16_t)eapol[2] << 8) | (uint16_t)eapol[3];
    const size_t availableBody = len - eapolOffset - 4;

    if (version < 1 || version > 3)
        return false;
    if (bodyLen > availableBody)
        return false;

    WifiEapolInfo info{};
    info.macHeaderBytes = hdr;
    info.version = version;
    info.packetType = packetType;
    info.bodyLen = bodyLen;
    info.phase = WifiEapolKeyPhase::None;

    if (packetType == 3) {
        if (bodyLen < 95 || availableBody < 95)
            return false;
        const uint8_t desc = eapol[4];
        if (desc != 1 && desc != 2 && desc != 254)
            return false;

        const uint16_t keyInfo = ((uint16_t)eapol[5] << 8) | (uint16_t)eapol[6];
        const bool pairwise = (keyInfo & 0x0008) != 0;
        const bool install = (keyInfo & 0x0040) != 0;
        const bool ack = (keyInfo & 0x0080) != 0;
        const bool mic = (keyInfo & 0x0100) != 0;
        const bool secure = (keyInfo & 0x0200) != 0;
        const bool error = (keyInfo & 0x0400) != 0;
        const bool request = (keyInfo & 0x0800) != 0;

        info.isKey = true;
        info.descriptorType = desc;
        info.keyInfo = keyInfo;
        info.pairwiseKey = pairwise;
        info.phase = WifiEapolKeyPhase::OtherKey;

        if (pairwise && !error && !request) {
            if (ack && !mic)
                info.phase = WifiEapolKeyPhase::Msg1;
            else if (!ack && mic && !secure)
                info.phase = WifiEapolKeyPhase::Msg2;
            else if (ack && mic && (secure || install))
                info.phase = WifiEapolKeyPhase::Msg3;
            else if (!ack && mic && secure)
                info.phase = WifiEapolKeyPhase::Msg4;
        }
    }

    if (infoOut)
        *infoOut = info;
    return true;
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
    {"Alfa", {0x00, 0xc0, 0xca}, true},       {"Pineapple/Orient", {0x00, 0x13, 0x37}, false},
    {"Hak5", {0x02, 0xc0, 0xca}, false},      {"Hak5", {0x02, 0x13, 0x37}, false},
    {"MediaTek*", {0x00, 0x0c, 0x43}, false}, {"MediaTek*", {0x00, 0x0c, 0xe7}, false},
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

bool wifi80211MgmtRemoteIdNanSignature(const uint8_t *frame, size_t len)
{
    uint8_t t, st;
    if (!wifi80211ParseFrameControl(frame, len, &t, &st) || t != 0)
        return false;
    if (len < 16)
        return false;
    static const uint8_t nanDa[6] = {0x51, 0x6f, 0x9a, 0x01, 0x00, 0x00};
    return memcmp(frame + 4, nanDa, 6) == 0;
}

bool wifi80211BeaconHasRemoteIdVendorIe(const uint8_t *frame, size_t len)
{
    uint8_t t, st;
    if (!wifi80211ParseFrameControl(frame, len, &t, &st) || t != 0 || st != 8)
        return false;
    if (len < 38)
        return false;
    size_t pos = 36;
    while (pos + 2 <= len) {
        uint8_t id = frame[pos];
        uint8_t elen = frame[pos + 1];
        if (pos + 2 + elen > len)
            break;
        if (id == 0xDD && elen >= 8) {
            const uint8_t *d = frame + pos + 2;
            if (d[0] == 0x90 && d[1] == 0x3a && d[2] == 0xe6)
                return true;
            if (d[0] == 0xfa && d[1] == 0x0b && d[2] == 0xbc)
                return true;
        }
        pos += 2 + elen;
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
