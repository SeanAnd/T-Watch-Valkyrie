#include "BleClassifier.h"

#include <ctype.h>
#include <stddef.h>
#include <string.h>

namespace valkyrie
{

namespace
{

// Like strstr but case-insensitive over ASCII. Returns true if `needle`
// (NUL-terminated, uppercase) appears anywhere in `haystack` ignoring
// haystack's case. Both args may be NULL/empty.
bool icontains(const char *haystack, const char *needleUpper)
{
    if (!haystack || !needleUpper || !*needleUpper)
        return false;
    size_t needleLen = strlen(needleUpper);
    for (size_t i = 0; haystack[i]; ++i) {
        size_t j = 0;
        while (j < needleLen && haystack[i + j] && (char)toupper((unsigned char)haystack[i + j]) == needleUpper[j]) {
            ++j;
        }
        if (j == needleLen)
            return true;
    }
    return false;
}

void setDetail(ClassificationResult &out, const char *s)
{
    if (!s)
        s = "";
    strncpy(out.detail, s, sizeof(out.detail) - 1);
    out.detail[sizeof(out.detail) - 1] = '\0';
}

bool detectAirtag(const uint8_t *p, size_t len, const char *&detailOut)
{
    if (!p || len < 4)
        return false;
    for (size_t i = 0; i + 4 <= len; ++i) {
        // Standard Find My network header: 1E FF 4C 00
        if (p[i] == 0x1E && p[i + 1] == 0xFF && p[i + 2] == 0x4C && p[i + 3] == 0x00) {
            detailOut = "Apple Find My (1E FF 4C 00)";
            return true;
        }
        // Alternative pattern: 4C 00 12 19
        if (p[i] == 0x4C && p[i + 1] == 0x00 && p[i + 2] == 0x12 && p[i + 3] == 0x19) {
            detailOut = "Apple Find My (4C 00 12 19)";
            return true;
        }
        // Extended Find My: length 1A, type FF, company 00 4C, type 12
        if (i + 5 <= len && p[i] == 0x1A && p[i + 1] == 0xFF && p[i + 2] == 0x4C && p[i + 3] == 0x00 && p[i + 4] == 0x12) {
            detailOut = "Apple Find My (1A FF 4C 00 12)";
            return true;
        }
        // Manuf 0x004C followed by a Find My payload type (0x12, 0x10, 0x0F).
        if (i + 5 <= len && p[i] == 0xFF && p[i + 1] == 0x4C && p[i + 2] == 0x00) {
            if (i + 4 < len && (p[i + 3] == 0x12 || p[i + 3] == 0x10 || p[i + 3] == 0x0F)) {
                detailOut = "Apple Find My (FF 4C 00 12/10/0F)";
                return true;
            }
        }
    }
    return false;
}

bool detectFlipperByManuf(const uint8_t *p, size_t len, const char *&detailOut)
{
    if (!p || len < 5)
        return false;
    for (size_t i = 0; i + 5 <= len; ++i) {
        // Manufacturer data: type FF, then company-id LSB MSB.
        // Flipper's company ID 0x0FBA -> BA 0F little-endian.
        if (p[i] == 0xFF && p[i + 1] == 0xBA && p[i + 2] == 0x0F) {
            detailOut = "manuf 0x0FBA (Flipper)";
            return true;
        }
    }
    return false;
}

// First 3 bytes of BLE public / static addresses for Flock Safety
// infrastructure radios — same 31-prefix set as colonelpanichacks/flock-you
// WiFi detector (README, NitekryDPaul + DeFlockJoplin 82:6b:f2).
static const uint8_t kFlockOui[][3] = {
    {0x70, 0xc9, 0x4e}, {0x3c, 0x91, 0x80}, {0xd8, 0xf3, 0xbc}, {0x80, 0x30, 0x49}, {0xb8, 0x35, 0x32}, {0x14, 0x5a, 0xfc},
    {0x74, 0x4c, 0xa1}, {0x08, 0x3a, 0x88}, {0x9c, 0x2f, 0x9d}, {0xc0, 0x35, 0x32}, {0x94, 0x08, 0x53}, {0xe4, 0xaa, 0xea},
    {0xf4, 0x6a, 0xdd}, {0xf8, 0xa2, 0xd6}, {0x24, 0xb2, 0xb9}, {0x00, 0xf4, 0x8d}, {0xd0, 0x39, 0x57}, {0xe8, 0xd0, 0xfc},
    {0xe0, 0x4f, 0x43}, {0xb8, 0x1e, 0xa4}, {0x70, 0x08, 0x94}, {0x58, 0x8e, 0x81}, {0xec, 0x1b, 0xbd}, {0x3c, 0x71, 0xbf},
    {0x58, 0x00, 0xe3}, {0x90, 0x35, 0xea}, {0x5c, 0x93, 0xa2}, {0x64, 0x6e, 0x69}, {0x48, 0x27, 0xea}, {0xa4, 0xcf, 0x12},
    {0x82, 0x6b, 0xf2},
};

bool macMatchesFlockOui(const uint8_t *mac)
{
    if (!mac)
        return false;
    for (size_t i = 0; i < sizeof(kFlockOui) / sizeof(kFlockOui[0]); ++i) {
        if (memcmp(mac, kFlockOui[i], 3) == 0)
            return true;
    }
    return false;
}

// Name qualifiers for XUNTONG manuf, mirroring ESP32Marauder WiFiScan::isFlockCamera.
bool flockBleNameQualifiesWithXuntong(const char *name)
{
    const char *n = name ? name : "";
    if (!n[0])
        return true;

    if (strncmp(n, "Penguin-", 8) == 0) {
        size_t L = strlen(n);
        if (L != 18)
            return false;
        for (size_t i = 8; i < 18; ++i) {
            if (n[i] < '0' || n[i] > '9')
                return false;
        }
        return true;
    }

    static const char kFsExt[] = "FS Ext Battery";
    size_t nlen = strlen(n);
    if (nlen == sizeof(kFsExt) - 1) {
        bool match = true;
        for (size_t i = 0; kFsExt[i]; ++i) {
            if ((char)toupper((unsigned char)n[i]) != (char)toupper((unsigned char)kFsExt[i])) {
                match = false;
                break;
            }
        }
        if (match)
            return true;
    }

    if (nlen == 10) {
        for (size_t i = 0; i < 10; ++i) {
            if (n[i] < '0' || n[i] > '9')
                return false;
        }
        return true;
    }

    return false;
}

// Walk Bluetooth advertising data records `[len][type][data...]` where
// `len` covers the type byte plus the data (BLE Core 5.4, Vol 3, Part C,
// Sec 11). Each record is yielded to `fn(adType, data, dataLen)`; the
// walk stops as soon as fn returns true and forwards that result.
//
// We do this proper TLV walk for SmartGlasses / Drone because both rules
// match on Service-UUID-list (AD type 0x02/0x03) and Service-Data (0x16)
// records — a sliding-window byte search would false-positive on
// arbitrary payload bytes that happen to contain 5F FD or FA FF.
template <typename Fn> bool walkAdRecords(const uint8_t *p, size_t len, Fn fn)
{
    if (!p)
        return false;
    size_t i = 0;
    while (i < len) {
        uint8_t adLen = p[i];
        if (adLen == 0)
            break; // zero length terminates the record list
        if (i + 1 + (size_t)adLen > len)
            break; // record runs past end of buffer
        uint8_t adType = p[i + 1];
        const uint8_t *adData = p + i + 2;
        size_t adDataLen = (size_t)adLen - 1;
        if (fn(adType, adData, adDataLen))
            return true;
        i += 1 + (size_t)adLen;
    }
    return false;
}

bool hasXuntongManufacturer(const uint8_t *p, size_t len)
{
    // BLE company ID 0x09C8 (XUNTONG), little-endian after AD type 0xFF.
    return walkAdRecords(p, len, [](uint8_t adType, const uint8_t *data, size_t dataLen) -> bool {
        return adType == 0xFF && dataLen >= 2 && data[0] == 0xc8 && data[1] == 0x09;
    });
}

// Meta Ray-Ban / Quest fingerprint, ported from NullPxl/banrays README
// and Marauder's `sniffbt -t meta` filter:
//   - Manufacturer Specific Data (AD type 0xFF) with company ID 0x01AB
//   - Complete/Incomplete 16-bit Service UUID list (0x02/0x03) with 0xFD5F
//   - Service Data 16-bit UUID (0x16) starting with 0xFD5F
bool detectSmartGlasses(const uint8_t *p, size_t len, const char *&detailOut)
{
    return walkAdRecords(p, len, [&](uint8_t adType, const uint8_t *data, size_t dataLen) -> bool {
        if (adType == 0xFF && dataLen >= 2 && data[0] == 0xAB && data[1] == 0x01) {
            detailOut = "manuf 0x01AB (Meta)";
            return true;
        }
        if ((adType == 0x02 || adType == 0x03) && dataLen >= 2) {
            for (size_t j = 0; j + 2 <= dataLen; j += 2) {
                if (data[j] == 0x5F && data[j + 1] == 0xFD) {
                    detailOut = "svc 0xFD5F (Meta)";
                    return true;
                }
            }
        }
        if (adType == 0x16 && dataLen >= 2 && data[0] == 0x5F && data[1] == 0xFD) {
            detailOut = "svcdata 0xFD5F (Meta)";
            return true;
        }
        return false;
    });
}

// ASTM F3411 RemoteID fingerprint per colonelpanichacks/Sky-Spy: drones
// subject to FAA Remote ID broadcast on Service UUID 0xFFFA over BLE.
//   - 16-bit Service UUID list (0x02/0x03) containing 0xFFFA
//   - Service Data 16-bit UUID (0x16) starting with 0xFFFA (OpenDroneID
//     payload follows; we report presence only, no telemetry parsing until later phases)
bool detectDroneRemoteId(const uint8_t *p, size_t len, const char *&detailOut)
{
    return walkAdRecords(p, len, [&](uint8_t adType, const uint8_t *data, size_t dataLen) -> bool {
        if ((adType == 0x02 || adType == 0x03) && dataLen >= 2) {
            for (size_t j = 0; j + 2 <= dataLen; j += 2) {
                if (data[j] == 0xFA && data[j + 1] == 0xFF) {
                    detailOut = "svc 0xFFFA (RemoteID)";
                    return true;
                }
            }
        }
        if (adType == 0x16 && dataLen >= 2 && data[0] == 0xFA && data[1] == 0xFF) {
            detailOut = "svcdata 0xFFFA (RemoteID)";
            return true;
        }
        return false;
    });
}

bool nameEqualsAny(const char *name, const char *const *list, size_t count)
{
    if (!name)
        return false;
    for (size_t i = 0; i < count; ++i) {
        if (strcmp(name, list[i]) == 0)
            return true;
    }
    return false;
}

} // namespace

ClassificationResult classifyAdvertisement(const uint8_t *payload, size_t payloadLen, const char *name, const uint8_t *mac)
{
    ClassificationResult r{};
    r.type = ThreatType::None;
    r.detail[0] = '\0';

    // --- 1. AirTag / Find My (must run first to avoid false-positive Flipper). ---
    const char *detail = nullptr;
    if (detectAirtag(payload, payloadLen, detail)) {
        r.type = ThreatType::Airtag;
        setDetail(r, detail ? detail : "Apple tracker");
        return r;
    }

    // --- 2. Flipper Zero by name (most reliable). ---
    if (icontains(name, "FLIPPER")) {
        r.type = ThreatType::Flipper;
        setDetail(r, "name contains FLIPPER");
        return r;
    }

    // --- 3. Flipper Zero by manufacturer ID 0x0FBA. ---
    detail = nullptr;
    if (detectFlipperByManuf(payload, payloadLen, detail)) {
        r.type = ThreatType::Flipper;
        setDetail(r, detail ? detail : "Flipper Zero");
        return r;
    }

    // --- 4. HC-* skimmer (exact device name match). ---
    static const char *kSkimmerNames[] = {"HC-03", "HC-05", "HC-06"};
    if (nameEqualsAny(name, kSkimmerNames, sizeof(kSkimmerNames) / sizeof(kSkimmerNames[0]))) {
        r.type = ThreatType::HCSkimmer;
        setDetail(r, name); // record which exact model matched
        return r;
    }

    // --- 5. Flock camera: name substring (broad). ---
    if (icontains(name, "FLOCK")) {
        r.type = ThreatType::Flock;
        setDetail(r, "name contains FLOCK");
        return r;
    }

    // --- 6. Flock: BLE MAC OUI (flock-you 31-prefix list). ---
    if (mac && macMatchesFlockOui(mac)) {
        r.type = ThreatType::Flock;
        setDetail(r, "OUI flock-you list");
        return r;
    }

    // --- 7. Flock: XUNTONG manuf 0x09C8 + Marauder name heuristics. ---
    if (payload && hasXuntongManufacturer(payload, payloadLen) && flockBleNameQualifiesWithXuntong(name)) {
        r.type = ThreatType::Flock;
        setDetail(r, "manuf 0x09C8 (Flock)");
        return r;
    }

    // --- 8. Meta smart-glasses (Ray-Ban / Quest) via manuf 0x01AB or service 0xFD5F. ---
    detail = nullptr;
    if (detectSmartGlasses(payload, payloadLen, detail)) {
        r.type = ThreatType::SmartGlasses;
        setDetail(r, detail ? detail : "Meta device");
        return r;
    }

    // --- 9. Drone (ASTM F3411 RemoteID via service 0xFFFA). ---
    detail = nullptr;
    if (detectDroneRemoteId(payload, payloadLen, detail)) {
        r.type = ThreatType::Drone;
        setDetail(r, detail ? detail : "RemoteID broadcast");
        return r;
    }

    return r;
}

} // namespace valkyrie
