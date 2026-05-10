#include "ThreatLogDecode.h"

#include "../ThreatTypeUi.h"

#include <cctype>
#include <cstdlib>
#include <cstring>
#include <cstdio>

namespace valkyrie::threatlog_decode
{

namespace
{

int hexValue(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'A' && c <= 'F')
        return 10 + c - 'A';
    if (c >= 'a' && c <= 'f')
        return 10 + c - 'a';
    return -1;
}

void trimField(char *s)
{
    if (!s || !*s)
        return;
    char *start = s;
    while (*start && std::isspace((unsigned char)*start))
        ++start;
    if (start != s)
        std::memmove(s, start, std::strlen(start) + 1);
    size_t L = std::strlen(s);
    while (L > 0 && std::isspace((unsigned char)s[L - 1]))
        s[--L] = '\0';
}

bool fieldIsAllDigits(const char *f)
{
    if (!f || !*f)
        return false;
    for (const char *p = f; *p; ++p) {
        if (!std::isdigit((unsigned char)*p))
            return false;
    }
    return true;
}

} // namespace

bool macFieldToBytes(const char *macIn, uint8_t out[6])
{
    int nybbles[12];
    int n = 0;
    for (const char *p = macIn; *p != '\0' && n < 12; ++p) {
        if (*p == ':' || *p == '-' || *p == '.')
            continue;
        int v = hexValue(*p);
        if (v < 0)
            continue;
        nybbles[n++] = v;
    }
    if (n != 12)
        return false;
    for (int i = 0; i < 6; ++i)
        out[i] = (uint8_t)((nybbles[i * 2] << 4) | nybbles[i * 2 + 1]);
    return true;
}

ThreatType wireTokenToThreatType(const char *tok)
{
    for (unsigned u = 1; u <= 11; ++u) {
        ThreatType t = static_cast<ThreatType>((uint8_t)u);
        if (std::strcmp(tok, valkyrie::threatTypeWireName(t)) == 0)
            return t;
    }
    return ThreatType::None;
}

ThreatSource inferSourceFromType(ThreatType t)
{
    uint8_t v = static_cast<uint8_t>(t);
    return (v >= 7 && v <= 11) ? ThreatSource::Wifi : ThreatSource::Ble;
}

bool parseThreatCsvPrefix(const char *line, const char **wireTypeOut, const char **macFieldOut, char *buf1, size_t n1,
                          char *buf2, size_t n2, char *buf3, size_t n3)
{
    const char *c1 = std::strchr(line, ',');
    if (!c1)
        return false;
    const char *c2 = std::strchr(c1 + 1, ',');
    if (!c2)
        return false;
    const char *c3 = std::strchr(c2 + 1, ',');
    if (!c3)
        return false;

    size_t l1 = (size_t)(c1 - line);
    size_t l2 = (size_t)(c2 - c1 - 1);
    size_t l3 = (size_t)(c3 - c2 - 1);
    if (l1 >= n1 || l2 >= n2 || l3 >= n3)
        return false;

    std::memcpy(buf1, line, l1);
    buf1[l1] = '\0';
    std::memcpy(buf2, c1 + 1, l2);
    buf2[l2] = '\0';
    std::memcpy(buf3, c2 + 1, l3);
    buf3[l3] = '\0';
    trimField(buf1);
    trimField(buf2);
    trimField(buf3);

    if (fieldIsAllDigits(buf1)) {
        *wireTypeOut = buf2;
        *macFieldOut = buf3;
    } else {
        *wireTypeOut = buf1;
        *macFieldOut = buf3;
    }
    return true;
}

bool extractTrailingSourceAndChannel(const char *line, ThreatSource *sourceOut, uint8_t *channelOut)
{
    if (!line || !sourceOut || !channelOut)
        return false;
    size_t len = std::strlen(line);
    while (len > 0) {
        char c = line[len - 1];
        if (c == '\r' || c == '\n' || c == ' ' || c == '\t')
            --len;
        else
            break;
    }
    if (len == 0)
        return false;

    // Source/channel are unquoted plain text at the very end. Scan from the end for the
    // last two commas; the quoted name/detail before them may contain commas but never
    // appear after the final two unquoted fields.
    size_t lastComma = (size_t)-1;
    for (size_t i = len; i-- > 0;) {
        if (line[i] == ',') {
            lastComma = i;
            break;
        }
    }
    if (lastComma == (size_t)-1)
        return false;
    size_t secondLast = (size_t)-1;
    for (size_t i = lastComma; i-- > 0;) {
        if (line[i] == ',') {
            secondLast = i;
            break;
        }
    }
    if (secondLast == (size_t)-1)
        return false;

    char srcBuf[8] = {0};
    size_t srcLen = lastComma - (secondLast + 1);
    if (srcLen == 0 || srcLen >= sizeof(srcBuf))
        return false;
    std::memcpy(srcBuf, line + secondLast + 1, srcLen);
    srcBuf[srcLen] = '\0';
    trimField(srcBuf);

    char chBuf[8] = {0};
    size_t chLen = len - (lastComma + 1);
    if (chLen == 0 || chLen >= sizeof(chBuf))
        return false;
    std::memcpy(chBuf, line + lastComma + 1, chLen);
    chBuf[chLen] = '\0';
    trimField(chBuf);

    if (std::strcmp(srcBuf, "BLE") == 0)
        *sourceOut = ThreatSource::Ble;
    else if (std::strcmp(srcBuf, "WIFI") == 0)
        *sourceOut = ThreatSource::Wifi;
    else
        return false;

    if (!fieldIsAllDigits(chBuf))
        return false;
    long c = std::atol(chBuf);
    if (c < 0 || c > 255)
        return false;
    *channelOut = (uint8_t)c;
    return true;
}

bool decodeIdentity(const char *csvLine, ThreatType *typeOut, uint8_t macOut[6])
{
    if (!csvLine || !typeOut || !macOut)
        return false;
    char f1[48], f2[48], f3[32];
    const char *wire = nullptr;
    const char *mac = nullptr;
    if (!parseThreatCsvPrefix(csvLine, &wire, &mac, f1, sizeof(f1), f2, sizeof(f2), f3, sizeof(f3)))
        return false;
    ThreatType t = wireTokenToThreatType(wire);
    if (t == ThreatType::None)
        return false;
    if (!macFieldToBytes(mac, macOut))
        return false;
    *typeOut = t;
    return true;
}

bool decodeFullIdentity(const char *csvLine, ThreatType *typeOut, uint8_t macOut[6], ThreatSource *sourceOut,
                        uint8_t *channelOut)
{
    if (!csvLine || !typeOut || !macOut || !sourceOut || !channelOut)
        return false;
    if (!decodeIdentity(csvLine, typeOut, macOut))
        return false;

    ThreatSource src = ThreatSource::Ble;
    uint8_t ch = 0;
    if (extractTrailingSourceAndChannel(csvLine, &src, &ch)) {
        *sourceOut = src;
        *channelOut = ch;
    } else {
        *sourceOut = inferSourceFromType(*typeOut);
        *channelOut = 0;
    }
    return true;
}

} // namespace valkyrie::threatlog_decode
