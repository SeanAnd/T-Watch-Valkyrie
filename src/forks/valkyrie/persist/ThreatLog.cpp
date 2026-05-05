#include "ThreatLog.h"
#include "configuration.h"

#if defined(ARCH_ESP32) && defined(VALKYRIE_FORK)

#include "../ThreatTypeUi.h"
#include "FSCommon.h"

#include <cctype>
#include <cstring>
#include <cstdio>

namespace valkyrie
{

static int hexValue(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'A' && c <= 'F')
        return 10 + c - 'A';
    if (c >= 'a' && c <= 'f')
        return 10 + c - 'a';
    return -1;
}

/** Collect exactly 12 hex digits (skip :, -, .); write 6 raw bytes (MSB first, same as log CSV). */
static bool macFieldToBytes(const char *macIn, uint8_t out[6])
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

/** Collect exactly 12 hex digits (skip :, -, .); emit canonical AA:BB:... uppercase */
static bool normalizeMacForDisplay(const char *macIn, char *out, size_t outLen)
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
    uint8_t b[6];
    for (int i = 0; i < 6; ++i)
        b[i] = (uint8_t)((nybbles[i * 2] << 4) | nybbles[i * 2 + 1]);
    snprintf(out, outLen, "%02X:%02X:%02X:%02X:%02X:%02X", b[0], b[1], b[2], b[3], b[4], b[5]);
    return true;
}

static ThreatType wireTokenToThreatType(const char *tok)
{
    for (unsigned u = 1; u <= 6; ++u) {
        ThreatType t = static_cast<ThreatType>((uint8_t)u);
        if (strcmp(tok, threatTypeWireName(t)) == 0)
            return t;
    }
    return ThreatType::None;
}

static void emitDisplayLine(const char *wireTypeToken, const char *macField, char *out, size_t outLen)
{
    char macCanon[24];
    if (!normalizeMacForDisplay(macField, macCanon, sizeof(macCanon))) {
        strncpy(macCanon, macField, sizeof(macCanon) - 1);
        macCanon[sizeof(macCanon) - 1] = '\0';
        for (char *p = macCanon; *p; ++p)
            *p = (char)toupper((unsigned char)*p);
    }
    ThreatType tt = wireTokenToThreatType(wireTypeToken);
    const char *label = (tt != ThreatType::None) ? threatTypeMenuLabel(tt) : wireTypeToken;
    snprintf(out, outLen, "%s %s", label, macCanon);
}

/** Centered overlay measures full string width; very long lines make the box wider than the screen and clip both edges. */
static void clampThreatLineForBanner(char *line, size_t lineCap, size_t maxChars)
{
    if (lineCap == 0)
        return;
    size_t len = strlen(line);
    if (len <= maxChars)
        return;

    char *sp = strrchr(line, ' ');
    if (!sp || sp == line) {
        if (maxChars >= 4 && len > maxChars - 1) {
            char tmp[160];
            snprintf(tmp, sizeof(tmp), "%.*s...", (int)(maxChars - 4), line);
            strncpy(line, tmp, lineCap - 1);
            line[lineCap - 1] = '\0';
        }
        return;
    }

    *sp = '\0';
    const char *macPart = sp + 1;
    size_t macLen = strlen(macPart);
    size_t roomForLabel = maxChars > macLen + 1 ? maxChars - macLen - 1 : 0;
    if (roomForLabel < 4) {
        snprintf(line, lineCap, "%s", macPart);
        return;
    }

    const char *lb = line;
    size_t lbLen = strlen(lb);
    if (lbLen <= roomForLabel) {
        snprintf(line, lineCap, "%s %s", lb, macPart);
        return;
    }

    size_t take = roomForLabel >= 2 ? roomForLabel - 2 : 0;
    const char *tail = lb;
    if (lbLen > take && take > 0)
        tail = lb + (lbLen - take);
    snprintf(line, lineCap, "..%s %s", tail, macPart);
}

static void trimField(char *s)
{
    if (!s || !*s)
        return;
    char *start = s;
    while (*start && isspace((unsigned char)*start))
        ++start;
    if (start != s)
        memmove(s, start, strlen(start) + 1);
    size_t L = strlen(s);
    while (L > 0 && isspace((unsigned char)s[L - 1]))
        s[--L] = '\0';
}

static bool fieldIsAllDigits(const char *f)
{
    if (!f || !*f)
        return false;
    for (const char *p = f; *p; ++p) {
        if (!isdigit((unsigned char)*p))
            return false;
    }
    return true;
}

/** Prepare untrusted text for a CSV double-quoted field: double quotes per RFC4180, strip control chars. */
static void csvEscapeForQuotedField(const char *in, char *out, size_t outCap)
{
    if (!out || outCap == 0)
        return;
    out[0] = '\0';
    if (!in)
        return;
    size_t j = 0;
    for (size_t i = 0; in[i] && j + 1 < outCap; ++i) {
        unsigned char c = (unsigned char)in[i];
        if (c == '\n' || c == '\r' || c < 0x20) {
            if (j + 1 >= outCap)
                break;
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
}

/**
 * Only the first three fields are needed for display. They never contain commas; remaining CSV
 * may include commas inside quoted name/detail — do not sscanf quoted fields (empty "" breaks %[^"] on some libcs).
 * New: type,ts,mac,...  Old: ts,type,mac,...
 */
static bool parseThreatCsvPrefix(const char *line, const char **wireTypeOut, const char **macFieldOut, char *buf1, size_t n1,
                                 char *buf2, size_t n2, char *buf3, size_t n3)
{
    const char *c1 = strchr(line, ',');
    if (!c1)
        return false;
    const char *c2 = strchr(c1 + 1, ',');
    if (!c2)
        return false;
    const char *c3 = strchr(c2 + 1, ',');
    if (!c3)
        return false;

    size_t l1 = (size_t)(c1 - line);
    size_t l2 = (size_t)(c2 - c1 - 1);
    size_t l3 = (size_t)(c3 - c2 - 1);
    if (l1 >= n1 || l2 >= n2 || l3 >= n3)
        return false;

    memcpy(buf1, line, l1);
    buf1[l1] = '\0';
    memcpy(buf2, c1 + 1, l2);
    buf2[l2] = '\0';
    memcpy(buf3, c2 + 1, l3);
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

// Display: "{menuLabel} {AA:BB:...}" (full CSV unchanged on disk).
static void formatThreatLineForDisplay(const String &raw, char *out, size_t outLen)
{
    if (!out || outLen < 8) {
        if (out && outLen)
            out[0] = '\0';
        return;
    }
    out[0] = '\0';
    String s = raw;
    s.trim();
    if (s.length() == 0)
        return;

    char f1[48], f2[48], f3[32];
    const char *wire = nullptr;
    const char *mac = nullptr;
    if (parseThreatCsvPrefix(s.c_str(), &wire, &mac, f1, sizeof(f1), f2, sizeof(f2), f3, sizeof(f3))) {
        emitDisplayLine(wire, mac, out, outLen);
        // ~38 chars keeps the selection banner box within typical round LCD width when centered
        clampThreatLineForBanner(out, outLen, 38);
        return;
    }

    String show = s;
    constexpr size_t kMaxRaw = 48;
    if (show.length() > kMaxRaw)
        show = show.substring(0, (int)kMaxRaw - 3) + "...";
    strncpy(out, show.c_str(), outLen - 1);
    out[outLen - 1] = '\0';
}

void ThreatLog::ensureDir()
{
    // LittleFS on ESP32 doesn't strictly require explicit mkdir for
    // intermediate path components, but other targets do. Be explicit
    // so the same code stays portable if we ever fork a non-ESP32
    // build of Valkyrie.
    FSCom.mkdir("/valkyrie");
}

void ThreatLog::rotateIfNeeded(size_t pendingBytes)
{
    if (!FSCom.exists(kPath))
        return;

    size_t current = 0;
    {
        auto stat = FSCom.open(kPath, FILE_O_READ);
        if (stat) {
            current = stat.size();
            stat.close();
        }
    }
    if (current + pendingBytes <= kMaxBytes)
        return;

    LOG_INFO("Valkyrie: rotating %s (%u bytes -> %s)", kPath, (unsigned)current, kBackupPath);

    if (FSCom.exists(kBackupPath))
        FSCom.remove(kBackupPath);
    if (!FSCom.rename(kPath, kBackupPath)) {
        LOG_WARN("Valkyrie: rotate rename failed; deleting current log to recover");
        FSCom.remove(kPath);
    }
}

void ThreatLog::append(uint32_t timestampSecs, const char *typeName, const uint8_t mac[6], const char *name, int32_t rssi,
                       const char *detail)
{
    ensureDir();

    char macStr[18];
    snprintf(macStr, sizeof(macStr), "%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    char nameEsc[80];
    char detailEsc[96];
    csvEscapeForQuotedField(name ? name : "", nameEsc, sizeof(nameEsc));
    csvEscapeForQuotedField(detail ? detail : "", detailEsc, sizeof(detailEsc));

    // Build the line up-front so we know the byte count for rotation.
    // Strings are quoted to keep CSV parseable when they contain commas.
    char line[256];
    // type first for on-device display; ts/mac/name/rssi/detail unchanged after that.
    int n = snprintf(line, sizeof(line), "%s,%u,%s,\"%s\",%d,\"%s\"\n", typeName ? typeName : "?",
                     (unsigned)timestampSecs, macStr, nameEsc, (int)rssi, detailEsc);
    if (n < 0)
        return;
    if (n >= (int)sizeof(line))
        n = sizeof(line) - 1;

    rotateIfNeeded((size_t)n);

    // LittleFS on ESP32 uses Arduino's fs API; FILE_APPEND ("a") is the
    // documented append mode. FSCommon.h only defines FILE_O_WRITE
    // ("w" — truncates) and FILE_O_READ, so we go through FILE_APPEND
    // directly here, the same pattern RangeTestModule uses.
    auto file = FSCom.open(kPath, FILE_APPEND);
    if (!file) {
        LOG_WARN("Valkyrie: failed to open %s for append", kPath);
        return;
    }
    file.write(reinterpret_cast<const uint8_t *>(line), n);
    file.close();
}

size_t ThreatLog::lineCount()
{
    if (!FSCom.exists(kPath))
        return 0;
    auto file = FSCom.open(kPath, FILE_O_READ);
    if (!file)
        return 0;
    size_t lines = 0;
    while (file.available()) {
        if (file.read() == '\n')
            lines++;
    }
    file.close();
    return lines;
}

/** `fileLineIndex` is 0-based from BOF; first line in file is oldest threat. */
static bool readLineAtFileIndex(size_t fileLineIndex, char *out, size_t outCap)
{
    if (!out || outCap == 0)
        return false;
    out[0] = '\0';
    if (!FSCom.exists(ThreatLog::kPath))
        return false;
    auto file = FSCom.open(ThreatLog::kPath, FILE_O_READ);
    if (!file)
        return false;
    size_t curLine = 0;
    while (file.available()) {
        String line = file.readStringUntil('\n');
        if (curLine == fileLineIndex) {
            line.trim();
            strncpy(out, line.c_str(), outCap - 1);
            out[outCap - 1] = '\0';
            file.close();
            return out[0] != '\0';
        }
        curLine++;
    }
    file.close();
    return false;
}

static bool viewerPageBounds(size_t pageIndex, size_t maxLines, size_t kMaxLinesPerPage, size_t *totalOut,
                             size_t *endExclusiveOut, size_t *startInclusiveOut, size_t *linesOnPageOut)
{
    if (!totalOut || !endExclusiveOut || !startInclusiveOut || !linesOnPageOut)
        return false;
    if (maxLines == 0 || maxLines > kMaxLinesPerPage)
        return false;
    size_t total = ThreatLog::lineCount();
    *totalOut = total;
    if (total == 0 || pageIndex * maxLines >= total)
        return false;
    size_t endExclusive = total - pageIndex * maxLines;
    size_t startInclusive = endExclusive > maxLines ? endExclusive - maxLines : 0;
    if (startInclusive >= endExclusive)
        return false;
    *endExclusiveOut = endExclusive;
    *startInclusiveOut = startInclusive;
    *linesOnPageOut = endExclusive - startInclusive;
    return true;
}

bool ThreatLog::readViewerLine(size_t pageIndex, size_t lineOnPage, size_t maxLines, char *rawCsvOut, size_t rawCap)
{
    if (!rawCsvOut || rawCap == 0)
        return false;
    rawCsvOut[0] = '\0';
    constexpr size_t kMaxLinesPerPage = 8;
    size_t total = 0, endExclusive = 0, startInclusive = 0, linesOnPage = 0;
    if (!viewerPageBounds(pageIndex, maxLines, kMaxLinesPerPage, &total, &endExclusive, &startInclusive, &linesOnPage))
        return false;
    (void)total;
    if (lineOnPage >= linesOnPage)
        return false;
    size_t fileLineIndex = endExclusive - 1 - lineOnPage;
    return readLineAtFileIndex(fileLineIndex, rawCsvOut, rawCap);
}

bool ThreatLog::decodeIdentityFromCsvLine(const char *csvLine, ThreatType *typeOut, uint8_t macOut[6])
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

void ThreatLog::buildLineWindow(size_t pageIndex, size_t maxLines, char *outMsg, size_t outLen)
{
    if (!outMsg || outLen == 0 || maxLines == 0)
        return;
    outMsg[0] = '\0';
    if (!FSCom.exists(kPath))
        return;

    constexpr size_t kMaxLinesPerPage = 8;
    if (maxLines > kMaxLinesPerPage)
        maxLines = kMaxLinesPerPage;

    size_t total = 0, endExclusive = 0, startInclusive = 0, linesOnPage = 0;
    if (!viewerPageBounds(pageIndex, maxLines, kMaxLinesPerPage, &total, &endExclusive, &startInclusive, &linesOnPage))
        return;
    (void)total;

    char fmtBuf[kMaxLinesPerPage][160];
    size_t n = 0;
    for (size_t li = 0; li < linesOnPage; ++li) {
        char raw[256];
        size_t fileLineIndex = startInclusive + li;
        if (!readLineAtFileIndex(fileLineIndex, raw, sizeof(raw)))
            break;
        formatThreatLineForDisplay(String(raw), fmtBuf[n], sizeof(fmtBuf[0]));
        n++;
    }

    size_t pos = 0;
    for (size_t i = n; i > 0; --i) {
        const char *chunk = fmtBuf[i - 1];
        int written = snprintf(outMsg + pos, outLen - pos, "%s%s", pos > 0 ? "\n" : "", chunk);
        if (written < 0 || (size_t)written >= outLen - pos)
            break;
        pos += (size_t)written;
    }
}

void ThreatLog::clearAll()
{
    ensureDir();
    if (FSCom.exists(kPath))
        FSCom.remove(kPath);
    if (FSCom.exists(kBackupPath))
        FSCom.remove(kBackupPath);
}

} // namespace valkyrie

#else

namespace valkyrie
{
void ThreatLog::ensureDir() {}
void ThreatLog::rotateIfNeeded(size_t) {}
void ThreatLog::append(uint32_t, const char *, const uint8_t[6], const char *, int32_t, const char *) {}
size_t ThreatLog::lineCount() { return 0; }
void ThreatLog::buildLineWindow(size_t, size_t, char *, size_t) {}
bool ThreatLog::readViewerLine(size_t, size_t, size_t, char *, size_t) { return false; }
bool ThreatLog::decodeIdentityFromCsvLine(const char *, ThreatType *, uint8_t *) { return false; }
void ThreatLog::clearAll() {}
} // namespace valkyrie

#endif
