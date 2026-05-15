#include "WigleLog.h"

#include "configuration.h"

#if defined(ARCH_ESP32) && defined(VALKYRIE_FORK)

#include "FSCommon.h"
#include "SPILock.h"
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

namespace valkyrie
{

// Hold the open `File` for the active session at translation-unit scope so the public header
// stays free of FSCommon. Only one wardrive session is ever active per device, so a singleton-
// style storage is fine here.
static File s_file;

static void littlefsAbsPath(char *out, size_t outCap, const char *fsRelative)
{
    snprintf(out, outCap, "/littlefs%s", fsRelative);
}

static bool unlinkIfExistsQuiet(const char *fsRelative)
{
    char absPath[96];
    littlefsAbsPath(absPath, sizeof(absPath), fsRelative);
    if (::unlink(absPath) == 0)
        return true;
    return errno == ENOENT;
}

static void ensureWardriveDir()
{
    // LittleFS doesn't require explicit mkdir for intermediates but other FS backends do.
    FSCom.mkdir("/valkyrie");
    FSCom.mkdir(WigleLog::kDir);
}

static bool writeFully(File &file, const char *path, const uint8_t *data, size_t len)
{
    if (len == 0)
        return true;
    const size_t written = file.write(data, len);
    if (written == len)
        return true;
    LOG_WARN("Valkyrie: WigleLog write failed for %s (%u/%u bytes)", path ? path : "?", (unsigned)written, (unsigned)len);
    return false;
}

WigleLog::~WigleLog() { close(); }

bool WigleLog::begin(uint32_t sessionUnixSecs, const char *appReleaseSuffix)
{
    if (openHandleValid) {
        LOG_WARN("Valkyrie: WigleLog::begin called while session already open");
        return false;
    }

    concurrency::LockGuard guard(spiLock);

    ensureWardriveDir();
    snprintf(currentSessionPath, sizeof(currentSessionPath), "%s/wardrive_%u.csv", kDir, (unsigned)sessionUnixSecs);

    s_file = FSCom.open(currentSessionPath, FILE_APPEND);
    if (!s_file) {
        LOG_WARN("Valkyrie: WigleLog could not open %s for append", currentSessionPath);
        currentSessionPath[0] = '\0';
        return false;
    }

    char header[320];
    size_t n = wigle_format::formatHeader(appReleaseSuffix, header, sizeof(header));
    if (n == 0) {
        LOG_WARN("Valkyrie: WigleLog header format failed");
        s_file.close();
        currentSessionPath[0] = '\0';
        return false;
    }

    // Only write the header on a fresh file (size == 0). Resume after a partial flush is
    // a niche, but keeping `FILE_APPEND` aligned with ThreatLog's pattern means an existing
    // file at this path (very unlikely with second-resolution naming) should not double-header.
    if (s_file.size() == 0) {
        if (!writeFully(s_file, currentSessionPath, reinterpret_cast<const uint8_t *>(header), n)) {
            s_file.close();
            currentSessionPath[0] = '\0';
            return false;
        }
        bytesWrittenThisSession = n;
    } else {
        bytesWrittenThisSession = s_file.size();
    }

    openHandleValid = true;
    LOG_INFO("Valkyrie: WigleLog opened %s", currentSessionPath);
    return true;
}

bool WigleLog::appendRow(const uint8_t bssid[6], const char *ssid, wigle_format::AuthMode authMode, uint32_t unixSecs,
                         uint8_t channel, int32_t rssi, int32_t lat_i, int32_t lon_i, double altitudeMeters,
                         double accuracyMeters, wigle_format::RowType rowType)
{
    if (!openHandleValid)
        return false;

    char row[kRowBufBytes];
    size_t n = wigle_format::formatRow(bssid, ssid, authMode, unixSecs, channel, rssi, lat_i, lon_i, altitudeMeters,
                                       accuracyMeters, rowType, row, sizeof(row));
    if (n == 0)
        return false;

    concurrency::LockGuard guard(spiLock);
    if (!s_file)
        return false;
    if (!writeFully(s_file, currentSessionPath, reinterpret_cast<const uint8_t *>(row), n)) {
        LOG_WARN("Valkyrie: closing WigleLog after write failure");
        s_file.close();
        openHandleValid = false;
        currentSessionPath[0] = '\0';
        return false;
    }
    bytesWrittenThisSession += n;
    return true;
}

void WigleLog::close()
{
    if (!openHandleValid)
        return;
    concurrency::LockGuard guard(spiLock);
    if (s_file) {
        s_file.close();
    }
    openHandleValid = false;
    LOG_INFO("Valkyrie: WigleLog closed %s (%u bytes)", currentSessionPath, (unsigned)bytesWrittenThisSession);
    currentSessionPath[0] = '\0';
    bytesWrittenThisSession = 0;
}

void WigleLog::pruneOldSessions()
{
    concurrency::LockGuard guard(spiLock);

    // Walk the wardrive directory and collect all `wardrive_*.csv` entries with their integer
    // timestamp suffix. If we are over the soft cap, delete the oldest until at or below cap.
    File dir = FSCom.open(kDir);
    if (!dir || !dir.isDirectory()) {
        return;
    }

    struct Entry {
        char name[64];
        unsigned long ts;
    };
    std::vector<Entry> entries;
    entries.reserve(kMaxSessionsKept + 4);

    File f = dir.openNextFile();
    while (f) {
        const char *name = f.name();
        if (name) {
            const char *base = strrchr(name, '/');
            base = base ? base + 1 : name;
            unsigned long ts = 0;
            if (sscanf(base, "wardrive_%lu.csv", &ts) == 1) {
                Entry e{};
                strncpy(e.name, base, sizeof(e.name) - 1);
                e.ts = ts;
                entries.push_back(e);
            }
        }
        f.close();
        f = dir.openNextFile();
    }
    dir.close();

    if (entries.size() <= kMaxSessionsKept)
        return;

    // Selection sort by ts ascending — small N, keep it dependency-free.
    for (size_t i = 0; i + 1 < entries.size(); ++i) {
        size_t minIdx = i;
        for (size_t j = i + 1; j < entries.size(); ++j) {
            if (entries[j].ts < entries[minIdx].ts)
                minIdx = j;
        }
        if (minIdx != i) {
            Entry tmp = entries[i];
            entries[i] = entries[minIdx];
            entries[minIdx] = tmp;
        }
    }

    const size_t toDelete = entries.size() - kMaxSessionsKept;
    for (size_t i = 0; i < toDelete; ++i) {
        char path[96];
        snprintf(path, sizeof(path), "%s/%s", kDir, entries[i].name);
        if (unlinkIfExistsQuiet(path))
            LOG_INFO("Valkyrie: wardrive pruned old session %s", path);
    }
}

} // namespace valkyrie

#else // !ARCH_ESP32 || !VALKYRIE_FORK

namespace valkyrie
{
WigleLog::~WigleLog() = default;
bool WigleLog::begin(uint32_t, const char *) { return false; }
bool WigleLog::appendRow(const uint8_t[6], const char *, wigle_format::AuthMode, uint32_t, uint8_t, int32_t, int32_t,
                         int32_t, double, double, wigle_format::RowType)
{
    return false;
}
void WigleLog::close() {}
void WigleLog::pruneOldSessions() {}
} // namespace valkyrie

#endif
