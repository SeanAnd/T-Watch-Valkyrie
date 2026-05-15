#pragma once

#include "WigleFormat.h"

#include <stddef.h>
#include <stdint.h>

namespace valkyrie
{

/// Per-session Wigle CSV writer on LittleFS. One file per wardrive session, named
/// `/valkyrie/wardrive/wardrive_<unixSecs>.csv`. Pure helpers used to encode rows live
/// in `WigleFormat.h` so the host tests can verify the row format without LittleFS.
///
/// The class is a thin stateful wrapper: opens the file on `begin`, writes a Wigle 1.6
/// two-line header, then appends one row per `appendRow` call. The session-CSV directory
/// is created on first append. There is no rotation per session; the file simply grows
/// until `close()`. Old session files are pruned via `pruneOldSessions()` to keep
/// LittleFS usage bounded.
class WigleLog
{
  public:
    /// Directory under LittleFS for wardrive session files.
    static constexpr const char *kDir = "/valkyrie/wardrive";
    /// Max raw bytes per row; sizes the on-stack format buffer.
    static constexpr size_t kRowBufBytes = 320;
    /// Soft cap on number of session CSVs kept on flash. Pruning is FIFO by ctime.
    static constexpr size_t kMaxSessionsKept = 8;

    WigleLog() = default;
    ~WigleLog();

    /// Open a new session file (`/valkyrie/wardrive/wardrive_<unixSecs>.csv`) and write the Wigle header.
    /// Returns false if filesystem ops fail or a session is already open.
    /// `appReleaseSuffix` is appended to the `appRelease=Valkyrie` token in the header (e.g. git short hash).
    bool begin(uint32_t sessionUnixSecs, const char *appReleaseSuffix);

    /// Append a single Wigle row. Returns false if not open or write fails.
    bool appendRow(const uint8_t bssid[6], const char *ssid, wigle_format::AuthMode authMode, uint32_t unixSecs,
                   uint8_t channel, int32_t rssi, int32_t lat_i, int32_t lon_i, double altitudeMeters,
                   double accuracyMeters, wigle_format::RowType rowType);

    /// Close the file handle if open. Safe to call when not open. Always called by the destructor.
    void close();

    bool isOpen() const { return openHandleValid; }

    /// Total bytes written to the current session file since `begin()`. Useful for the wardrive UI.
    size_t bytesWritten() const { return bytesWrittenThisSession; }

    /// Path of the current session file (returns empty string when not open).
    const char *currentPath() const { return openHandleValid ? currentSessionPath : ""; }

    /// FIFO-prune old wardrive session files in `kDir` so at most `kMaxSessionsKept` survive.
    /// Caller invokes once per session boot to bound flash usage.
    static void pruneOldSessions();

  private:
    char currentSessionPath[64] = {0};
    size_t bytesWrittenThisSession = 0;
    bool openHandleValid = false;

    // FSCom file handle is held as an opaque void* so the header doesn't drag in FSCommon for stock builds.
    void *handlePtr = nullptr;
};

} // namespace valkyrie
