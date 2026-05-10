#pragma once

#include "modules/BleClassifier.h"

#include <stddef.h>
#include <stdint.h>

namespace valkyrie
{

// CSV log of detected threats on LittleFS with a single backup file rotation.
// At most one row per (threat type wire token, MAC): a new sighting replaces
// older lines for the same identity so the viewer stays newest-first without
// duplicate keys. Path is namespaced under /valkyrie/.
//
//   /valkyrie/threats.log    current log (rotated when it exceeds kMaxBytes)
//   /valkyrie/threats.log.1  most recent rotation, kept as backup
//
// CSV columns (current schema): type,timestamp_secs,mac,name,rssi,detail,source,channel
// Legacy 6-field rows (no source/channel) are still parsed; their source is
// inferred from `type` (WifiDeauth..WifiMultiSsid -> WIFI, otherwise BLE) and
// channel defaults to 0.
class ThreatLog
{
  public:
    // Maximum size of /valkyrie/threats.log before we rotate it to .1
    // and start fresh. 32 KB is a safe default for a flash budget.
    static constexpr size_t kMaxBytes = 32 * 1024;

    static constexpr const char *kPath = "/valkyrie/threats.log";
    static constexpr const char *kBackupPath = "/valkyrie/threats.log.1";

    // Record one detection (upsert by type + MAC). Rotates if the file would exceed kMaxBytes.
    // - timestampSecs: millis()/1000 at detection time
    // - typeName: short string ("AIRTAG", "FLIPPER", ...) for human-readable CSV
    // - mac: 6 raw bytes
    // - name: NUL-terminated, may be empty
    // - rssi: dBm
    // - detail: NUL-terminated, may be empty
    // - source: BLE or Wi‑Fi promiscuous origin (drives heartbeat radio choice)
    // - channel: Wi‑Fi channel the frame arrived on (1/6/11); pass 0 for BLE rows or unknown
    static void append(uint32_t timestampSecs, const char *typeName, const uint8_t mac[6], const char *name, int32_t rssi,
                       const char *detail, ThreatSource source, uint8_t channel);

    // Read helpers for on-device log viewer (primary file only).
    static size_t lineCount();
    // Fills outMsg with up to maxLines entries for viewer page `pageIndex`, where page 0 is the most recently
    // appended lines. Within the page, lines are ordered newest-first (latest threat at the top). Newline-separated,
    // truncated to outLen-1.
    static void buildLineWindow(size_t pageIndex, size_t maxLines, char *outMsg, size_t outLen);

    // Raw CSV line for viewer cell (same paging as buildLineWindow). lineOnPage 0 = newest on that page.
    static bool readViewerLine(size_t pageIndex, size_t lineOnPage, size_t maxLines, char *rawCsvOut, size_t rawCap);

    // Parse leading type + MAC from a stored CSV line (supports legacy ts-first rows).
    static bool decodeIdentityFromCsvLine(const char *csvLine, ThreatType *typeOut, uint8_t macOut[6]);

    // Same as decodeIdentityFromCsvLine but also returns source + channel. For legacy rows
    // (no trailing columns), source is inferred from type (Wifi* => WIFI, else BLE) and
    // channel is 0.
    static bool decodeFullIdentityFromCsvLine(const char *csvLine, ThreatType *typeOut, uint8_t macOut[6],
                                              ThreatSource *sourceOut, uint8_t *channelOut);

    // Delete current + rotated log files on LittleFS.
    static void clearAll();

  private:
    static void ensureDir();
    static void rotateIfNeeded(size_t pendingBytes);
};

// Wire token for the `source` CSV column ("BLE" / "WIFI"). Pure helper so
// host tests can use it.
const char *threatSourceWireName(ThreatSource s);

} // namespace valkyrie
