#pragma once

// Pure CSV decode helpers for the threat log. Extracted from ThreatLog.cpp so
// the host test (`test/test_threat_log_decode.cpp`) can exercise the schema-
// upgrade path without dragging in Arduino / FSCom / SPILock dependencies.
//
// The firmware-side `ThreatLog::decodeIdentityFromCsvLine` and
// `ThreatLog::decodeFullIdentityFromCsvLine` are thin wrappers around these.

#include "../modules/BleClassifier.h"

#include <stddef.h>
#include <stdint.h>

namespace valkyrie::threatlog_decode
{

/// Parse the leading three fields (type wire token, ts/mac, mac) of a stored CSV line.
/// Handles both the new schema (type first) and the legacy ts-first rows; returns the
/// wire-type and mac field pointers into the caller-provided scratch buffers.
bool parseThreatCsvPrefix(const char *line, const char **wireTypeOut, const char **macFieldOut, char *buf1, size_t n1,
                          char *buf2, size_t n2, char *buf3, size_t n3);

/// Convert any hex string with optional :, -, . separators into 6 raw bytes (MSB first).
bool macFieldToBytes(const char *macIn, uint8_t out[6]);

/// Map the textual wire token ("AIRTAG", "WIFI_DEAUTH", ...) back to a `ThreatType`. Returns
/// `ThreatType::None` if unknown.
ThreatType wireTokenToThreatType(const char *tok);

/// Infer source from threat type for legacy log rows that lack the trailing column.
ThreatSource inferSourceFromType(ThreatType t);

/// Pull the trailing two unquoted columns (source, channel) off a CSV line if present.
/// Returns false when the line lacks those columns or has unrecognised tokens.
bool extractTrailingSourceAndChannel(const char *line, ThreatSource *sourceOut, uint8_t *channelOut);

/// Combined: returns (type, mac) for both old and new schema rows.
bool decodeIdentity(const char *csvLine, ThreatType *typeOut, uint8_t macOut[6]);

/// Returns (type, mac, source, channel). For legacy rows source is inferred from type
/// (Wifi* => WIFI, else BLE) and channel is 0.
bool decodeFullIdentity(const char *csvLine, ThreatType *typeOut, uint8_t macOut[6], ThreatSource *sourceOut,
                        uint8_t *channelOut);

} // namespace valkyrie::threatlog_decode
