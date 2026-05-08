#pragma once

#include <stddef.h>
#include <stdint.h>

namespace valkyrie
{

// Pure 802.11 helpers for Wi‑Fi threat pass (host-unit-testable, no esp_wifi).

bool wifi80211ParseFrameControl(const uint8_t *frame, size_t len, uint8_t *typeOut, uint8_t *subtypeOut);

/// Management / extension fields: Addr1 @4, Addr2 @10, Addr3 @16 (24-byte header).
bool wifi80211CopyAddr123(const uint8_t *frame, size_t len, uint8_t addr1[6], uint8_t addr2[6], uint8_t addr3[6]);

bool wifi80211IsBroadcastMac(const uint8_t mac[6]);
bool wifi80211IsMulticastMac(const uint8_t mac[6]);
/// IEEE 802: locally administered (includes typical randomised STA addresses).
bool wifi80211IsLocallyAdministeredMac(const uint8_t mac[6]);

/// Probe Request + SSID IE tag 0 length 0 (wildcard), flock-you / DeFlockJoplin signature.
bool wifi80211IsWildcardProbeRequest(const uint8_t *frame, size_t len);

/// Management subtype 0x0A disassoc or 0x0C deauth.
bool wifi80211MgmtIsDeauthDisassoc(const uint8_t *frame, size_t len);

/// Data frame: LLC/SNAP EAPOL (88 8E) after variable MAC header; hdrBytesOut optional.
bool wifi80211DataHasEapol(const uint8_t *frame, size_t len, size_t *hdrBytesOut);

/// Beacon: extract SSID (tag 0) into ssidOut (NUL-terminated), caps LE at offset 34 for privacy bit.
bool wifi80211BeaconExtractSsidAndPrivacy(const uint8_t *frame, size_t len, char *ssidOut, size_t ssidCap,
                                          bool *privacyOnOut);

/// Simple DJB-ish hash over SSID bytes for MultiSSID tracking.
uint16_t wifi80211HashSsidBytes(const uint8_t *ssid, size_t ssidLen);

/// Marauder-style suspicious AP OUIs (trimmed set); open-only heuristic optional via privacyOn.
bool wifi80211MacMatchesSuspiciousVendorOui(const uint8_t mac[6], bool privacyOn, const char **vendorLabelOut);

/// Heuristic: JSON-ish beacon containing Pwnagotchi markers ("pwnd_tot" + "name").
bool wifi80211BeaconLooksLikePwnagotchi(const uint8_t *frame, size_t len);

} // namespace valkyrie
