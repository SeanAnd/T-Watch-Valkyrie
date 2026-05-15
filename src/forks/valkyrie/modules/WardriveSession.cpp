#include "WardriveSession.h"

#if defined(ARCH_ESP32) && defined(VALKYRIE_FORK)

#include "../ThreatTypeUi.h"
#include "../ValkyrieFork.h"
#include "../persist/ThreatLog.h"
#include "BleClassifier.h"
#include "BleThreatDetectorModule.h"
#include "FlockOuiTable.h"
#include "GPSStatus.h"
#include "RTC.h"
#include "WifiFrameClassifier.h"
#include "configuration.h"
#include "graphics/Screen.h"
#include "mesh/NodeDB.h"
#include "main.h" // screen, gpsStatus
#include "sleep.h"

#include <WiFi.h>
#include <string.h>

namespace valkyrie
{

WardriveSession *wardriveSession = nullptr;

namespace
{
constexpr uint32_t kWardriveAsyncScanHardTimeoutMs = 8000;
}

WardriveSession *getOrCreateWardriveSession()
{
    if (!wardriveSession) {
        ValkyriePrefs prefs = ValkyriePrefs::load();
        wardriveSession = new WardriveSession(prefs);
    }
    return wardriveSession;
}

WardriveSession::WardriveSession(const ValkyriePrefs &p) : OSThread("ValkyrieWardrive"), prefs(p)
{
    // Subscribe so we close the CSV cleanly if something forces LS through anyway. Deep sleep
    // is also wired up for symmetry (resume from deep sleep starts a fresh boot, so the session
    // is implicitly aborted; closing the log first keeps the row write atomic).
    lightSleepObserver.observe(&notifyLightSleep);
    deepSleepObserver.observe(&notifyDeepSleep);

    // We don't need to tick when no session is active — sleep the thread until begin() nudges it.
    setInterval(60UL * 1000UL);

    // Boot-time pruning so old session files don't accumulate forever on devices that wardrive often.
    WigleLog::pruneOldSessions();
}

WardriveSession::~WardriveSession()
{
    if (active)
        end(/*aborted=*/true);
}

bool WardriveSession::begin()
{
    if (active) {
        LOG_WARN("Valkyrie: WardriveSession::begin called while session already active");
        return false;
    }

    if (bleThreatDetector)
        bleThreatDetector->pauseForWardrive();

    // Bring Wi‑Fi up in STA mode. If the threat-pass hot path already initialised the modem,
    // this is a no-op; if not, WiFi.mode() does the full cold init.
    WiFi.mode(WIFI_STA);

    memset(dedup, 0, sizeof(dedup));
    dedupCount = 0;
    aborted = false;
    s = WardriveStats{};
    s.startedUnixSecs = getValidTime(RTCQualityFromNet);

    if (!log.begin(s.startedUnixSecs ? s.startedUnixSecs : (uint32_t)millis() / 1000U, /*appReleaseSuffix=*/nullptr)) {
        LOG_ERROR("Valkyrie: WardriveSession could not open Wigle log; aborting begin");
        if (bleThreatDetector)
            bleThreatDetector->resumeFromWardrive();
        return false;
    }

    active = true;
    lastScanRequestMs = 0;
    asyncScanInFlight = false;
    consecutiveScanKickFailures = 0;
    lastGpsTickMs = 0;
    lastUiRepaintMs = 0;

    setIntervalFromNow(0);

    LOG_INFO("Valkyrie: WardriveSession begun, log=%s", log.currentPath());
    return true;
}

void WardriveSession::end(bool wasAborted)
{
    if (!active)
        return;
    aborted = wasAborted;

    // Stop any in-flight async scan so the modem doesn't keep ticking after we hand control back.
    int16_t st = WiFi.scanComplete();
    if (st == WIFI_SCAN_RUNNING) {
        WiFi.scanDelete();
    } else if (st >= 0) {
        WiFi.scanDelete();
    }
    asyncScanInFlight = false;
    consecutiveScanKickFailures = 0;

    log.close();
    active = false;

    if (bleThreatDetector)
        bleThreatDetector->resumeFromWardrive();

    LOG_INFO("Valkyrie: WardriveSession ended (aborted=%d) APs=%u dist=%um threats=%u", (int)aborted,
             (unsigned)s.apsLoggedDistinct, (unsigned)s.distanceMeters, (unsigned)s.threatsHit);

    setInterval(60UL * 1000UL);
}

void WardriveSession::formatFixStatusLine(char *buf, size_t bufCap, bool *outDrawInverse) const
{
    if (outDrawInverse)
        *outDrawInverse = false;
    if (!buf || bufCap < 12) {
        if (buf && bufCap)
            buf[0] = '\0';
        return;
    }
    buf[0] = '\0';

    if (!gpsStatus) {
        snprintf(buf, bufCap, "Fix: None");
        return;
    }

    const bool lock = gpsStatus->getHasLock();
    const bool usable = gpsStatus->getHasUsablePosition();
    const bool anchored = config.position.fixed_position;
    const bool localNonZero = (localPosition.latitude_i != 0 || localPosition.longitude_i != 0);

    auto phoneAgeSecs = [&]() -> uint32_t {
        if (!nodeDB)
            return 0;
        const uint32_t last = nodeDB->getLastLocalPositionUpdateMs();
        if (!last)
            return 0;
        return (millis() - last) / 1000U;
    };

    const uint32_t pAgeSec = phoneAgeSecs();
    const bool havePhoneStamp = nodeDB && nodeDB->getLastLocalPositionUpdateMs() != 0;

    if (lock && usable) {
        uint32_t chipAge = 0;
        const uint32_t lfm = gpsStatus->getLastFixMillis();
        if (lfm != 0)
            chipAge = (millis() - lfm) / 1000U;
        if (chipAge > 9999U)
            chipAge = 9999U;
        snprintf(buf, bufCap, "Fix: GPS (%us)", (unsigned)chipAge);
        return;
    }

    // Anchored/manual position — treat like a stable ground-truth coord; no *Stale heuristic.
    if (anchored && usable && localNonZero) {
        uint32_t a = havePhoneStamp ? pAgeSec : 0;
        if (a > 9999U)
            a = 9999U;
        snprintf(buf, bufCap, "Fix: Phone (%us)", (unsigned)a);
        return;
    }

    const bool dynPhoneUsable = usable && !lock && !anchored && localNonZero;
    const bool lingeringPhone = !usable && !lock && !anchored && localNonZero && havePhoneStamp;

    if (dynPhoneUsable || lingeringPhone) {
        uint32_t a = havePhoneStamp ? pAgeSec : 0;
        if (a > 9999U)
            a = 9999U;
        const bool staleCsv = (pAgeSec > 10U);
        if (staleCsv && outDrawInverse)
            *outDrawInverse = true;
        const char *tag = staleCsv ? "*Stale" : "Phone";
        snprintf(buf, bufCap, "Fix: %s (%us)", tag, (unsigned)a);
        return;
    }

    snprintf(buf, bufCap, "Fix: None");
}

bool WardriveSession::dedupSeen(const uint8_t mac[6])
{
    // Pack 6-byte MAC into uint64. Add 1 so 0 is reserved for "empty slot" (a real all-zeros
    // BSSID is invalid anyway).
    uint64_t packed = 1;
    for (int i = 0; i < 6; ++i)
        packed = (packed << 8) | mac[i];

    // FNV-1a 64 -> bucket index. Linear probe on collision.
    uint64_t h = 1469598103934665603ULL;
    for (int i = 0; i < 6; ++i) {
        h ^= mac[i];
        h *= 1099511628211ULL;
    }
    size_t idx = (size_t)(h % kDedupCap);

    for (size_t probe = 0; probe < kDedupCap; ++probe) {
        size_t slot = (idx + probe) % kDedupCap;
        if (dedup[slot] == 0) {
            dedup[slot] = packed;
            if (dedupCount < kDedupCap)
                dedupCount++;
            return false;
        }
        if (dedup[slot] == packed)
            return true;
    }
    // Table full — fail open: treat as duplicate so we don't lose all subsequent rows. Realistically
    // 1024 distinct BSSIDs in one drive is already a long session and the row is still safe to drop.
    return true;
}

int WardriveSession::onLightSleep(void *)
{
    // Something forced LS through anyway (e.g. critical battery). Close the file cleanly and mark
    // the session aborted; resume on wake will surface the abort in the summary banner.
    if (active) {
        LOG_WARN("Valkyrie: WardriveSession closing log under LS edge");
        end(/*aborted=*/true);
    }
    return 0;
}

int WardriveSession::onDeepSleep(void *)
{
    if (active) {
        end(/*aborted=*/true);
    }
    return 0;
}

void WardriveSession::gpsTick(uint32_t nowMs)
{
    if (!gpsStatus)
        return;

    const bool usable = gpsStatus->getHasUsablePosition();
    s.hasUsableFix = usable;
    if (!usable) {
        return;
    }

    s.fixIsOnDeviceGps = gpsStatus->getHasLock();
    s.fixIsFromPhoneOrFixedPos = !s.fixIsOnDeviceGps;

    const int32_t lat = gpsStatus->getLatitude();
    const int32_t lon = gpsStatus->getLongitude();
    if (lat == 0 && lon == 0) {
        s.hasUsableFix = false;
        return;
    }

    if (s.lastFixWallMs != 0 && (s.lastLatI != 0 || s.lastLonI != 0)) {
        const uint32_t dtMs = nowMs - s.lastFixWallMs;
        // Time-gate against teleport spikes: require >=1 s between samples, and implied speed
        // <100 m/s. Anything faster is a GPS jitter artifact, not a real movement.
        if (dtMs >= 1000U) {
            double d = wigle_format::haversineMeters(s.lastLatI, s.lastLonI, lat, lon);
            const double maxAllowed = (double)dtMs * 0.1; // 100 m/s = 0.1 m/ms
            if (d < maxAllowed && d > 0.5) {
                s.distanceMeters += (uint32_t)d;
            }
        }
    }

    s.lastLatI = lat;
    s.lastLonI = lon;
    s.lastFixWallMs = nowMs;
}

void WardriveSession::scanTick(uint32_t nowMs)
{
    if (asyncScanInFlight) {
        int16_t st = WiFi.scanComplete();
        if (st == WIFI_SCAN_RUNNING) {
            if (lastScanRequestMs != 0 && (uint32_t)(nowMs - lastScanRequestMs) > kWardriveAsyncScanHardTimeoutMs) {
                LOG_WARN("Valkyrie: WiFi wardrive async scan stuck; resetting scan state");
                WiFi.scanDelete();
                WiFi.mode(WIFI_OFF);
                WiFi.mode(WIFI_STA);
                asyncScanInFlight = false;
                lastScanRequestMs = nowMs;
            }
            return;
        }
        asyncScanInFlight = false;
        if (st == WIFI_SCAN_FAILED || st < 0) {
            WiFi.scanDelete();
            return;
        }

        const uint32_t unixSecs = getValidTime(RTCQualityFromNet);
        for (int i = 0; i < (int)st; ++i) {
            processScanResult(i, unixSecs);
        }
        WiFi.scanDelete();
        consecutiveScanKickFailures = 0;
        return;
    }

    if (lastScanRequestMs != 0) {
        const uint32_t periodMs = prefs.wardriveScanPeriodMs ? prefs.wardriveScanPeriodMs : 10000U;
        if ((uint32_t)(nowMs - lastScanRequestMs) < periodMs)
            return;
    }

    // Passive scan: no probe transmits — Dramatically improves BLE coexistence vs active scan while
    // the paired phone pushes position over GATT. Most APs beacon every ~100 ms; 150 ms/channel
    // catches nearly all (~11 × 150 ms ≈ 1.7 s RX-biased dwell per burst). Hidden networks that
    // never beacon still won't appear (same trade-off as passive wardriving elsewhere).
    // We poll for completion in subsequent runOnce() ticks.
    int16_t kicked = WiFi.scanNetworks(/*async=*/true, /*show_hidden=*/true, /*passive=*/true,
                                       /*max_ms_per_chan=*/150U);
    if (kicked == WIFI_SCAN_RUNNING) {
        asyncScanInFlight = true;
        lastScanRequestMs = nowMs;
        consecutiveScanKickFailures = 0;
    } else if (kicked == WIFI_SCAN_FAILED) {
        lastScanRequestMs = nowMs;
        if (consecutiveScanKickFailures < 255)
            consecutiveScanKickFailures++;
        if (consecutiveScanKickFailures == 1 || (consecutiveScanKickFailures % 4U) == 0) {
            LOG_WARN("Valkyrie: WiFi.scanNetworks kick failed (%u)", (unsigned)consecutiveScanKickFailures);
        }
    }
}

void WardriveSession::processScanResult(int idx, uint32_t unixSecs)
{
    String ssid = WiFi.SSID(idx);
    int32_t rssi = WiFi.RSSI(idx);
    int32_t channel = WiFi.channel(idx);
    wifi_auth_mode_t enc = WiFi.encryptionType(idx);
    uint8_t *bssidRaw = WiFi.BSSID(idx);
    if (!bssidRaw)
        return;

    uint8_t bssid[6];
    memcpy(bssid, bssidRaw, 6);

    s.apsSeenTotalRaw++;

    const bool requireFix = prefs.wardriveRequireFix;
    const bool fixUsable = gpsStatus && gpsStatus->getHasUsablePosition();
    if (requireFix && !fixUsable) {
        // No GPS data yet; skip the row entirely so we don't poison the Wigle log with bogus (0,0)
        // points. Still run the classifier so threats still fire (Marauder behaviour).
    } else if (!dedupSeen(bssid)) {
        int32_t lat_i = fixUsable ? gpsStatus->getLatitude() : 0;
        int32_t lon_i = fixUsable ? gpsStatus->getLongitude() : 0;
        // Altitude is in mm in Meshtastic's localPosition (millimetres above MSL); convert to m.
        double altM = fixUsable ? (double)gpsStatus->getAltitude() : 0.0;
        // Accuracy proxy: HDOP * 5 m if we have on-device DOP, else 25 m fallback for phone-supplied fixes.
        double accuracyM = 25.0;
        if (fixUsable && gpsStatus->getHasLock()) {
            uint32_t dop = gpsStatus->getDOP();
            if (dop != 0)
                accuracyM = (double)dop * 0.01 * 5.0; // PDOP is *100 in nanopb; HDOP-ish proxy
        }

        const wigle_format::AuthMode auth = wigle_format::authFromArduinoEspWifi((uint8_t)enc);
        if (log.appendRow(bssid, ssid.c_str(), auth, unixSecs, (uint8_t)channel, rssi, lat_i, lon_i, altM, accuracyM,
                          wigle_format::RowType::Wifi)) {
            s.apsLoggedDistinct++;
        }
    }

    // Classifier dispatch — run on every scan result (not just newly-deduped) so a moving driver
    // who briefly disappears + reappears still flags the threat in the threats.log.
    ClassificationResult cr{};
    if (macMatchesFlockInfraOui(bssid)) {
        cr.type = ThreatType::Flock;
        snprintf(cr.detail, sizeof(cr.detail), "wifi_scan_flock_oui");
    } else {
        const char *vendorLabel = nullptr;
        const bool privacyOn = (enc != WIFI_AUTH_OPEN);
        if (wifi80211MacMatchesSuspiciousVendorOui(bssid, privacyOn, &vendorLabel)) {
            cr.type = ThreatType::WifiSuspiciousAp;
            snprintf(cr.detail, sizeof(cr.detail), "wifi_scan_vendor_%s", vendorLabel ? vendorLabel : "?");
        }
    }

    if (cr.type != ThreatType::None) {
        if (prefs.wardrivePhoneNotify && bleThreatDetector) {
            // Normal path: writes to threats.log + sends PRIVATE_APP / ClientNotification to phone (gated by
            // phoneNotificationsEnabled / dedupe / phone cooldown inside emitDetection).
            bleThreatDetector->emitWifiThreat(cr, bssid, ssid.length() ? ssid.c_str() : nullptr, rssi, (uint8_t)channel);
        } else {
            // Quiet path: still write to threats.log so the row counts toward total XP and the log viewer, but
            // skip the phone push (the wardrive UI is fullscreen anyway, so the phone link is redundant during
            // the drive when the user opted out via wd_phn).
            ThreatLog::append(unixSecs, threatTypeWireName(cr.type), bssid, ssid.length() ? ssid.c_str() : "", rssi, cr.detail,
                              ThreatSource::Wifi, (uint8_t)channel);
        }
        s.threatsHit++;
    }
}

int32_t WardriveSession::runOnce()
{
    if (!active)
        return 60UL * 1000UL;

    const uint32_t now = millis();

    if (lastGpsTickMs == 0 || (now - lastGpsTickMs) >= 1000U) {
        lastGpsTickMs = now;
        gpsTick(now);
    }

    scanTick(now);

#if HAS_SCREEN && defined(VALKYRIE_FORK)
    // Repaint at ~10 Hz so the live counters / fix-source line / age tick smoothly.
    if (screen && (lastUiRepaintMs == 0 || (now - lastUiRepaintMs) >= 100U)) {
        lastUiRepaintMs = now;
        screen->repaintFrameNow();
    }
#endif

    // Wake often enough for smooth wardrive UI (intro animation + counters). repaintFrameNow() only
    // runs from this thread; a 250 ms interval between scans caused multi-frame intro skips.
    return 100;
}

} // namespace valkyrie

#endif // ARCH_ESP32 && VALKYRIE_FORK
