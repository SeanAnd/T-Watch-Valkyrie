#pragma once

#include "configuration.h"

#if defined(ARCH_ESP32) && defined(VALKYRIE_FORK)

#include "../persist/WigleFormat.h"
#include "../persist/WigleLog.h"
#include "../prefs/ValkyriePrefs.h"
#include "Observer.h"
#include "concurrency/OSThread.h"

#include <stdint.h>

namespace valkyrie
{

/// Heartbeat-style live stats surfaced to ValkyrieWardriveFrame. All counters are session-local
/// (the session resets them on begin()).
struct WardriveStats {
    uint32_t apsLoggedDistinct = 0;      ///< distinct BSSIDs that produced a Wigle row this session
    uint32_t apsSeenTotalRaw = 0;        ///< total scan results seen (incl. duplicates)
    uint32_t threatsHit = 0;             ///< classifier hits dispatched into emitWifiThreat this session
    uint32_t distanceMeters = 0;         ///< accumulated haversine distance, floor int meters
    uint32_t startedUnixSecs = 0;        ///< session start time (UTC seconds, 0 if RTC unknown)
    uint32_t lastFixWallMs = 0;          ///< millis() when we last observed a usable position
    bool hasUsableFix = false;           ///< true while getHasUsablePosition() last reported true
    bool fixIsOnDeviceGps = false;       ///< true when the fix came from the on-device chip (hasLock)
    bool fixIsFromPhoneOrFixedPos = false;///< true when the fix came from phone-supplied localPosition or fixed_position
    int32_t lastLatI = 0;                ///< last sampled latitude * 1e7
    int32_t lastLonI = 0;                ///< last sampled longitude * 1e7
};

/// Single-instance wardrive FSM. One OSThread per device; lifecycle is owned by the menu
/// (begin on confirm, end on tap-to-stop). Drives WiFi.scanNetworks asynchronously, samples
/// `gpsStatus` once per second, writes Wigle 1.6 CSV rows to LittleFS, and dispatches threat-
/// classifier hits through the existing BleThreatDetectorModule::emitWifiThreat path.
///
/// Concurrency contract (see plan): the session calls
/// `bleThreatDetector->pauseForWardrive()` in `begin()` and `resumeFromWardrive()` in `end()`,
/// so the duty-cycle OSThread is silent for the whole drive. Light-sleep is refused via the
/// detector's preflightSleepCb vote-no (also widened to cover wardriveActive).
class WardriveSession : private concurrency::OSThread
{
  public:
    explicit WardriveSession(const ValkyriePrefs &prefs);
    ~WardriveSession();

    /// Start a session. Returns false if a session is already active or radio init failed.
    bool begin();

    /// End the active session. `aborted` means the caller had to bail (LS edge, battery, etc.) —
    /// the row count + distance still credit XP, but the summary banner can flag the abort.
    /// No-op when no session is active.
    void end(bool aborted);

    bool isActive() const { return active; }
    bool wasAborted() const { return aborted; }

    /// Live counters; safe to read from the UI thread (all fields are 32-bit aligned, scalar).
    const WardriveStats &stats() const { return s; }

    /// Single-line status text "Fix: GPS|Phone|Stale|None". Phone-coordinate age uses
    /// `nodeDB->getLastLocalPositionUpdateMs()`, not the 1 Hz gps tick. Dynamic phone coords
    /// with age >10 s render as "*Stale"; `outDrawInverse` requests OLED INVERSE paint for that warning.
    void formatFixStatusLine(char *buf, size_t bufCap, bool *outDrawInverse = nullptr) const;

    /// Hot-reload prefs (settings UI calls this after toggling wd_req_fix / wd_per_ms / wd_phn).
    /// Doesn't restart the session; the new period applies to the next scan tick.
    void reloadPrefs(const ValkyriePrefs &p) { prefs = p; }

  private:
    int32_t runOnce() override;

    int onLightSleep(void *unused);
    int onDeepSleep(void *unused);

    void gpsTick(uint32_t nowMs);
    void scanTick(uint32_t nowMs);
    void processScanResult(int idx, uint32_t unixSecs);

    /// Hash-set dedup of BSSIDs seen this session. Returns true if `mac` was already present.
    bool dedupSeen(const uint8_t mac[6]);

    static constexpr size_t kDedupCap = 1024;
    /// Packed 48-bit MAC + 1 (so 0 means "empty slot"). Linear-probed.
    uint64_t dedup[kDedupCap]{};
    size_t dedupCount = 0;

    ValkyriePrefs prefs;
    bool active = false;
    bool aborted = false;
    WardriveStats s{};
    WigleLog log;

    uint32_t lastScanRequestMs = 0;
    bool asyncScanInFlight = false;
    uint8_t consecutiveScanKickFailures = 0;
    uint32_t lastGpsTickMs = 0;
    uint32_t lastUiRepaintMs = 0;

    CallbackObserver<WardriveSession, void *> lightSleepObserver =
        CallbackObserver<WardriveSession, void *>(this, &WardriveSession::onLightSleep);
    CallbackObserver<WardriveSession, void *> deepSleepObserver =
        CallbackObserver<WardriveSession, void *>(this, &WardriveSession::onDeepSleep);
};

/// Globally-accessible singleton. Lazily created the first time the user opens the wardrive
/// menu (so the OSThread isn't spun up on watches that never wardrive). Owned by ValkyrieFork.cpp.
extern WardriveSession *wardriveSession;

/// Create the singleton if it doesn't exist. Idempotent. Returns the singleton.
WardriveSession *getOrCreateWardriveSession();

} // namespace valkyrie

#endif // ARCH_ESP32 && VALKYRIE_FORK
