# Features

What actually ships in this fork today.

- **BLE passive scan.** The 2.4 GHz radio is shared with the existing NimBLE GATT server, so scanning piggybacks on it.
- **Wi‑Fi promiscuous threat pass** (`WifiThreatPass.cpp`, when `HAS_WIFI` and prefs allow): hops channels **1 / 6 / 11**, passive classification via **`WifiFrameClassifier`** — Flock infra OUI + wildcard probe requests (`FlockOuiTable.h`), **deauth/disassoc**, **EAPOL**, **multi‑SSID** beacons, **Pwnagotchi**-style JSON beacon heuristic, **suspicious AP** vendor OUIs (incl. Pineapple-class), **OpenDroneID / RemoteID Wi‑Fi fingerprints** (NAN destination MAC + vendor IE OUIs per Sky‑Spy; detection only, no full telemetry decode). Implementation lives in **`WifiThreatPass`** / **`WifiFrameClassifier`**, not a separate `WifiThreatDetectorModule`.
- **Wi‑Fi driver lifecycle:** STA mode is initialized once and the driver stays resident so we never hit per-cycle `esp_wifi_deinit()` (that path leaked ~48 B/cycle). Between passes the modem is powered down with **`esp_wifi_stop()`** and brought back with **`esp_wifi_start()`** for lower idle current; **`WifiThreatPassPolicy.h`** documents the cold/hot/teardown contract. After the first Wi‑Fi pass, a baseline of internal heap remains reserved for the driver for the rest of uptime (stable vs leaking). **LoRa (SX126x)** is unrelated — separate SPI radio.
- **Classifier (BLE)** (patterns from upstream ESP32Valkyrie `WiFiScan.cpp` where applicable): AirTag / Find My (TLV-aware `0x004C` manufacturer parsing + legacy fallbacks), Flipper Zero, HC‑03/05/06 skimmer, Flock camera, Meta Ray‑Ban / Quest smart glasses, drone RemoteID over BLE (service `0xFFFA`).
- **AirTag + GPS stalking gate:** when `readGeoForStalking()` is true (GPS lock **or** `config.position.fixed_position`, non-zero lat/lon), **only** `ThreatType::Airtag` must meet an AirGuard-style rule before log/haptic/phone emit: at least `stalkMinSightings` (default 3) sightings and `stalkMinDistinctPlaces` (default 2) distinct ~`stalkMinSeparationM` grid cells for the same BLE MAC. Without position, AirTag uses pattern match + `dedupeWindowSecs` only. Correlation is **by MAC**; rotating addresses limit reliability. Thresholds in NVS (`stk_*`) / `userPrefs.valkyrie.jsonc`.
- **Power-aware scheduling:** duty-cycled BLE scan window (defaults ~10 s scan every ~30 s between threat-pass starts; idle gap `max(0, scanIntervalSecs - scanWindowSecs)` in NVS). Each pass ends with the Wi‑Fi promiscuous phase when enabled, then hub timing updates. Gated on `PowerFSM` state and battery percentage; aborted on `notifyDeepSleep` / `notifyLightSleep`.
- **Sink:** detections written to `/valkyrie/threats.log` on LittleFS (rotate at 32 KB). CSV columns: `type,timestamp_secs,mac,name,rssi,detail,source,channel` — `source` is `BLE` or `WIFI` (where the detection came from), `channel` is the Wi‑Fi channel (1/6/11) for Wi‑Fi rows or 0 for BLE; both drive heartbeat radio + lock. Legacy 6-column rows from older builds are still parsed (source inferred from type). On paired BLE, events also go to the phone as **`meshtastic_PortNum_PRIVATE_APP`** protobuf (`sendToPhone()`), plus **`ClientNotification`** bursts at pass end / immediate alerts where applicable — traffic stays off LoRa (`sendToMesh()` is not used for threats).
- **Valkyrie menu:** Bluetooth toggle, WiFi toggle (when the build has WiFi), **Settings** (enable/disable detector, constant vs interval BLE scan), **Threat log** (paged CSV viewer), **Exp log** (most-recent XP sources), **Threats** (per-type toggles, NVS), **Ignored devices** (ignore list UI).
- **Ignore list (NVS):** up to 32 `(threat type, MAC)` pairs. **Randomized BLE addresses** rotate over time, so MAC-based ignores can stop matching the same physical device.
- **Detection feedback:** at most one threat haptic pulse per scan window when something fires (stock Meshtastic-style buzzer program).
- **Heartbeat mode:** from a threat log row — continuous passive scan on the target MAC, haptic, RTTTL beeps, and sprite strength from filtered RSSI / tier (EMA + hysteresis). Duty-cycle scanning pauses while heartbeat runs; display stays on; tap exits back into the Valkyrie flow. The radio path is driven by the row's stored `source`: **BLE rows** use NimBLE continuous scan with duplicates on; **Wi‑Fi rows** drop into `esp_wifi` promiscuous and lock to the row's stored `channel` (1/6/11) for fast RSSI updates, falling back to a 1/6/11 hop when the channel is unknown (legacy rows). Both paths feed the same `HeartbeatRssiFilter` so the UI is identical.
- **Wardrive mode (Wi‑Fi):** session-based, opened from the Valkyrie root menu. `WardriveSession` pauses the BLE+Wi‑Fi duty cycle (refuses light sleep + pumps `EVENT_CONTACT_FROM_PHONE` like constant scan mode), runs `WiFi.scanNetworks` **passive** async on all regulatory-domain channels every `wd_per_ms` ms (**default 10 s** — nicer to BLE / phone-supplied position), listens **150 ms/channel** (~1–2 s bursts, mostly RX; no probe transmits), samples position once a second via `gpsStatus->getHasUsablePosition()` (on-device GPS **or** phone-supplied `localPosition`), accumulates haversine distance (time-gated), and writes Wigle 1.6 CSV to `/valkyrie/wardrive/wardrive_<unixSecs>.csv` on LittleFS. BSSID dedup is in-session (~1024 entries). The threat classifier fires from beacon-derived scan results where applicable (Flock OUI + suspicious vendor hits → `BleThreatDetectorModule`; `wardrivePhoneNotify` gates phone push). Hidden SSIDs that never beacon may be missed vs active scan — the usual passive trade-off. fullscreen heartbeat-style frame shows `Fix: GPS|Phone|Stale|None` with **phone-coordinate age** taken from `nodeDB` (not the 1 Hz poll); dynamic phone fixes older than ~10 s render as `*Stale` and invert on OLED to flag CSV positions that are behind real time. Session end awards XP via `ThreatExperience::onWardriveSessionEnded`. FIFO-pruned old session CSVs at boot.
- **Experience & unified level (`Lvl / Exp / Req` on hub):** Three XP sources roll into one displayed level on `ValkyrieHubFrame`. **Threat XP** (`ThreatExperience`, NVS `thr_xp`): one award per distinct `(type wire token, MAC)` at `ThreatLog::append`, weighted by rarity (rarer detections like Pwnagotchi/Drone/HC‑skimmer pay more); one-time backfill from existing `threats.log` after upgrade; cleared with the threat log. **Wardrive XP** (`ThreatExperience::onWardriveSessionEnded`): one bounded award per session from distinct BSSIDs, validated distance, and threat hits. **Mesh-participation XP** (`MeshExperience`, NVS `mesh_xp`, new): a 60 s tick piggybacked on `DeviceTelemetryModule::runOnce()` reads `RadioLibInterface` + `Router` counters directly and credits the delta — `txRelay` × 10, `txRelayCanceled` × 1, `rxGood` × 0.1, with a `rxDupe` × 0.5 penalty clamped non-negative per tick. Fractional XP accumulates in RAM (tenths) and only flushes to NVS when ≥ 1 whole XP has accrued (NVS-wear protection); counter regressions (reboots) silently re-baseline. `ExperienceLog` records the most recent 12 credited XP events in a fixed RAM ring (`Threat`, `Mesh`, `Wardrive`) and the root-menu **Exp log** displays them newest-first without heap growth or extra NVS writes. All totals share `ThreatExperience::levelProgress()`'s pure-math tier curve, so the level just climbs faster as sources contribute. Stock builds compile out via `__has_include`.
- **Digital clock face:** When the device is on the clock screen and built with `VALKYRIE_FORK + ARCH_ESP32`, `ValkyrieDigitalClockLayout` paints a top time row plus a compact hub chibi overlay just above the bottom icon strip; non-Valkyrie builds keep the stock face unchanged via the `#else` path in `ClockRenderer.cpp`.
- **Fork-local tests:** `forks/valkyrie/test/` holds small native `.cpp` harnesses (classifier, stalking state, Wi‑Fi frame helpers, heartbeat RSSI); excluded from the firmware build via `build_src_filter`. Meshtastic Unity suites live under `test/` (see `test/README.md`).

## Known issues

Alerts need to be refined for airtag, deauth eapol to prevent fatigue.

Heartbeat indicator could use some work, maybe a 4th signal indicator to show when you are right on top of something. Shorter/weaker vibrations on weak signals too.

if wifi or ble scanning is off, fill in the gap with the only enabled one so we get the full 20 seconds of scanning.

## Valkyrie fork overlay

Phase 1 of porting [ESP32Valkyrie](https://github.com/SeanAnd/ESP32Valkyrie)
threat detection onto the LilyGo T-Watch S3 running upstream Meshtastic.

The whole overlay lives under `firmware/src/forks/valkyrie/`. A **Valkyrie
build** also touches a small set of upstream files; keep changes there
minimal and behind `#if defined(VALKYRIE_FORK)` (and the same macro plus
`__has_include` in `Modules.cpp` for the fork entry point) so rebasing Meshtastic stays predictable:

| Upstream file | What changes |
|---------------|----------------|
| [`src/modules/Modules.cpp`](src/modules/Modules.cpp) | `VALKYRIE_FORK` + `__has_include("forks/valkyrie/ValkyrieFork.h")` (include + `valkyrie::setupFork()` at end of `setupModules()`). Stock builds exclude `forks/valkyrie/` via `arduino_base.build_src_filter`. |
| [`src/graphics/Screen.cpp`](src/graphics/Screen.cpp), [`Screen.h`](src/graphics/Screen.h) | Hub frame + long-press opens Valkyrie menu when `VALKYRIE_FORK`. |
| [`src/graphics/draw/MenuHandler.cpp`](src/graphics/draw/MenuHandler.cpp), [`MenuHandler.h`](src/graphics/draw/MenuHandler.h) | Extra `screenMenus` enum values and switch arms for Valkyrie menus when `VALKYRIE_FORK` (incl. wardrive entries). |
| [`src/input/InputBroker.cpp`](src/input/InputBroker.cpp) | Heartbeat **and wardrive** input hooks when `VALKYRIE_FORK`. |
| [`src/graphics/draw/ClockRenderer.cpp`](src/graphics/draw/ClockRenderer.cpp) | When `VALKYRIE_FORK` + `ARCH_ESP32`: digital clock delegates body layout to `forks/valkyrie/ui/ValkyrieDigitalClockLayout` (Valkyrie sprite + top time row); `#else` path unchanged. |
| [`src/modules/Telemetry/DeviceTelemetry.cpp`](src/modules/Telemetry/DeviceTelemetry.cpp) | `VALKYRIE_FORK` + `__has_include("forks/valkyrie/persist/MeshExperience.h")` (one-line hook at the top of `runOnce()` to credit passive mesh-participation XP on the existing 60 s telemetry tick). |
| [`src/GPSStatus.h`](src/GPSStatus.h) | Additive `getHasUsablePosition()` accessor + lat/lon/alt fallback into `localPosition` (gated by a 30 s freshness window from `nodeDB->getLastLocalPositionUpdateMs()`). `getHasLock()` semantics unchanged — only the public lat/lon/alt accessors widened. Stock-safe: no stock caller reads the new accessor. |
| [`src/mesh/NodeDB.h`](src/mesh/NodeDB.h), [`NodeDB.cpp`](src/mesh/NodeDB.cpp) | Stamp `millis()` into a new `lastLocalPositionUpdateMs` member each time `setLocalPosition` receives non-zero coordinates; reset it in `clearLocalPosition`. New `getLastLocalPositionUpdateMs()` accessor. Stock-safe — additive. |
| [`src/graphics/draw/UIRenderer.cpp`](src/graphics/draw/UIRenderer.cpp) | Under `#if defined(VALKYRIE_FORK)` only: swap four "No Lock" / sat-count badge sites from `getHasLock()` to the new `getHasUsablePosition()` so the UI shows "Phone" instead of "No Sats" while phone-supplied position is live. |
| [`variants/esp32s3/t-watch-s3-valkyrie/platformio.ini`](variants/esp32s3/t-watch-s3-valkyrie/platformio.ini) | Parallel env: `-DVALKYRIE_FORK=1`, `-Isrc/forks/valkyrie`, `build_src_filter` for `forks/valkyrie/` (test subtree excluded from firmware). |

Non-Valkyrie builds never define `VALKYRIE_FORK` and do not compile `src/forks/valkyrie/` (see root `platformio.ini` `arduino_base.build_src_filter`), so fork code and graphics hooks compile out.

## Layout

```
forks/valkyrie/
  ValkyrieFork.{h,cpp}              entry point invoked from Modules.cpp
  modules/
    BleThreatDetectorModule.{h,cpp} OSThread: BLE scan, duty cycle, Wi‑Fi pass
    BleClassifier.{h,cpp}           pure: BLE payload -> ThreatType
    WifiThreatPass.{h,cpp}          Wi‑Fi promiscuous pass (HAS_WIFI)
    WifiThreatPassPolicy.h          pure cold/hot/teardown policy (host-testable)
    WifiFrameClassifier.{h,cpp}     pure 802.11 parsers / heuristics
    FlockOuiTable.h                 Flock infra OUI matching (Wi‑Fi path)
    AirtagStalkingState.{h,cpp}     GPS-backed stalking gate for AirTag
    GeoStalking.{h,cpp}             GPS lock or fixed position for stalking
    WardriveSession.{h,cpp}         OSThread: WiFi.scanNetworks + GPS + Wigle log
  ui/                               menus, hub frame, heartbeat + wardrive UI/input
  prefs/
    ValkyriePrefs.{h,cpp}           private NVS namespace via Preferences
  persist/
    ThreatLog.{h,cpp}               LittleFS append + 32 KB rotate
    ThreatLogDecode.{h,cpp}         pure CSV decode helpers (host-testable)
    ExperienceLog.{h,cpp}           fixed RAM ring of recent XP sources for Exp log UI
    ThreatIgnoreList.{h,cpp}        NVS ignore list backing store
    WigleFormat.{h,cpp}             pure Wigle 1.6 row/header/haversine (host-testable)
    WigleLog.{h,cpp}                LittleFS wardrive session writer + FIFO prune
  proto/
    threat_event.proto              fork-local nanopb schema
    generated/                      pre-generated nanopb sources
  test/                             fork-local native smoke tests (not in firmware image)
  sprites/                          hub / heartbeat RGB565 assets
  HeartbeatRssiFilter.{h,cpp}       heartbeat proximity filtering
  HeartbeatSignalTier.{h,cpp}       RSSI -> UI tier
  ThreatTypeUi.{h,cpp}              threat labels for menus
  userPrefs.valkyrie.jsonc          fork-only defaults (NOT upstream's)
  regen-proto.sh                    fork-only nanopb generator
```

## Centralized GPS source

The T‑Watch S3 doesn't have an on-device GPS chip, but the paired phone pushes
position into `nodeDB->setLocalPosition()` continuously via the GATT phone link.
Stock `gpsStatus` only routed that through to `getLatitude()` / `getLongitude()`
when `config.position.fixed_position` was set, so a phone-only watch reported
"No Lock" everywhere — including the AirTag stalking gate, which made the
stalking heuristic effectively unreachable on the standard hardware variant.

The fork widens `gpsStatus` instead of growing a parallel helper:

- `getHasLock()` keeps its narrow on-device-chip semantic (so e.g.
  `MeshService::onGPSChanged` continues to copy `gps->p` only when the chip
  really has a fix).
- New `getHasUsablePosition()` returns true when **any** of the following hold:
  on-device lock, fixed-position mode with non-zero localPosition, or fresh
  phone-supplied localPosition (last update within
  `GPSStatus::kPhonePositionFreshMs` = 30 s).
- `getLatitude()` / `getLongitude()` / `getAltitude()` fall back to
  `localPosition.*` when `hasLock` is false but `getHasUsablePosition()` is true.

Side benefit: the existing AirTag GPS stalking gate now works on a phone-only
S3 with no expansion module (the "Alerts need to be refined for airtag" item in
**Known issues** is partially addressed as a result —
[`GeoStalking.cpp`](src/forks/valkyrie/modules/GeoStalking.cpp) collapses to a
one-liner that just calls `getHasUsablePosition()`). Wardrive mode consumes the
same accessor so it works transparently on watches with or without an on-device
GPS module.

## Wigle CSV format

Wardrive sessions write **Wigle 1.6**-compatible CSV files at
`/valkyrie/wardrive/wardrive_<unixSecs>.csv` on LittleFS, one file per session.
The phone app can pull them via the Meshtastic file API for later upload to
Wigle.net or offline analysis.

```
WigleWifi-1.6,appRelease=Valkyrie,model=T-Watch-S3,release=Meshtastic,device=t-watch-s3,display=NONE,board=ESP32-S3,brand=LilyGo
MAC,SSID,AuthMode,FirstSeen,Channel,Frequency,RSSI,CurrentLatitude,CurrentLongitude,AltitudeMeters,AccuracyMeters,RCOIs,MfgrId,Type
AA:BB:CC:DD:EE:FF,"MyWifi",[WPA2-PSK-CCMP][ESS],2026-05-13 20:30:15,6,2437,-65,40.712800,-74.006000,12.50,5.00,,,WIFI
```

`AuthMode` follows the Wigle bracketed-cipher convention and always ends in
`[ESS]` for an infrastructure AP. Lat/Lon/Alt come from
`gpsStatus->getLatitude() / 1e7` etc. — callers don't have to know whether the
source is on-device GPS, fixed position, or phone-supplied. `AccuracyMeters`
derives from `gpsStatus->getDOP()` (HDOP·5 m proxy) when an on-device fix is
present; phone-supplied fixes fall back to a conservative 25 m constant since
DOP is GPS-chip-only. Pure helpers for header / row / haversine / ISO-8601 live
in [`persist/WigleFormat.{h,cpp}`](src/forks/valkyrie/persist/WigleFormat.h)
and are covered by [`test/test_wigle_format.cpp`](src/forks/valkyrie/test/test_wigle_format.cpp)
(host-buildable). Discovery uses **passive** `WiFi.scanNetworks` (150 ms/channel, 10 s spacing by default)
so beacon-based rows favor BLE coexistence over probe-heavy active scans.

### Wardrive NVS prefs

| Key (NVS) | C++ field | Default | Notes |
|-----------|-----------|---------|-------|
| `wd_req_fix` | `wardriveRequireFix` | `true` | When true, skip Wigle rows while `getHasUsablePosition()` is false (no on-device fix, no fixed_position, no fresh phone-supplied localPosition). Threats still classify and log. |
| `wd_per_ms` | `wardriveScanPeriodMs` | `10000` (ms) | Period between consecutive passive `WiFi.scanNetworks` bursts. Clamped to [1000, 60000]. |
| `wd_phn` | `wardrivePhoneNotify` | `true` | Forward classifier hits to the phone (PRIVATE_APP + ClientNotification) during a drive. When off, threats still write to `threats.log` but the phone link stays quiet. |

## Build

A parallel PlatformIO env `t-watch-s3-valkyrie` is shipped in
`variants/esp32s3/t-watch-s3-valkyrie/platformio.ini` and is
auto-discovered by `extra_configs = variants/*/*/platformio.ini`. It
extends the upstream `t-watch-s3` env and adds `-DVALKYRIE_FORK=1`,
include path, and `+<forks/valkyrie/>` in `build_src_filter`.

Run commands from the `firmware/` directory:

```bash
pio run -e t-watch-s3-valkyrie
pio run -e t-watch-s3-valkyrie -t upload --upload-port /dev/ttyACM0
```

The original `t-watch-s3` env still builds unchanged.

## Hub UI (BLE + Wi‑Fi sprites)

The Valkyrie hub chibi is driven by `BleThreatDetectorModule` timing, not redraw rate: when a BLE scan window starts, the hub plays wake (reverse sleep strip), the BLE “start scan” clip forward, then loops three BLE “scanning” frames while `isScanActive()` is true. When the BLE window stops, `hubBleWindowEndMs` anchors the synchronous Wi‑Fi promiscuous pass (`isWifiThreatPassActive()`): the BLE “start scan” strip plays in reverse, then the Wi‑Fi “start scan” strip forward and three Wi‑Fi scan loop frames until the pass ends. When the full threat pass completes, `lastScanWindowEndMs` updates; if Wi‑Fi ran, the Wi‑Fi strip reverses, then sleep intro + sleep loop (if Wi‑Fi was skipped, the shorter BLE-only outro still applies). Between passes, sleep loops until the next window; waking reverses “start sleep” before the scan intro. If no pass has completed yet (`lastScanWindowEndMs == 0`), or detection is off or the module is absent, the hub stays on the idle sprite.

## Future plans

Stuff not done yet, or deliberately deferred.

### Phase 2

**BLE wardrive companion:** today's wardriving is Wi‑Fi-only. Still planned: BLE wardrive rows (CSV `Type=BLE`), the same heartbeat-style session screen, and an XP curve that fits beside the shipped threat / mesh / Wi‑Fi wardrive sources without making background scans noisy.

**Threat Sensitivity setting:** A threat warning setting which contains 2 modes, normal and paranoid, defaulted to normal. Paranoid disables the alert alarm fatigue logic. Any deauth, airtag etc. will be considered a threat.

**Wi‑Fi RemoteID:** on-watch **fingerprints only** today; full OpenDroneID message decode (Basic ID, GPS, operator location) and tooling integrations (e.g. mapper-style USB JSON) are not implemented here.

Further **AirTag** logic: stable identity across **rotating** BLE addresses, tighter neighbour vs stalker discrimination, optional multi-window heuristics (partially overlapped with the shipped GPS stalking gate).

### Phase 3 (the UI / gamification phase)

Adding logic so the importance of the notifications will determine the displayed sprite. (threat detected being of the highest importance, meshtastic message notification being second, scanning states, and sleeping being least important) for the sprite on the clock screen only. That way waking the clock you can see that you have a pending notification without swapp to the valkyrie screen.

(optional) A Stats menu (likely in the phone app) that will have the stats of current level, how many threats detected, detected threat types count, total exp, exp to the next level to valkyrie screen.

(optional) Let the phone app handle historical threat logs and experience logic. I could prevent duplicate exp getting rewarded by checking threat type+mac address. The watch would then only have to handle the rolling threat logs, scanning, notifications and ignore list. The historical data could be used to calc stats(num of detected threats and their type) and exp/level would all be on the phone app and sent to the watch when updated for display. If it becomes popular, I could implement an API for the phone app to store statistics and do leaderboards etc. Could even do opt in wardriving to report possible real-time threats to other users who opt in. (it would be cool to have a level up screen in the app and watch. especially if there is an evolution mechanic)

integrate mapping of detected drones and their operators via the open drone id data on both the watch and phone(open id broadcasts the gps coordinates of the drone AND the operator). The mapped icons would last until no signal was received for x period of time.

valkyrie paired node triangulation. use nearby ble/wifi/usb paired nodes(ex. phone + watch) to triangulate threats and give a directional arrow/indicator during heartbeat mode.

### Phase 4: Custom hardware

A list of wishes that would require mass adoption. It would need people familiar with hardware/how cellular works and a custom PCB among other things I probably haven't even thought of yet.

#### Pipe dream

Implement rgba with easy theme swapping. Users could upload their own art and custom color palettes.

Cellular. This would allow imsi catcher/stingray detection because the watch will need/have lower level access to cell data. Plus in general it would give users the ability to use cellular without a phone.

Separate bluetooth/wifi. This will solve the random dropping that occurs when wifi threat detection is enabled because we have to cycle wifi/bluetooth on and off to scan for wifi threats as the bluetooth and wifi module is shared.

physical toggle switches to turn off microphone, bluetooth, wifi, cellular, radio and GPS. Depending on how testing goes it could be placed directly on the back of the watch or under the rear cover. (maybe even on the sides but not sure how much room will be available. ease of access will be key. nobody wants to take a cover off to flip a switch but gd that's a lot of toggle switches)

Waterproofing/resistance and overall just quality.

(integrate custom local llm like gemma on your phone. probably more of a phase 4 thing) This could help determine if threats are legitimate and provide user education/guidance on what they are seeing, how/why it may be dangerous and if it's worth being concerned over/how to avoid being a victim of the threat. This would help normies understand things better and possibly get them interested in cybersecurity. Some of this stuff could be solved with an info button but being able to ask questions/learn is the real magic.

it would be cool to have users opt in to sharing threats and look into building an ML classifier that can flag suspicious bluetooth/wifi/cellular signals/packets.

---

## Acknowledgments

BLE classification leans on patterns and prior art from several communities; I encoded the same *ideas* in NimBLE-friendly C++ on the watch:

- **[ESP32 Marauder](https://github.com/justcallmekoko/ESP32Marauder):** Flock-style camera naming heuristics (the same spirit as `WiFiScan::isFlockCamera`) and the Meta BLE fingerprint (`sniffbt -t meta`: manufacturer 0x01AB, service / service-data 0xFD5F).
- **[colonel panic hacks](https://github.com/colonelpanichacks):** `flock-you` infrastructure OUI list for Flock, **Sky-Spy**-style ASTM F3411 RemoteID over BLE (service UUID 0xFFFA), and Wi‑Fi NAN / beacon vendor-IE fingerprints used for drone Wi‑Fi detection here (fingerprints only).
- **Meta smart glasses:** public writeups and captures (e.g. **NullPxl / banrays**) that match the Marauder Meta filter, which we walk as proper AD records in `BleClassifier`.
- **[AirGuard](https://github.com/seemoo-lab/AirGuard)** (Secure Mobile Networking Lab, TU Darmstadt): the **multi-sighting + location-change** idea behind our GPS-backed AirTag stalking gate, and broader awareness of how consumer trackers behave on BLE. We do not ship their code; our classifier and state machine are independent, but the *problem framing* owes a debt to their open research and app.
