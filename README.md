# Features

What actually ships in this fork today.

- **BLE + Wi‑Fi threat scanning.** BLE scans ride on the existing NimBLE radio. When Wi‑Fi is enabled, the promiscuous pass hops channels **1 / 6 / 11** and runs `WifiFrameClassifier`.
- **Detections covered.** BLE catches AirTag / Find My, Flipper Zero, HC‑03/05/06 skimmers, Flock cameras, Meta Ray‑Ban / Quest gear, and BLE RemoteID. Wi‑Fi catches Flock OUIs and probes, deauth/disassoc, EAPOL, multi‑SSID beacons, Pwnagotchi-style beacons, Pineapple-ish AP vendors, and OpenDroneID / RemoteID fingerprints.
- **Wi‑Fi radio lifecycle.** STA mode is initialized once, then `esp_wifi_stop()` / `esp_wifi_start()` handles idle time between passes. That avoids the old per-cycle `esp_wifi_deinit()` leak while keeping current down. LoRa is a separate SPI radio.
- **AirTag stalking gate.** With a usable position, AirTags need repeated sightings in multiple places before the watch logs, buzzes, or notifies the phone. Without position, they use the normal pattern match plus dedupe window. Matching is by MAC, so rotating addresses can still get weird.
- **Power-aware duty cycle.** BLE runs in scan windows, Wi‑Fi runs at the end when enabled, and the whole pass respects `PowerFSM`, battery state, and sleep notifications.
- **Threat log and phone alerts.** Detections go to `/valkyrie/threats.log` as CSV and, when paired, to the phone over `meshtastic_PortNum_PRIVATE_APP` plus `ClientNotification`. Threats stay off LoRa.
- **Valkyrie menus.** Toggle Bluetooth / Wi‑Fi scanning, tweak settings, view the threat log, check recent XP, enable per-threat types, and manage ignored devices.
- **Ignored devices.** Up to 32 `(threat type, MAC)` pairs live in NVS. Randomized BLE addresses can rotate out from under an ignore, because of course they can.
- **Haptics.** One threat buzz per scan window, so alerts do not get too spicy.
- **Heartbeat mode.** Open a threat row and track that MAC live. BLE rows use continuous NimBLE scan; Wi‑Fi rows lock to the saved channel or hop 1 / 6 / 11 if the channel is unknown. RSSI filtering keeps the sprite and beeps steady.
- **Wardrive mode.** Runs passive Wi‑Fi scans, records usable GPS / phone position, writes Wigle 1.6 CSVs under `/valkyrie/wardrive/`, and awards XP at session end. Hidden networks that never beacon can still be missed, since this is passive.
- **Unified XP.** Threat finds, wardrive sessions, and mesh participation all feed the same `Lvl / Exp / Req` display. Recent XP sources show up in **Exp log**.
- **Digital clock face.** Valkyrie builds add the compact hub chibi overlay to the clock face. Stock builds keep the normal renderer.
- **Fork-local tests.** Small native harnesses live in `forks/valkyrie/test/`; upstream Meshtastic Unity tests stay under `test/`.

## Known issues

Alerts need to be refined for airtag, deauth eapol to prevent fatigue.

if wifi or ble scanning is off, fill in the gap with the only enabled one so we get the full 20 seconds of scanning.

| Upstream file | What changes |
|---------------|----------------|
| [`src/modules/Modules.cpp`](src/modules/Modules.cpp) | `VALKYRIE_FORK` + `__has_include("forks/valkyrie/ValkyrieFork.h")` (include + `valkyrie::setupFork()` at end of `setupModules()`). Stock builds exclude `forks/valkyrie/` via `arduino_base.build_src_filter`. |
| [`src/graphics/Screen.cpp`](src/graphics/Screen.cpp), [`Screen.h`](src/graphics/Screen.h) | Hub frame + long-press opens Valkyrie menu when `VALKYRIE_FORK`. |
| [`src/graphics/draw/MenuHandler.cpp`](src/graphics/draw/MenuHandler.cpp), [`MenuHandler.h`](src/graphics/draw/MenuHandler.h) | Extra `screenMenus` enum values and switch arms for Valkyrie menus when `VALKYRIE_FORK` (incl. wardrive entries). |
| [`src/input/InputBroker.cpp`](src/input/InputBroker.cpp) | Heartbeat **and wardrive** input hooks when `VALKYRIE_FORK`. |
| [`src/graphics/draw/ClockRenderer.cpp`](src/graphics/draw/ClockRenderer.cpp) | When `VALKYRIE_FORK` + `ARCH_ESP32`: digital clock delegates body layout to `forks/valkyrie/ui/ValkyrieDigitalClockLayout` (Valkyrie sprite + top time row); `#else` path unchanged. |
| [`src/modules/Telemetry/DeviceTelemetry.cpp`](src/modules/Telemetry/DeviceTelemetry.cpp) | `VALKYRIE_FORK` + `__has_include("forks/valkyrie/persist/MeshExperience.h")` (one-line hook at the top of `runOnce()` to credit passive mesh-participation XP on the existing 60 s telemetry tick). |
| [`src/GPSStatus.h`](src/GPSStatus.h) | Additive `getHasUsablePosition()` accessor + lat/lon/alt fallback into `localPosition` (gated by a 30 s freshness window from `nodeDB->getLastLocalPositionUpdateMs()`). `getHasLock()` semantics unchanged; only the public lat/lon/alt accessors widened. Stock-safe: no stock caller reads the new accessor. |
| [`src/mesh/NodeDB.h`](src/mesh/NodeDB.h), [`NodeDB.cpp`](src/mesh/NodeDB.cpp) | Stamp `millis()` into a new `lastLocalPositionUpdateMs` member each time `setLocalPosition` receives non-zero coordinates; reset it in `clearLocalPosition`. New `getLastLocalPositionUpdateMs()` accessor. Stock-safe and additive. |
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

The T‑Watch S3 usually gets position from the paired phone, not an onboard GPS
chip. Valkyrie makes `gpsStatus` treat these as usable position sources:

- Real GPS lock, when hardware is present.
- Fixed position mode with non-zero coordinates.
- Fresh phone-supplied `localPosition` from the GATT phone link, currently
  within `GPSStatus::kPhonePositionFreshMs` = 30 s.

`getHasLock()` still means "real GPS chip has a fix", so stock GPS behavior
does not get muddied. The wider `getHasUsablePosition()` is what Valkyrie uses
for AirTag stalking checks, wardrive rows, and UI spots that should accept phone
position.

`getLatitude()` / `getLongitude()` / `getAltitude()` fall back to
`localPosition.*` when there is no chip lock but there is a usable position. In
plain English: a phone-only T‑Watch S3 can still do GPS-backed stalking checks
and Wigle rows without extra hardware. `GeoStalking.cpp` just calls
`getHasUsablePosition()`.

## Wigle CSV format

Wardrive mode writes one **Wigle 1.6**-compatible CSV per session:
`/valkyrie/wardrive/wardrive_<unixSecs>.csv` on LittleFS. The phone app can pull
the files through the Meshtastic file API for Wigle.net upload or offline poking.

```
WigleWifi-1.6,appRelease=Valkyrie,model=T-Watch-S3,release=Meshtastic,device=t-watch-s3,display=NONE,board=ESP32-S3,brand=LilyGo
MAC,SSID,AuthMode,FirstSeen,Channel,Frequency,RSSI,CurrentLatitude,CurrentLongitude,AltitudeMeters,AccuracyMeters,RCOIs,MfgrId,Type
AA:BB:CC:DD:EE:FF,"MyWifi",[WPA2-PSK-CCMP][ESS],2026-05-13 20:30:15,6,2437,-65,40.712800,-74.006000,12.50,5.00,,,WIFI
```

Quick notes:

- `AuthMode` follows Wigle's bracketed-cipher style and ends in `[ESS]` for
  infrastructure APs.
- Lat/Lon/Alt come from `gpsStatus`, so the source can be onboard GPS, fixed
  position, or fresh phone position.
- `AccuracyMeters` uses `getDOP()` as an HDOP * 5 m proxy with real GPS. Phone
  positions use a conservative 25 m fallback.
- Header / row / haversine / time helpers live in
  [`persist/WigleFormat.{h,cpp}`](src/forks/valkyrie/persist/WigleFormat.h) and
  are covered by
  [`test/test_wigle_format.cpp`](src/forks/valkyrie/test/test_wigle_format.cpp).
- Discovery uses passive `WiFi.scanNetworks` by default, about 150 ms per
  channel every 10 s, so it plays nicer with BLE than probe-heavy active scans.

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

The Valkyrie hub chibi follows the scan cycle, not the screen refresh. When BLE scanning starts, it wakes up, plays the BLE scan intro, then loops the BLE scan frames. If the Wi-Fi threat pass runs after BLE, the chibi switches into the Wi-Fi scan intro and loop. Once the full pass is done, it plays the matching outro and goes back to sleeping between scans. If scanning has not started yet, detection is off, or the detector is unavailable, the hub just stays idle.

## Future plans

Stuff not done yet, or deliberately deferred.

### Phase 2

**BLE wardrive companion:** today's wardriving is Wi‑Fi-only. Still planned: BLE wardrive rows (CSV `Type=BLE`), the same heartbeat-style session screen, and an XP curve that fits beside the shipped threat / mesh / Wi‑Fi wardrive sources without making background scans noisy.

**Threat Sensitivity setting:** A threat warning setting which contains 2 modes, normal and paranoid, defaulted to normal. Paranoid disables the alert alarm fatigue logic. Any deauth, airtag etc. will be considered a threat while in paranoid mode xp gain is disabled.

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

Separate BLE and Wi-Fi scanning. Wi-Fi threat detection can make the phone link and BLE scans feel flaky because the ESP32-S3 shares one 2.4 GHz radio for BLE and Wi-Fi. We do not really turn Bluetooth on and off for every Wi-Fi pass, but promiscuous Wi-Fi scanning still steals radio time. Trying to wardrive and BLE-scan at the same time would just time-slice the radio, so both sides would miss more. A cleaner split, or separate hardware later, would make wardrive and threat detection more reliable.

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
- **[AirGuard](https://github.com/seemoo-lab/AirGuard)** (Secure Mobile Networking Lab, TU Darmstadt): the **multi-sighting + location-change** idea behind the GPS-backed AirTag stalking gate, and broader awareness of how consumer trackers behave on BLE. I do not ship their code; the classifier and state machine are independent, but the *problem framing* owes a debt to their open research and app.
