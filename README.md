# Valkyrie fork overlay

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
| [`src/graphics/draw/MenuHandler.cpp`](src/graphics/draw/MenuHandler.cpp), [`MenuHandler.h`](src/graphics/draw/MenuHandler.h) | Extra `screenMenus` enum values and switch arms for Valkyrie menus when `VALKYRIE_FORK`. |
| [`src/input/InputBroker.cpp`](src/input/InputBroker.cpp) | Heartbeat input hook when `VALKYRIE_FORK`. |
| [`src/graphics/draw/ClockRenderer.cpp`](src/graphics/draw/ClockRenderer.cpp) | When `VALKYRIE_FORK` + `ARCH_ESP32`: digital clock delegates body layout to `forks/valkyrie/ui/ValkyrieDigitalClockLayout` (Valkyrie sprite + top time row); `#else` path unchanged. |
| [`src/modules/Telemetry/DeviceTelemetry.cpp`](src/modules/Telemetry/DeviceTelemetry.cpp) | `VALKYRIE_FORK` + `__has_include("forks/valkyrie/persist/MeshExperience.h")` (one-line hook at the top of `runOnce()` to credit passive mesh-participation XP on the existing 60 s telemetry tick). |
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
  ui/                               menus, hub frame, heartbeat UI/input
  prefs/
    ValkyriePrefs.{h,cpp}           private NVS namespace via Preferences
  persist/
    ThreatLog.{h,cpp}               LittleFS append + 32 KB rotate
    ThreatLogDecode.{h,cpp}         pure CSV decode helpers (host-testable)
    ThreatIgnoreList.{h,cpp}        NVS ignore list backing store
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

## Features

What actually ships in this fork today.

- **BLE passive scan.** The 2.4 GHz radio is shared with the existing NimBLE GATT server, so scanning piggybacks on it.
- **Wi‑Fi promiscuous threat pass** (`WifiThreatPass.cpp`, when `HAS_WIFI` and prefs allow): hops channels **1 / 6 / 11**, passive classification via **`WifiFrameClassifier`** — Flock infra OUI + wildcard probe requests (`FlockOuiTable.h`), **deauth/disassoc**, **EAPOL**, **multi‑SSID** beacons, **Pwnagotchi**-style JSON beacon heuristic, **suspicious AP** vendor OUIs (incl. Pineapple-class), **OpenDroneID / RemoteID Wi‑Fi fingerprints** (NAN destination MAC + vendor IE OUIs per Sky‑Spy; detection only, no full telemetry decode). Implementation lives in **`WifiThreatPass`** / **`WifiFrameClassifier`**, not a separate `WifiThreatDetectorModule`.
- **Wi‑Fi driver lifecycle:** STA mode is initialized once and the driver stays resident so we never hit per-cycle `esp_wifi_deinit()` (that path leaked ~48 B/cycle). Between passes the modem is powered down with **`esp_wifi_stop()`** and brought back with **`esp_wifi_start()`** for lower idle current; **`WifiThreatPassPolicy.h`** documents the cold/hot/teardown contract. After the first Wi‑Fi pass, a baseline of internal heap remains reserved for the driver for the rest of uptime (stable vs leaking). **LoRa (SX126x)** is unrelated — separate SPI radio.
- **Classifier (BLE)** (patterns from upstream ESP32Valkyrie `WiFiScan.cpp` where applicable): AirTag / Find My (TLV-aware `0x004C` manufacturer parsing + legacy fallbacks), Flipper Zero, HC‑03/05/06 skimmer, Flock camera, Meta Ray‑Ban / Quest smart glasses, drone RemoteID over BLE (service `0xFFFA`).
- **AirTag + GPS stalking gate:** when `readGeoForStalking()` is true (GPS lock **or** `config.position.fixed_position`, non-zero lat/lon), **only** `ThreatType::Airtag` must meet an AirGuard-style rule before log/haptic/phone emit: at least `stalkMinSightings` (default 3) sightings and `stalkMinDistinctPlaces` (default 2) distinct ~`stalkMinSeparationM` grid cells for the same BLE MAC. Without position, AirTag uses pattern match + `dedupeWindowSecs` only. Correlation is **by MAC**; rotating addresses limit reliability. Thresholds in NVS (`stk_*`) / `userPrefs.valkyrie.jsonc`.
- **Power-aware scheduling:** duty-cycled BLE scan window (defaults ~10 s scan every ~30 s between threat-pass starts; idle gap `max(0, scanIntervalSecs - scanWindowSecs)` in NVS). Each pass ends with the Wi‑Fi promiscuous phase when enabled, then hub timing updates. Gated on `PowerFSM` state and battery percentage; aborted on `notifyDeepSleep` / `notifyLightSleep`.
- **Sink:** detections written to `/valkyrie/threats.log` on LittleFS (rotate at 32 KB). CSV columns: `type,timestamp_secs,mac,name,rssi,detail,source,channel` — `source` is `BLE` or `WIFI` (where the detection came from), `channel` is the Wi‑Fi channel (1/6/11) for Wi‑Fi rows or 0 for BLE; both drive heartbeat radio + lock. Legacy 6-column rows from older builds are still parsed (source inferred from type). On paired BLE, events also go to the phone as **`meshtastic_PortNum_PRIVATE_APP`** protobuf (`sendToPhone()`), plus **`ClientNotification`** bursts at pass end / immediate alerts where applicable — traffic stays off LoRa (`sendToMesh()` is not used for threats).
- **Valkyrie menu:** Bluetooth toggle, WiFi toggle (when the build has WiFi), **Settings** (enable/disable detector, constant vs interval BLE scan), **Threat log** (paged CSV viewer), **Threats** (per-type toggles, NVS), **Ignored devices** (ignore list UI).
- **Ignore list (NVS):** up to 32 `(threat type, MAC)` pairs. **Randomized BLE addresses** rotate over time, so MAC-based ignores can stop matching the same physical device.
- **Detection feedback:** at most one threat haptic pulse per scan window when something fires (stock Meshtastic-style buzzer program).
- **Heartbeat mode:** from a threat log row — continuous passive scan on the target MAC, haptic, RTTTL beeps, and sprite strength from filtered RSSI / tier (EMA + hysteresis). Duty-cycle scanning pauses while heartbeat runs; display stays on; tap exits back into the Valkyrie flow. The radio path is driven by the row's stored `source`: **BLE rows** use NimBLE continuous scan with duplicates on; **Wi‑Fi rows** drop into `esp_wifi` promiscuous and lock to the row's stored `channel` (1/6/11) for fast RSSI updates, falling back to a 1/6/11 hop when the channel is unknown (legacy rows). Both paths feed the same `HeartbeatRssiFilter` so the UI is identical.
- **Fork-local tests:** `forks/valkyrie/test/` holds small native `.cpp` harnesses (classifier, stalking state, Wi‑Fi frame helpers, heartbeat RSSI); excluded from the firmware build via `build_src_filter`. Meshtastic Unity suites live under `test/` (see `test/README.md`).

## Known issues

Alerts need to be refined for airtag, deauth eapol to prevent fatigue.

Heartbeat indicator could use some work, maybe a 4th signal indicator to show when you are right on top of something. Shorter/weaker vibrations on weak signals too.

if wifi or ble scanning is off, fill in the gap with the only enabled one so we get the full 20 seconds of scanning.

## Future plans

Stuff not done yet, or deliberately deferred.

### Phase 2

**More ways to exp:** An exp log displaying exp gained and its source. Passive **mesh-participation XP** now ships: a 60 s tick (piggybacked on `DeviceTelemetryModule::runOnce()`) reads the `RadioLibInterface` + `Router` counters that already feed `LocalStats` (`txRelay` / `txRelayCanceled` / `rxGood`, with an `rxDupe` penalty), credits weighted XP for the delta, and feeds a unified hub-HUD level (threat XP + mesh XP) via `forks/valkyrie/persist/MeshExperience.{h,cpp}`. Still planned: an exp log UI showing source-tagged gains, and **wardriving** XP (active exping. Networks scanned+distance+threats found that's session based via heartbeat style screen with stats and tap to stop).

**Wi‑Fi deauth / disassoc & EAPOL false alarms:** today these are **single-frame heuristics** (management deauth/disassoc; data frames with EAPOL LLC snap). Future work: **rate limits and burst detection** (ignore one-off noise; require sustained or patterned abuse), **pair-aware context** (relate source/destination MAC and optional BSSID roles where inferable), **EAPOL sanity** (handshake phase hints vs stray encrypted garbage), and optional **SSID / privacy / channel** context so normal roaming or noisy cafés don’t look like attacks. Goal: fewer false positives without hiding real incidents.

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

Contribute to UI/UX to make it more responsive and improve the experience for everyone. Implement rgba with easy theme swapping. Users could upload their own art and custom color palettes.

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
