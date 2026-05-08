# Valkyrie fork overlay

Phase 1 of porting [ESP32Valkyrie](https://github.com/SeanAnd/ESP32Valkyrie)
threat detection onto the LilyGo T-Watch S3 running upstream Meshtastic.

The whole overlay lives under `firmware/src/forks/valkyrie/`. A **Valkyrie
build** also touches a small set of upstream files; keep changes there
minimal and behind `#if defined(VALKYRIE_FORK)` (and the same macro plus
`__has_include` in `Modules.cpp` for the fork entry point) so rebasing Meshtastic stays predictable:

| Upstream file | What changes |
|---------------|----------------|
| [`firmware/src/modules/Modules.cpp`](../../modules/Modules.cpp) | `VALKYRIE_FORK` + `__has_include("forks/valkyrie/ValkyrieFork.h")` (include + `valkyrie::setupFork()` at end of `setupModules()`). Stock builds exclude `forks/valkyrie/` via `arduino_base.build_src_filter`. |
| [`firmware/src/graphics/Screen.cpp`](../../graphics/Screen.cpp), [`Screen.h`](../../graphics/Screen.h) | Hub frame + long-press opens Valkyrie menu when `VALKYRIE_FORK`. |
| [`firmware/src/graphics/draw/MenuHandler.cpp`](../../graphics/draw/MenuHandler.cpp), [`MenuHandler.h`](../../graphics/draw/MenuHandler.h) | Extra `screenMenus` enum values and switch arms for Valkyrie menus when `VALKYRIE_FORK`. |
| [`firmware/variants/esp32s3/t-watch-s3-valkyrie/platformio.ini`](../../../variants/esp32s3/t-watch-s3-valkyrie/platformio.ini) | Parallel env: `-DVALKYRIE_FORK=1`, include path, `build_src_filter` for `forks/valkyrie/`. |

Non-Valkyrie builds never define `VALKYRIE_FORK` and do not compile `src/forks/valkyrie/` (see root `platformio.ini` `arduino_base.build_src_filter`), so fork code and graphics hooks compile out.

## Layout

```
forks/valkyrie/
  ValkyrieFork.{h,cpp}              entry point invoked from Modules.cpp
  modules/
    BleThreatDetectorModule.{h,cpp} OSThread that owns the NimBLE scan
    BleClassifier.{h,cpp}           pure: payload -> ThreatType
    AirtagStalkingState.{h,cpp}     GPS-backed multi-sight + multi-place gate for AirTag
    GeoStalking.{h,cpp}             readGeoForStalking() (GPS lock or fixed position)
  prefs/
    ValkyriePrefs.{h,cpp}           private NVS namespace via Preferences
  persist/
    ThreatLog.{h,cpp}               LittleFS append + 32 KB rotate
  proto/
    threat_event.proto              fork-local nanopb schema
    generated/                      pre-generated nanopb sources
  test/                             native unit tests (classifier + stalking state)
  userPrefs.valkyrie.jsonc          fork-only defaults (NOT upstream's)
  regen-proto.sh                    fork-only nanopb generator
```

## Build

A parallel PlatformIO env `t-watch-s3-valkyrie` is shipped in
`firmware/variants/esp32s3/t-watch-s3-valkyrie/platformio.ini` and is
auto-discovered by `extra_configs = variants/*/*/platformio.ini`. It
extends the upstream `t-watch-s3` env and only adds:

- `-DVALKYRIE_FORK=1`
- `build_src_filter += <forks/valkyrie/>`

```bash
pio run -e t-watch-s3-valkyrie
pio run -e t-watch-s3-valkyrie -t upload --upload-port /dev/ttyACM0
```

The original `t-watch-s3` env still builds unchanged.

## Hub UI (BLE scan sprite)

The Valkyrie hub chibi is driven by `BleThreatDetectorModule` timing, not redraw rate: when a BLE scan window starts, the hub plays wake (reverse sleep strip), the BLE “start scan” clip forward, then loops three BLE “scanning” frames while `isScanActive()` is true. When the BLE window stops, `hubBleWindowEndMs` anchors the synchronous Wi‑Fi promiscuous pass (`isWifiThreatPassActive()`): first the **BLE** “start scan” strip plays **in reverse** (close the BLE arc), then the **Wi‑Fi** “start scan” strip forward and three **Wi‑Fi** scan loop frames until the pass ends. When the full threat pass completes, `lastScanWindowEndMs` updates: if Wi‑Fi ran for real, the hub plays the **Wi‑Fi** “start scan” strip in reverse, then sleep intro + sleep loop; if Wi‑Fi was skipped, the legacy BLE outro→sleep timeline from pass end still applies. Between passes, the sleep loop runs until the next window; when scanning resumes, “start sleep” plays in reverse (wake) before the scan intro plays again. If no pass has completed yet (`lastScanWindowEndMs == 0`), or detection is off or the module is absent, the hub stays on the idle sprite.

## Features

What actually ships in this fork today.

- **BLE-only passive scan.** The 2.4 GHz radio is shared with the existing NimBLE GATT server, so scanning piggybacks on it.
- **Classifier** (ported from `WiFiScan.cpp` lines 894-989 of upstream ESP32Valkyrie where applicable): AirTag / Find My (TLV-aware manufacturer `0x004C` parsing plus legacy sliding-window fallbacks, including `4C 00 07 19` style payloads), Flipper Zero, HC-03/05/06 skimmer, Flock camera, Meta Ray-Ban / Quest smart glasses, drone RemoteID broadcasts over BLE. Wi-Fi-side RemoteID parsing stays Phase 2 (future).
- **AirTag + GPS stalking gate:** when `readGeoForStalking()` is true (GPS lock **or** `config.position.fixed_position`, with non-zero lat/lon), **only** `ThreatType::Airtag` must satisfy an AirGuard-style rule before log/haptic/phone emit: at least `stalkMinSightings` (default 3) sightings and at least `stalkMinDistinctPlaces` (default 2) distinct ~`stalkMinSeparationM` metre grid cells for the same BLE MAC. Without usable position, AirTag behaves like other threats: pattern match + `dedupeWindowSecs` only. Correlation is **by MAC**; resolvable private addresses still rotate, so this is best-effort (same limitation as the ignore list). Thresholds live in NVS (`stk_sig`, `stk_plc`, `stk_sep`, `stk_ttl`) with defaults in `ValkyriePrefs::defaults()` / `userPrefs.valkyrie.jsonc`.
- **Power-aware scheduling:** duty-cycled BLE scan window (defaults ~10 s scan every ~30 s between **threat pass** starts; idle gap is `max(0, scanIntervalSecs - scanWindowSecs)` in NVS). Each pass ends with a Wi-Fi threat **placeholder** (real scanning Phase 2), then hub timing updates. Gated on `PowerFSM` state and battery percentage, aborted on `notifyDeepSleep` / `notifyLightSleep`.
- **Sink:** detections written to `/valkyrie/threats.log` on LittleFS (rotate at 32 KB). The intent is to also emit them to the paired phone over `meshtastic_PortNum_PRIVATE_APP` via `service->sendToPhone()` (we never call `sendToMesh()`; stays off the LoRa channel). **That phone path is broken in practice right now;** see [Known issues](#known-issues).
- **Valkyrie menu:** Bluetooth toggle, WiFi toggle (when the build has WiFi), **Settings** (enable/disable detector, constant vs interval BLE scan), **Threat log** (paged viewer over the on-device CSV), **Threats** (per threat-type scan toggles, persisted in NVS), **Ignored devices** (ignore list UI).
- **Ignore list (NVS):** up to 32 `(threat type, MAC)` pairs. While ignored, a device does not trigger log append, haptic, or phone `PRIVATE_APP` events. **Randomized BLE addresses** rotate over time, so MAC-based ignores can stop matching the same physical device.
- **Detection feedback:** at most one threat haptic pulse per scan window when something fires (stock Meshtastic-style buzzer program).
- **Heartbeat mode:** from a threat log row you can start heartbeat mode to hunt a device: haptic, RTTTL beeps, and sprite cadence from proximity (scan pauses while active; display stays on; tap stops heartbeat). Still rough around the edges; see [Known issues](#known-issues).

## Known issues

- **Meshtastic app not getting threat “notifications.”** I’m not seeing detections show up in the stock Meshtastic companion app the way you’d expect for a phone alert, even though the fork tries to push threat events over `PRIVATE_APP` / `sendToPhone()`. Could be decoding on the app side, port handling, protobuf registration, or something else in the chain. Needs a proper pass (and may need a forked or extended client if the official app never surfaces that port the way we need).

## Future plans

Stuff not done yet, or deliberately deferred.

### Phase 2

**Partially shipped:** GPS-backed multi-sight + multi-place stalking gate for AirTag (see Features). Remaining ideas: stable tracker identity across **rotating** BLE addresses (payload-derived fingerprint), tighter neighbour vs stalker discrimination, and optional “must span multiple scan windows” heuristics.

### Phase 3 (the UI / gamification phase)

Add experience dependant on the threat type detected. The rarer the threat the more experience gained just like my esp32valkyrie repo. The difficulty to level grows at a steady rate.

Add a small chibi themed valkyrie icon on the watches time screen. The sprite will change depending on its current action, just like the Valkyrie menu changing depending on what it's doing or detected. The importance of the notifications will determine the displayed sprite. (threat detected being of the highest importance, meshtastic message notification being second, scanning states, and sleeping being least important).

A Stats menu that will have the stats of current level, how many threats detected, detected threat types count, total exp, exp to the next level to valkyrie screen.

(optional) Let the phone app handle historical threat logs and experience logic. I could prevent duplicate exp getting rewarded by checking threat type+mac address. The watch would then only have to handle the rolling threat logs, scanning, notifications and ignore list. The historical data could be used to calc stats(num of detected threats and their type) and exp/level would all be on the phone app and sent to the watch when updated for display. If it becomes popular, I could implement an API for the phone app to store statistics and do leaderboards etc. Could even do opt in wardriving to report possible real-time threats to other users who opt in. (it would be cool to have a level up screen in the app and watch. especially if there is an evolution mechanic)

integrate mapping of detected drones and their operators via the open drone id data on both the watch and phone(open id broadcasts the gps coordinates of the drone AND the operator). The mapped icons would last until no signal was received for x period of time.

valkyrie paired node triangulation. use nearby ble/wifi/usb paired nodes(ex. phone + watch) to triangulate threats and give a directional arrow/indicator during heartbeat mode.

### Phase 4: Custom hardware

A list of wishes that would require mass adoption. It would need people familiar with hardware/how cellular works and a custom PCB among other things I probably haven't even thought of yet.

#### Pipe dream

Contribute to UI/UX to make it more responsive and improve the experience for everyone. Implement rgba with easy theme swapping. Users could upload their own art and custom color palettes.

Cellular. This would allow imsi catcher/stingray detection because the watch will need/have lower level access to cell data. Plus in general it will give users the ability to use cellular without a phone.

Separate bluetooth/wifi. This will solve the random dropping that occurs when wifi threat detection is enabled because we have to cycle wifi/bluetooth on and off to scan for wifi threats as the bluetooth and wifi module is shared.

physical toggle switches to turn off microphone, bluetooth, wifi, cellular, radio and GPS. Depending on how testing goes it could be placed directly on the back of the watch or under the rear cover. (maybe even on the sides but not sure how much room will be available. ease of access will be key. nobody wants to take a cover off to flip a switch but gd that's a lot of toggle switches)

Waterproofing/resistance and overall just quality. I want to build something that will last and extends the functionality of your phone. Not just an expensive wrist phone that collects biometric data to sell to the highest bidder.

(integrate custom local llm like gemma on your phone. probably more of a phase 4 thing) This could help determine if threats are legitimate and provide user education/guidance on what they are seeing, how/why it may be dangerous and if it's worth being concerned over/how to avoid being a victim of the threat. This would help normies understand things better and possibly get them interested in cybersecurity. Some of this stuff could be solved with an info button but being able to ask questions/learn is the real magic.

it would be cool to have users opt in to sharing threats and look into building an ML classifier that can flag suspicious bluetooth/wifi/cellular signals/packets.

---

## Acknowledgments

BLE classification leans on patterns and prior art from several communities; I encoded the same *ideas* in NimBLE-friendly C++ on the watch:

- **[ESP32 Marauder](https://github.com/justcallmekoko/ESP32Marauder):** Flock-style camera naming heuristics (the same spirit as `WiFiScan::isFlockCamera`) and the Meta BLE fingerprint (`sniffbt -t meta`: manufacturer 0x01AB, service / service-data 0xFD5F).
- **[colonel panic hacks](https://github.com/colonelpanichacks):** `flock-you` infrastructure OUI list for Flock, and **Sky-Spy**-style ASTM F3411 RemoteID over BLE (service UUID 0xFFFA) for drone presence.
- **Meta smart glasses:** public writeups and captures (e.g. **NullPxl / banrays**) that match the Marauder Meta filter, which we walk as proper AD records in `BleClassifier`.
- **[AirGuard](https://github.com/seemoo-lab/AirGuard)** (Secure Mobile Networking Lab, TU Darmstadt): the **multi-sighting + location-change** idea behind the GPS-backed AirTag stalking gate, and broader awareness of how consumer trackers behave on BLE. We do not ship their code; our classifier and state machine are independent, but the *problem framing* owes a debt to their open research and app.