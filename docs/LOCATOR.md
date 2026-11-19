# Locator — where in the house is each device?

`/where` lists every WiFi device with a rough position, and (with three sensors)
draws them on a map of your floor.

It works from signal strength. A few small receivers at known spots each report
how loudly they hear a device; loud means near. Three or more readings place the
device in an area of the floor plan.

## What to expect

- **Room-level, not centimetres.** Walls, furniture and people shift a reading
  by several dB, which is a metre or more. Every position comes with its spread
  (the circle on the map); typical error is 1–3 m.
- **Fewer than three readings never get coordinates.** The list then says
  "near the kitchen sensor (~3 m)" and nothing more.
- **5 GHz devices are only heard by the router.** The sensors are 2.4 GHz
  radios. A phone on 5 GHz shows as "about N m from the router".
- **Only your own devices are shown.** The sensors also hear the neighbours'
  devices; those are dropped because they are not connected to your network.
- Without any sensor, `/where` already works: it shows each device's distance
  from the router.

## What you need

| Item | Notes |
|---|---|
| 3 × ESP32 dev board | Any classic ESP32 or ESP32-C3 board with USB. More than three improves the result. |
| 3 × USB power supply | A phone charger each. They draw about 0.5 W. |
| PlatformIO | To build and flash the firmware once (`pip install platformio`). |

## 1. Flash the sensors

For each board, in `firmware/locator-sensor/`:

1. Copy `include/config.example.h` to `include/config.h` and fill in:
   - `SENSOR_ID` — `s1`, `s2`, `s3` …
   - `WIFI_SSID` / `WIFI_PASSWORD` — the 2.4 GHz network your smart-home devices
     use. The sensor hears whatever shares that access point's channel.
   - `STATIC_IP` (recommended) or reserve the sensor's address on your router.
   - `SENSOR_KEY` — optional shared key.
2. Plug the board in and run `pio run -t upload` (ESP32-C3: `pio run -e esp32-c3 -t upload`).
3. Check it: `pio device monitor` prints the address; opening
   `http://<address>/` in a browser shows a status line.

`config.h` is git-ignored — it holds your WiFi password.

## 2. Place them

- Spread them out: ideally three corners of the home, **not in a line**. A
  device between sensors is located better than one outside them.
- About 1–1.5 m high, in the open (not behind a TV or inside a cabinet).
- One of them fairly close to another (a third of the way, not all three
  equally far apart) lets NetSentry measure how fast the signal falls off in
  your home instead of assuming a typical value.

## 3. Tell NetSentry where they are

Measure the floor as a rectangle and each sensor's position from one corner
(x = across, y = down, in metres). Then in `config.yaml`:

```yaml
  - name: locator
    enabled: true
    config:
      floor:
        width_m: 12
        height_m: 9
        # image: ~/.config/netsentry/floor.png   # optional plan, drawn under the map
      router:                   # where the router/access point stands (optional)
        x: 1.0
        y: 4.0
      sensors:
        - {id: s1, name: Living room, host: 192.0.2.61, x: 0.5, y: 0.5}
        - {id: s2, name: Bedroom,     host: 192.0.2.62, x: 11.5, y: 0.5}
        - {id: s3, name: Kitchen,     host: 192.0.2.63, x: 6.0,  y: 8.5}
      # token: ${vault:LOCATOR_KEY}   # if you set SENSOR_KEY in the firmware
```

If the machine running NetSentry sits *outside* your router and cannot reach the
sensors, add `via_router_port: 8111` (a different port per sensor). NetSentry
then asks the router for one forward per sensor — from the NetSentry host only,
that port only, to that sensor only.

Restart NetSentry and open `/where`.

## Using it

- `/where` — the list. 📍 placed by three or more anchors · ◦ near one sensor ·
  • router only.
- **🗺 Map** — the floor with sensors (squares), devices (dots) and how unsure
  each position is (circles).
- **📡 Sensors** — which sensors answer, how many devices each hears, and where
  the signal model came from.
- `/health` reports a sensor that stopped answering.

## How the numbers are made

Signal strength is turned into distance with the log-distance model
`rssi = level − 10 · n · log10(metres)`. The sensors hear each other, and their
distances are known from the config, so NetSentry measures `level` (and `n`,
when the sensors are not all equally far apart) in your home; otherwise it uses
typical values (−45 dBm at 1 m, n = 3). Set `rssi_at_1m` / `exponent` to fix them
by hand, and `router_gain_db` (default 5) if the router's own readings look
systematically too near or too far.

The position is not a single intersection of circles — with noisy readings those
rarely meet. Every 25 cm cell of the floor is scored by how well it explains all
readings, and the answer is the centre and spread of the likely cells.

## Privacy and security

- A sensor only answers when asked; it stores nothing and sends nothing on its
  own. It reports MAC addresses and signal strength of everything it hears.
- Its HTTP interface has no login beyond the optional shared key. Keep sensors
  on a network you trust (an IoT network that cannot reach your computers is a
  good place).
- NetSentry treats a sensor's answer as untrusted input and shows only devices
  connected to your own network.
