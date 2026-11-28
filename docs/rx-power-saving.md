# RX power saving (images without Wi-Fi)

The radio sleeps between short listening windows instead of listening all the time, timed so a
sender's preamble always falls into a window. On a solar node it is most of what the node
draws: IoTThinks measured a RAK4631 at 0.9 to 6.0 mA with it against 6.0 mA with the CPU sleep
(`powersaving on`) alone.

The feature is IoTThinks' **PowerSaving 18** (`IoTThinks/MeshCore`, branch `PowerSaving-v18`,
by Kevin Le / IoTThinks; the SX1262 timer workaround by Jarosław Domański), taken into the core
images (`fork/core`) of this fork with its own commands and settings. MIT, as MeshCore.

## Off until you switch it on

A node that never types `set radio.rxps` runs exactly as MeshCore 1.18: the image carries the
feature, the settings file does not turn it on, and the radio is driven call for call as before
(`test/test_rx_power_saving_off`). Unlike PowerSaving 18, nothing else changes either: the
`powersaving` default (off), the FEM LNA, the TX power, the TCXO start-up time (RadioLib's
5 ms), the RadioLib version and the ESP32 core are MeshCore's.

Observer images do not have it: their Wi-Fi draws far more than the radio. STM32 images
(RAK3172, Wio-E5) do not either: their radio cannot duty-cycle here.

## Commands

The same names and replies as PowerSaving 18, so its users' habits carry over:

- `set radio.rxps balanced` -- level 6 with the 16-symbol profile; `on` and `conservative` are
  level 3, `max` level 8.
- `set radio.rxps overdrive` (level 9) and `set radio.rxps riskyWorkingMax` (level 10) run
  outside the datasheet's timing rule: overdrive measured lossless by its author,
  riskyWorkingMax drops about 2 % of packets by design.
- `set radio.rxps level <1-10> [preamble <16|32>]`, `set radio.rxps max|overdrive|riskyWorkingMax
  preamble <16|32>`
- `set radio.rxps <rx_us> <sleep_us>` -- manual periods, 1 000 to 30 000 000 µs.
- `set radio.rxps off`
- `get radio.rxps` -- `desired` (the saved choice), `effective` (`armed` or `continuous`),
  `supported`, `err`, `fail` (arm failures), `level`, `catch` (preamble symbols still caught),
  `preamble`, `rx`/`sleep` (µs), and `erx`/`eslp` when the driver adjusted them.

A setting takes effect at once and is saved. Radios: SX1262 and LR1110. SX1268, LLCC68,
LR1121, LR2021 and SX127x answer `supported=no` and stay in continuous RX.

**The preamble profile.** The named presets assume the worst case a mixed mesh can present, a
sender with a 16-symbol preamble (MeshCore 1.15 and older). From 1.16 a sender at SF 8 or lower
uses 32 symbols, and `level <n>` without `preamble` follows that. At SF8/BW62.5, worked out by
the calculator with this tree's TCXO time:

| setting | listens | sleeps | share listening |
|---|---|---|---|
| `conservative` (3, P16) | 57.2 ms | 11.5 ms | 83 % |
| `balanced` (6, P16) | 51.0 ms | 23.8 ms | 68 % |
| `max` (8, P16) | 46.9 ms | 32.0 ms | 59 % |
| `overdrive` (9, P16) | 32.8 ms | 41.0 ms | 44 % |
| `level 6` (P32 at SF8) | 51.0 ms | 89.3 ms | 36 % |
| `overdrive preamble 32` | 32.8 ms | 106.5 ms | 24 % |

A P32 profile on a mesh that still has 1.15 senders misses some of their packets.

**Errors.** A profile that does not fit the active SF/BW is refused; after `set radio` it leaves
the node in continuous RX with `err=-10001` while the saved choice is kept. After three failed
arm attempts the node stays in continuous RX until the setting changes.

**With the CPU sleep.** `powersaving on` (MeshCore's) lets the processor sleep between events;
RX power saving lets the radio sleep. Both are needed for the full saving. While RX power
saving measures the noise floor (5 s a minute in continuous RX) the processor stays awake.

## What it does around this fork's features

- **Reports.** A node reporting to an Observer node (`docs/mqtt-control.md`, "Reporting to an
  Observer node nearby") keeps its receiver awake from each try until 3.2 s after it has gone
  out, the latest a zero-hop ack starts, so the ack never meets a sleeping radio.
- **The control plane.** `set radio.rxps ...` is a radio setting: refused over MQTT and the
  mesh road like every `set radio...` (`mqttCtrlCommandDenied`), so it is changed at the node's
  console or through a mesh admin login. `get radio.rxps` travels.
- **Settings.** Five keys in the `radio` object of `/prefs.json`, PowerSaving 18's own:
  `rxps_en`, `rxps_rx_us`, `rxps_sleep_us`, `rxps_level`, `rxps_preamble`. A file without them
  (MeshCore's, or this fork's before lou-21) loads with RX power saving off; MeshCore reading
  this fork's file skips them. A node moved from PowerSaving 18 keeps its choice.

## Known

PowerSaving 18's release notes (30 Oct 2026) report an RX problem on the T-Echo with it on;
`set radio.rxps off` is the cure there.

## Building without it

`-DNO_RX_POWERSAVING=1` leaves it out: the wrappers compile to MeshCore's own code. The flash it
costs, `arrc`, measured on `fork/core`:

| board | flash without | with | cost |
|---|---|---|---|
| Xiao_nrf52_repeater (nRF52840, SX1262) | 412 544 | 423 456 | +10 912 B of 811 008 |
| RAK_4631_repeater (nRF52840, SX1262) | 492 796 | 503 452 | +10 656 B of 815 104 |
| t1000e_repeater (nRF52840, LR1110) | 347 652 | 357 988 | +10 336 B of 811 008 |
| Heltec_v3_repeater (ESP32-S3) | 1 225 829 | 1 235 005 | +9 176 B of 3 342 336 |
| Tenstar_C3_sx1262_repeater (ESP32-C3) | 1 203 280 | 1 212 662 | +9 382 B of 1 310 720 (92.5 %) |
| Xiao_rp2040_repeater (RP2040) | 269 848 | 277 672 | +7 824 B of 1 568 768 |
| wio-e5_repeater (STM32WLE5) | 227 968 | 227 968 | none: not built in |

RAM: 88 to 96 bytes. With `-DNO_RX_POWERSAVING=1` the Xiao nRF52 image is byte for byte the size
it was before (412 544).
