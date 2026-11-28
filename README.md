# MeshCore Observer, with the fork's features

> ## ⬇️ Get the firmware: [sweden-mesh.github.io/firmware](https://sweden-mesh.github.io/firmware/)
>
> **Flash a node from the [firmware page](https://sweden-mesh.github.io/firmware/)**, not from
> this repository. Pick the node type, the features and the board: it gives you one file, how to
> flash it, and the console commands to set it up. Every file is also in the
> [latest release](https://github.com/sweden-mesh/MeshCore-lou/releases/latest).

**This repository is a fork**, kept by sweden-mesh, of [MeshCore](https://github.com/meshcore-dev/MeshCore)
and [agessaman's MeshCore Observer](https://github.com/agessaman/MeshCore). It is not the official
MeshCore. Two branches carry the fork: `fork/observer` (this one, on the Observer) and
[`fork/core`](https://github.com/sweden-mesh/MeshCore-lou/tree/fork/core) (on stock MeshCore).

## Flavours

Each release is built in four flavours, all repeaters. The
[firmware page](https://sweden-mesh.github.io/firmware/) picks the right one for you.

| flavour | built from | boards | for |
|---|---|---|---|
| **Auto-reply** (`ar`) | stock MeshCore, `fork/core` | 93: ESP32, nRF52, RP2040, STM32 | a repeater that answers `test` on its county's test channel, no Wi-Fi needed |
| **Remote control** (`rc`) | stock MeshCore, `fork/core` | 93 | signed commands over the mesh, from a companion radio or through an Observer relay; no Wi-Fi needed (from lou-20) |
| **Both** (`arrc`) | stock MeshCore, `fork/core` | 92 | both of the above |
| **Observer** (`arrc`) | the Observer, `fork/observer` | 33 ESP32 | auto-reply and remote control in one image, each off until a setting switches it on, plus reporting what it hears to MQTT and updating itself over Wi-Fi. Up to lou-20 there were also Observer `ar` and `rc` images: their nodes update to this one, and the feature they lacked starts off ([docs/ota.md](docs/ota.md)) |

What the features do:

- **Auto-reply** ([docs/autoreply.md](docs/autoreply.md)): the repeater answers `test` on
  `#test-<region>`, where the region is its `region home` (for example `#test-se-jkp`), so
  anyone can see which repeaters hear them. Replies wait 10 to 120 seconds in a slot of their
  own so they don't collide, and are rate limited. It also answers on the national `#test-se`
  (`set autoreply.national auto|off|<region>`) and, on an Observer node, on the legacy
  `#test-<iata>`.
- **Remote control** ([docs/mqtt-control.md](docs/mqtt-control.md)): console commands sent over
  MQTT or over the mesh, signed with the owner's Ed25519 key and checked on the node. The key is
  set by cable, once over the admin login for a node without one, and replaced with `rekey`.
  Identity, radio and destructive commands are refused. On stock boards remote control works
  over the mesh only. Sent with [mccontrol](https://mccontrol.meshcoresverige.se). From lou-20
  the settings are `cmd` (`set cmd on`); the `mqtt.cmd` names of lou-18 are gone. From lou-21
  the node speaks one scheme, mcc3, and the old topics and requests are gone:
  [upgrading to lou-21](docs/mqtt-control.md#upgrading-to-lou-21). Also from lou-20:
  - [The relay](docs/mqtt-control.md#relaying-one-nodes-mqtt-for-another-nodes-command-lou-20): an Observer node
    sends its owner's commands over the air to the owner's nodes without Wi-Fi and returns the
    answers, one at a time, on a fixed airtime and flood budget. `set relay any|own|off`; from
    lou-21 `any`, the default, serves other owners too, within caps.
  - [Over the mesh](docs/mqtt-control.md#over-the-mesh-when-wi-fi-or-the-broker-is-down-lou-19): an Observer node
    takes the same signed commands from a companion radio when its broker is down.
    `set cmd.mesh off|on|auto`.
  - [The alive message](docs/mqtt-control.md#mcc3-keyed-by-the-node-sealed-to-its-owner-lou-20): an Observer node
    announces itself, sealed to its owner, so the tools find it. `set alive.interval <5-1440>`
    (minutes).
  - [`time <epoch>`](docs/mqtt-control.md#mending-a-clock-over-the-mesh-time-epoch) mends a clock that fell
    behind, over the mesh only; [`get sensors`](docs/mqtt-control.md#what-may-be-sent) reads the node's sensors;
    [`set cmd.debug on|off`](docs/mqtt-control.md#joining-the-log-lines) prints the plane's decisions on the
    serial console.
- **Signed OTA** ([docs/ota.md](docs/ota.md)): every Observer image. `ota update` fetches the
  latest release over Wi-Fi and installs it only if the signature checks out. The stock
  flavours have none.
- **Auto-scope** (`as`): reserved, not built yet.

Not here: with no features, use [MeshCore's own flasher](https://meshcore.io/flasher); for the
Observer alone, [agessaman's Observer firmware](https://observer.gessaman.com/).

An image names its flavour in the file and in `ver`:
`<board>-<mcu>-v<MeshCore version>-lou-<nn>-<features>-<hash>`, for example
`Heltec_v3_repeater_observer_mqtt-esp32s3-v1.18.0-lou-20-ar-9c6c0a0.bin`.

## For developers

This branch adds auto-reply, signed remote control over MQTT and signed pull
OTA to the MeshCore Observer firmware, released as one image (`arrc`) from lou-21:
[`docs/fork.md`](docs/fork.md) for the combinations and how they are built,
[`docs/fork-overview.md`](docs/fork-overview.md) for what they do,
[`docs/quick-check-guide.md`](docs/quick-check-guide.md) for setting up a repeater, and
[`docs/fork-contributing.md`](docs/fork-contributing.md) before changing anything.
The Observer's and upstream's own README follows.

---

## About MeshCore

MeshCore is a lightweight, portable C++ library that enables multi-hop packet routing for embedded projects using LoRa and other packet radios. It is designed for developers who want to create resilient, decentralized communication networks that work without the internet.

## 🔍 What is MeshCore?

MeshCore now supports a range of LoRa devices, allowing for easy flashing without the need to compile firmware manually. Users can flash a pre-built binary using tools like Adafruit ESPTool and interact with the network through a serial console.
MeshCore provides the ability to create wireless mesh networks, similar to Meshtastic and Reticulum but with a focus on lightweight multi-hop packet routing for embedded projects. Unlike Meshtastic, which is tailored for casual LoRa communication, or Reticulum, which offers advanced networking, MeshCore balances simplicity with scalability, making it ideal for custom embedded solutions, where devices (nodes) can communicate over long distances by relaying messages through intermediate nodes. This is especially useful in off-grid, emergency, or tactical situations where traditional communication infrastructure is unavailable.

> **MQTT Observer Setup:** prebuilt observer firmware, docs, and a changelog are at
> [observer.gessaman.com](https://observer.gessaman.com/). See the
> [MQTT Implementation Guide](./MQTT_IMPLEMENTATION.md) for configuration, CLI commands, and
> troubleshooting.

## ⚡ Key Features

* Multi-Hop Packet Routing
  * Devices can forward messages across multiple nodes, extending range beyond a single radio's reach.
  * Supports up to a configurable number of hops to balance network efficiency and prevent excessive traffic.
  * Nodes use fixed roles where "Companion" nodes are not repeating messages at all to prevent adverse routing paths from being used.
* Supports LoRa Radios – Works with Heltec, RAK Wireless, and other LoRa-based hardware.
* Decentralized & Resilient – No central server or internet required; the network is self-healing.
* Low Power Consumption – Ideal for battery-powered or solar-powered devices.
* Simple to Deploy – Pre-built example applications make it easy to get started.

## 🎯 What Can You Use MeshCore For?

* Off-Grid Communication: Stay connected even in remote areas.
* Emergency Response & Disaster Recovery: Set up instant networks where infrastructure is down.
* Outdoor Activities: Hiking, camping, and adventure racing communication.
* Tactical & Security Applications: Military, law enforcement, and private security use cases.
* IoT & Sensor Networks: Collect data from remote sensors and relay it back to a central location.

## 🚀 How to Get Started

- Watch the [MeshCore QuickStart Playlist](https://www.youtube.com/watch?v=iaFltojJrAc&list=PLshzThxhw4O4WU_iZo3NmNZOv6KMrUuF9) by The Comms Channel
- Watch the [MeshCore Technical Presentation](https://www.youtube.com/watch?v=OwmkVkZQTf4) by Liam Cottle.
- Read through our [Frequently Asked Questions](./docs/faq.md) and [Documentation](https://docs.meshcore.io).
- Flash the MeshCore firmware on a supported device.
- Connect with a supported client.

For developers:

- Install [PlatformIO](https://docs.platformio.org) in [Visual Studio Code](https://code.visualstudio.com).
- Clone and open the MeshCore repository in Visual Studio Code.
- See the example applications you can modify and run:
  - [Companion Radio](./examples/companion_radio) - For use with an external chat app, over BLE, USB or Wi-Fi.
  - [KISS Modem](./examples/kiss_modem) - Serial KISS protocol bridge for host applications. ([protocol docs](./docs/kiss_modem_protocol.md))
  - [Simple Repeater](./examples/simple_repeater) - Extends network coverage by relaying messages.
  - [Simple Room Server](./examples/simple_room_server) - A simple BBS server for shared Posts.
  - [Simple Secure Chat](./examples/simple_secure_chat) - Secure terminal based text communication between devices.
  - [Simple Sensor](./examples/simple_sensor) - Remote sensor node with telemetry and alerting.

The Simple Secure Chat example can be interacted with through the Serial Monitor in Visual Studio Code, or with a Serial USB Terminal on Android.

## ⚡️ MeshCore Flasher

We have prebuilt firmware ready to flash on supported devices.

- Launch https://meshcore.io/flasher
- Select a supported device
- Flash one of the firmware types:
  - Companion, Repeater or Room Server
- Once flashing is complete, you can connect with one of the MeshCore clients below.

## 📱 MeshCore Clients

**Companion Firmware**

The companion firmware can be connected to via BLE, USB or Wi-Fi depending on the firmware type you flashed.

- Web: https://app.meshcore.nz
- Android: https://play.google.com/store/apps/details?id=com.liamcottle.meshcore.android
- iOS: https://apps.apple.com/us/app/meshcore/id6742354151?platform=iphone
- NodeJS: https://github.com/liamcottle/meshcore.js
- Python: https://github.com/fdlamotte/meshcore-cli

**Repeater and Room Server Firmware**

The repeater and room server firmware can be set up via USB in the web config tool.

- https://config.meshcore.io

They can also be managed via LoRa in the mobile app by using the Remote Management feature.

## 🛠 Hardware Compatibility

MeshCore is designed for devices listed in the [MeshCore Flasher](https://meshcore.io/flasher)

## 📜 License

MeshCore is open-source software released under the MIT License. You are free to use, modify, and distribute it for personal and commercial projects.

## Contributing

Please submit PR's using 'dev' as the base branch!
For minor changes just submit your PR and we'll try to review it, but for anything more 'impactful' please open an Issue first and start a discussion. It is better to sound out what it is you want to achieve first, and try to come to a consensus on what the best approach is, especially when it impacts the structure or architecture of this codebase.

Here are some general principles you should try to adhere to:
* Keep it simple. Please, don't think like a high-level lang programmer. Think embedded, and keep code concise, without any unnecessary layers.
* No dynamic memory allocation, except during setup/begin functions.
* Use the same brace and indenting style that's in the core source modules. (A .clang-format is probably going to be added soon, but please do NOT retroactively re-format existing code. This just creates unnecessary diffs that make finding problems harder)

Help us prioritize! Please react with thumbs-up to issues/PRs you care about most. We look at reaction counts when planning work.

### Running unit tests

To run unit tests, run the following command:

```bash
pio test --environment native --verbose
```

## Road-Map / To-Do

There are a number of fairly major features in the pipeline, with no particular time-frames attached yet. In very rough chronological order:
- [X] Companion radio: UI redesign
- [X] Repeater + Room Server: add ACL's (like Sensor Node has)
- [X] Standardise Bridge mode for repeaters
- [ ] Repeater/Bridge: Standardise the Transport Codes for zoning/filtering
- [X] Core + Repeater: enhanced zero-hop neighbour discovery
- [ ] Core: round-trip manual path support
- [ ] Companion + Apps: support for multiple sub-meshes (and 'off-grid' client repeat mode)
- [ ] Core + Apps: support for LZW message compression
- [ ] Core: dynamic CR (Coding Rate) for weak vs strong hops
- [ ] Core: new framework for hosting multiple virtual nodes on one physical device
- [ ] V2 protocol spec: discussion and consensus around V2 packet protocol, including path hashes, new encryption specs, etc

## 📞 Get Support

- Report bugs and request features on the [GitHub Issues](https://github.com/meshcore-dev/meshcore/issues) page.
- Find additional guides and components on [my site](https://buymeacoffee.com/ripplebiz).
- Join [MeshCore Discord](https://meshcore.gg) to chat with the developers and get help from the community.
