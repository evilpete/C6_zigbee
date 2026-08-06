# IEEE802154 Sniffer

Promiscuous 802.15.4 sniffer for ESP32-C6.
Captures and decodes Zigbee and Thread/Matter traffic.

## Hardware

- ESP32-C6 (4MB or 8MB flash)
- No additional hardware needed — C6 has built-in 802.15.4 radio

## Build

```bash
pio run -e esp32c6_4m        # 4MB board
pio run -e esp32c6_8m        # 8MB board
pio run -t upload -t monitor
```

## Serial output

```
[CH] Protocol     Src          → Dst         PAN     Function          RSSI    Len
─────────────────────────────────────────────────────────────────────────────────
[15] Zigbee       0x1234       → 0x0000      PAN:1A2B  Route Request    -65 dBm   32 B
[15] Thread       0x8F3A       → BCAST       PAN:4321  6LoWPAN          -72 dBm   48 B
[15] 802.15.4     None         → 0xFFFF      PAN:FFFF  Beacon           -58 dBm   23 B
[15] Zigbee       0x4567       → 0x1234      PAN:1A2B  Data             -69 dBm   28 B
```

## Commands (Serial)

| Command | Action |
|---------|--------|
| `c15`   | Set channel 15 |
| `c20`   | Set channel 20 |
| `h`     | Toggle channel hop mode (500ms per channel) |
| `s`     | Print stats |
| `r`     | Reset stats |
| `k`     | Print captured crypto keys |
| `K`     | Save captured keys to SD |
| `p`     | Start/Stop saving Pcap file to SD card |
| `S`     | Scan all channels with a "Beacon Request"|
| `H`     | (re)print column header
| `U`     | Show or hide duplicate host in scan output
| `B`     | Show or hide Broadcast packets in scan output
| `V`     | Toggle verbose `[KC]`/debug logging
| `l`     | List known hosts |
| `W`     | Save known hosts to SD |
| `F`     | List files on SD |
| `t<addr>,<type>,<label>` | Label a host, e.g. `t04A7,R,Ikea Repeater` |
| `j`     | Print join status |
| `J[addr]` | Join the network as a plain end device (ZbJoiner). Auto-picks the most recently seen host advertising association-permit if `addr` is omitted, e.g. `J04A7` to target a specific host. Requires an open network. |
| `P[addr]` | Ping a host via ZDO Node Descriptor request (ZbPing). `P` alone sweeps every known host. Requires a successful `J` join **and** a captured network key — see below. |
| `L[addr]` | `find_lock` — probe a host's endpoints/clusters for the Door Lock cluster (0x0101). `L` alone sweeps every known host. Requires join + network key. |
| `M[addr]` | Spoof our EUI64 to that of a known host (`M` alone restores the real hardware MAC). |
| `R<addr>` | `insecure_rejoin` attack — impersonate a host and send an unsecured rejoin request. **Authorised testing only.** |
| `A[addr]` | `ack_attack` — spoof MAC ACKs to a target to suppress/steal its traffic (`A` alone = stop / status). **Authorised testing only.** |

reads /labels.csv if SD (if exists) for device names

## Offensive probes (ZigDiggity-style) — authorised testing only

> These are active attacks. Only run them against a Zigbee network you own or
> are explicitly authorised to test. They transmit on-air and can disrupt or
> take over devices.

Ports of three attacks from Bishop Fox's [ZigDiggity](https://github.com/BishopFox/zigdiggity):

- **`insecure_rejoin` (`R<addr>`)** — impersonates a known device by spoofing
  its EUI64 (`M`) and sends an *unsecured* NWK Rejoin Request to the
  coordinator. If the Trust Center's policy permits insecure / Trust-Center
  rejoin, it answers with a Rejoin Response and then transports the network
  key encrypted only with the well-known default TCLK — which the existing
  `ZbKeyCapture` pipeline recovers passively. This is the classic way to pull
  the network key off a misconfigured network without waiting for a real join.
  Run `M` (no arg) afterwards to restore the hardware MAC.

- **`ack_attack` (`A<addr>`)** — while armed, the RX ISR watches for data
  frames addressed to the target that request an ACK and injects a spoofed MAC
  ACK immediately, racing the real device. The *sender* then believes delivery
  succeeded while the target may never process the frame — e.g. suppressing a
  sensor's report from reaching the hub. Best-effort: winning the race depends
  on RF proximity and radio turnaround (see `ack_attack` caveats in the code).

- **`find_lock` (`L<addr>` / `L`)** — enumerates a device's endpoints
  (`Active_EP_req`) and each endpoint's clusters (`Simple_Desc_req`) and flags
  any device that exposes the Door Lock cluster (0x0101). Reuses the same ZDO
  request/response + NWK-crypto machinery as `P` (ping), so it needs a join and
  a captured network key.

## Active probing (join / ping)

Beyond passive sniffing, the firmware can act as a (non-functional) network
member to actively probe the mesh:

1. **`J[addr]`** — sends a real MAC Association Request and polls the parent
   (coordinator or router) for the resulting Association Response, the same
   way a battery-powered end device joins. On success it reports the
   assigned short address; the Trust Center's follow-up Transport Key
   exchange is then captured automatically and passively (see below).
2. **`P[addr]`** — once joined and holding a network key, sends a ZDO
   Node Descriptor request/response ("ping", since Zigbee has no ICMP
   equivalent) to a specific host, or `P` to sweep every known host.
   Reports RTT and flags whether the responding device's descriptor is
   new or has changed since the last sighting.

Both require a captured/known **network key** to build valid NWK-layer
frames — either the well-known default keys loaded at boot, or one
captured live via `k`/`K` after a join sequence completes.

## Known bugs fixed

- **Transport Key never decrypted** (root cause): `ZbKeyCapture::processFrame`
  passed the *full* raw frame (from the MAC header) into the NWK-header
  parser instead of slicing it at `macPayloadOffset` first, so every offset
  computed downstream (AUX header, APS layer, ciphertext) started from the
  wrong byte. Fixed.
- **NWK/APS security-bit misreads**: `zbNwkSecurityEnabled` was read from
  bit1 of the NWK frame-control field (part of the 2-bit frame-type field,
  always 0 for Data/Command frames) instead of the spec-correct bit9, so it
  was permanently `false` for real traffic. The AUX header's `hasExtSrc`
  flag was similarly read from the reserved bit6 instead of the
  spec-correct bit5. Both fixed in `IEEE802154Sniffer.cpp` and
  `ZbKeyCapture.cpp`.
- **Hardcoded MIC length**: `_decryptApsPayload` assumed a fixed 4-byte MIC;
  the field notes recorded eISY using MIC-64 (8 bytes) as well. MIC length
  is now derived from `secLevel` per frame.

## Channels

802.15.4 channels 11-26 (2.4 GHz):
- **Zigbee** commonly uses: 11, 15, 20, 25
- **Thread/Matter** commonly uses: 15, 20, 25, 26
- Default: channel 15

## Future roadmap

- [ ] TFT display (TFT_eSPI) — hook is in `onSnifferFrame()`
- ~~[ ] PCap recording to SD card~~
- [ ] ESP32-C5 support
- [ ] Marauder v2/v3 integration
- ~~[ ] Join network as a plain end device~~ (`J` command, `ZbJoiner`)
- ~~[ ] Ping / reachability probe for Zigbee devices~~ (`P` command, `ZbPing`)
- ~~[ ] Assume/clone another device's MAC (EUI64) address~~ (`M` command)
- ~~[ ] insecure_rejoin / ack_attack / find_lock~~ (`R`/`A`/`L`, `ZbAttack`/`ZbPing`)

## Architecture

```
802.15.4 radio ISR
    ↓ rxCallback() — copies frame to FreeRTOS queue
FreeRTOS queue
    ↓ sniffer.update() in loop()
_decodeMac() → _decodeZigbee() / _isThread()
    ↓
_printFrame() → Serial
onFrame()     → TFT (future)
onKeyCapture() → ZbKeyCapture (passive Transport Key capture)
              → ZbJoiner      (active join state machine, 'J')
              → ZbPing        (active ZDO ping 'P' + find_lock 'L')

Offensive:      ZbAttack      (insecure_rejoin 'R', ack_attack 'A')
                sniffer        EUI64 spoof 'M', ACK-inject (RX ISR)
```

Active TX (join requests, data polls, encrypted ping frames) shares the
radio's stop-RX/transmit/resume-RX plumbing via
`IEEE802154Sniffer::sendRawFrame()`; each higher-layer class builds its own
complete frame bytes (MAC header + whatever NWK/APS layers it needs) and
hands them to that one primitive.
