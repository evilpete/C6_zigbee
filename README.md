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

## Channels

802.15.4 channels 11-26 (2.4 GHz):
- **Zigbee** commonly uses: 11, 15, 20, 25
- **Thread/Matter** commonly uses: 15, 20, 25, 26
- Default: channel 15

## Future roadmap

- [ ] TFT display (TFT_eSPI) — hook is in `onSnifferFrame()`
- [ ] PCap recording to SD card
- [ ] ESP32-C5 support
- [ ] Marauder v2/v3 integration

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
```
