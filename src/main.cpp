/*
 * IEEE802154 Sniffer - ESP32-C6
 * Promiscuous 802.15.4 sniffer for Zigbee and Thread/Matter traffic.
 *
 * WS2812B LED on GPIO8:
 *   Blue pulsing  - scanning, no packets
 *   Green flash   - Zigbee packet
 *   Purple flash  - Thread / Matter packet
 *   Yellow flash  - unknown 802.15.4
 *   Red solid     - radio error
 *
 * Serial commands:
 *   c<nn>   Set channel (e.g. c15, c20, c26)
 *   h       Toggle channel hop mode
 *   s       Print stats
 *   r       Reset stats
 */

#include "USB.h"
#include <Arduino.h>
#include <Adafruit_NeoPixel.h>
#include "IEEE802154Sniffer.h"

// On ESP32-C6 with USB CDC, Arduino.h maps Serial → USBSerial
// #if defined(ARDUINO_USB_CDC_ON_BOOT) && ARDUINO_USB_CDC_ON_BOOT
//   #define SNIFFER_SERIAL USBSerial
// #else
  #define SNIFFER_SERIAL Serial
// #endif

#ifdef CONFIG_IDF_TARGET_ESP32C6
// -- WS2812B ------------------------------------------------------------------
#define LED_PIN     8
#define LED_COUNT   1
#define LED_BRIGHT  40   // 0-255, keep low for power/heat

Adafruit_NeoPixel led(LED_COUNT, LED_PIN, NEO_GRB + NEO_KHZ800);

// Colours
#define COL_OFF     led.Color(0,   0,   0)
#define COL_BLUE    led.Color(0,   0,   80)
#define COL_GREEN   led.Color(0,   80,  0)
#define COL_PURPLE  led.Color(60,  0,   80)
#define COL_YELLOW  led.Color(80,  60,  0)
#define COL_RED     led.Color(80,  0,   0)
#define COL_WHITE   led.Color(40,  40,  40)


static uint32_t _flashColor    = 0;
static uint32_t _flashUntil    = 0;
static uint32_t _pulseLastMs   = 0;
static uint8_t  _pulseBright   = 0;
static int8_t   _pulseDir      = 1;

void ledFlash(uint32_t color, uint16_t duration_ms = 80) {
    _flashColor = color;
    _flashUntil = millis() + duration_ms;
    led.setPixelColor(0, color);
    led.show();
}

void ledUpdate() {
    uint32_t now = millis();
    if (_flashUntil > 0) {
        if (now >= _flashUntil) {
            _flashUntil = 0;
            led.setPixelColor(0, COL_OFF);
            led.show();
        }
        return;
    }
    // Blue pulse when idle (no flash pending)
    if (now - _pulseLastMs > 20) {
        _pulseLastMs = now;
        _pulseBright += _pulseDir * 3;
        if (_pulseBright >= 60)  { _pulseBright = 60;  _pulseDir = -1; }
        if (_pulseBright == 0)   { _pulseBright = 0;   _pulseDir =  1; }
        led.setPixelColor(0, led.Color(0, 0, _pulseBright));
        led.show();
    }
}
#else
void ledFlash(uint32_t color, uint16_t duration_ms = 80) { }

void ledUpdate() {}

// Colours
#define COL_OFF     0
#define COL_BLUE    0
#define COL_GREEN   0
#define COL_PURPLE  0
#define COL_YELLOW  0
#define COL_RED     0
#define COL_WHITE   0
#endif

// -- Sniffer -------------------------------------------------------------------
IEEE802154Sniffer sniffer;
static bool hopping = false;

// -- Frame callback - fires per decoded frame -----------------------------------
void onSnifferFrame(const FrameInfo &info) {
    switch (info.protocol) {
        case FrameProtocol::ZIGBEE:  ledFlash(COL_GREEN,  60); break;
        case FrameProtocol::THREAD:
        case FrameProtocol::MATTER:  ledFlash(COL_PURPLE, 60); break;
        default:                     ledFlash(COL_YELLOW, 40); break;
    }
    // TFT display hook goes here in a future version
}

void printheader() {
    SNIFFER_SERIAL.println();
    SNIFFER_SERIAL.println("[CH] Protocol     Src          -> Dst         PAN     Function          RSSI    Len");
    SNIFFER_SERIAL.println("-------------------------------------------------------------------------------------");
}
// -- Serial command handler ----------------------------------------------------
void handleSerial() {
    if (!SNIFFER_SERIAL.available()) return;
    String cmd = SNIFFER_SERIAL.readStringUntil('\n');
    cmd.trim();
    if (cmd.length() == 0) return;

    if (cmd[0] == 'c' && cmd.length() > 1) {
        uint8_t ch = (uint8_t)cmd.substring(1).toInt();
        if (ch >= SNIFFER_MIN_CHANNEL && ch <= SNIFFER_MAX_CHANNEL) {
            sniffer.stopChannelHop();
            hopping = false;
            sniffer.setChannel(ch);
            #ifdef CONFIG_IDF_TARGET_ESP32C6
              ledFlash(COL_WHITE, 100);
            #endif
        } else {
            SNIFFER_SERIAL.printf("Channel must be %u-%u\n",
                          SNIFFER_MIN_CHANNEL, SNIFFER_MAX_CHANNEL);
        }
    } else if (cmd == "H") {
      printheader();
    } else if (cmd == "h") {
        hopping = !hopping;
        if (hopping) { sniffer.startChannelHop(500); ledFlash(COL_WHITE, 200); }
        else         { sniffer.stopChannelHop();      ledFlash(COL_WHITE, 100); }
    } else if (cmd == "s") {
        SNIFFER_SERIAL.println("-- Sniffer Stats ------------------");
        SNIFFER_SERIAL.printf("  Channel  : %u\n",  sniffer.getChannel());
        SNIFFER_SERIAL.printf("  Total    : %lu\n", sniffer.getFrameCount());
        SNIFFER_SERIAL.printf("  Zigbee   : %lu\n", sniffer.getZigbeeCount());
        SNIFFER_SERIAL.printf("  Thread   : %lu\n", sniffer.getThreadCount());
        SNIFFER_SERIAL.printf("  Dropped  : %lu\n", sniffer.getDroppedCount());
        SNIFFER_SERIAL.println("-----------------------------------");
    } else if (cmd == "r") {
        SNIFFER_SERIAL.println("Stats reset");
    } else if (cmd == "l") {
        sniffer.printHosts();
    } else if (cmd == "p") {
        if (sniffer.isPcapActive()) {
            sniffer.stopPcap();
        } else {
            // For now write to Serial - replace with SD File in future
            sniffer.startPcap(&SNIFFER_SERIAL);
        }
    } else {
        SNIFFER_SERIAL.println("Commands: c<ch>  h(op)  l(ist hosts)  p(cap)  s(tats)  r(eset)");
    }
}

// -- setup() ------------------------------------------------------------------
void setup() {
    SNIFFER_SERIAL.begin(115200);
    delay(1000);

    // LED init
    #ifdef CONFIG_IDF_TARGET_ESP32C6
      led.begin();
      led.setBrightness(LED_BRIGHT);
      led.setPixelColor(0, COL_RED);
      led.show();
    #endif

    SNIFFER_SERIAL.println("\n╔══════════════════════════════════╗");
    SNIFFER_SERIAL.println(  "║  IEEE 802.15.4 Sniffer v0.1      ║");
    SNIFFER_SERIAL.println(  "║  ESP32-C6  Zigbee + Thread/Matter ║");
    SNIFFER_SERIAL.println(  "╚══════════════════════════════════╝");

    sniffer.onFrame = onSnifferFrame;

    if (!sniffer.begin(SNIFFER_DEFAULT_CHANNEL)) {
        SNIFFER_SERIAL.println("ERROR: Failed to start 802.15.4 radio");
        // Stay red on error
        while (true) {
            #ifdef CONFIG_IDF_TARGET_ESP32C6
              led.setPixelColor(0, COL_RED);
              led.show();
              delay(500);
              led.setPixelColor(0, COL_OFF);
              led.show();
            #endif
            delay(500);
        }
    }

    #ifdef CONFIG_IDF_TARGET_ESP32C6
      // Radio up - start blue pulse
      led.setPixelColor(0, COL_OFF);
      led.show();
    #endif

    SNIFFER_SERIAL.println("Ready. Commands: c<ch>  h(op)  l(ist)  p(cap)  s(tats)");
    printheader();
}


// -- loop() -------------------------------------------------------------------
void loop() {
    sniffer.update();
    handleSerial();
    #ifdef CONFIG_IDF_TARGET_ESP32C6
      ledUpdate();
    #endif
}
