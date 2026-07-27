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
// #include <Adafruit_NeoPixel.h>
#include "ledQ.h"
#include "IEEE802154Sniffer.h"
#include "SnifferSD.h"
#include "ZbKeyCapture.h"

/*
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
    led.setBrightness(LED_BRIGHT * 3);
    led.setPixelColor(0, color);
    led.show();
}

void ledUpdate() {
    uint32_t now = millis();
    if (_flashUntil > 0) {
        if (now >= _flashUntil) {
            _flashUntil = 0;
            led.setBrightness(LED_BRIGHT);
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
        led.setBrightness(LED_BRIGHT);
        led.setPixelColor(0, led.Color(0, 0, _pulseBright));
        led.show();
    }
}
*/

// -- Known device labels -------------------------------------------------------
// Format: "addr,type,label\n"  type: C=coordinator R=router E=end device
static const char DEVICE_LABELS[] =
    "0000,C,Hub\n"
    "0106,E,Soil_Monitor_2\n"
    "04A7,R,Repeater 1\n"
    "13AA,E,Weather B\n"
    "16CC,E,On-Off W Button\n"
    "1A2E,R,Color Bulb 1\n"
    "1F28,R,Repeater 3\n"
    "21CD,E,Furnace Water Sensor\n"
    "35EA,R,Sonoff Repeater\n"
    "3A7B,E,Soil_Monitor_5\n"
    "40B3,E,Weather G\n"
    "4298,E,On-Off 2\n"
    "450F,R,Color Bulb 2\n"
    "46C5,E,BT Water Sensor\n"
    "5A4A,E,Motion Std CIE\n"
    "5D3A,E,Soil_Monitor_3\n"
    "6299,E,On-Off 1\n"
    "71D9,E,Weather R\n"
    "73AD,E,Blue On-Off Button\n"
    "8880,E,Soil_Monitor_4\n"
    "966A,E,Round Blue Button\n"
    "9C26,E,K Water Sensor\n"
    "B83A,E,Soil_Moisture\n"
    "BBC9,E,Soil_Monitor_1\n"
    "CA77,E,Main\n"
    "D76B,E,Soil_Monitor_6\n"
    "DD7A,E,Weather Disp\n"
    "E234,E,Weather RD\n";

// -- Sniffer -------------------------------------------------------------------
IEEE802154Sniffer sniffer;
SnifferSD         sd;
ZbKeyCapture      keyCapture(sniffer);
static bool hopping = false;


void show_header() {
    Serial.println();
    Serial.println("[CH] Protocol     Src          -> Dst         PAN     Function          RSSI    Len");
    Serial.println("-------------------------------------------------------------------------------------");
}

// -- Frame callback - fires per decoded frame -----------------------------------
void onSnifferFrame(const FrameInfo &info) {
    switch (info.protocol) {
        case FrameProtocol::ZIGBEE:  ledFlash(COL_GREEN,  60); break;
        case FrameProtocol::THREAD:
        case FrameProtocol::MATTER:  ledFlash(COL_PURPLE, 61); break;
        default:                     ledFlash(COL_YELLOW, 40); break;
    }
    // TFT display hook goes here in a future version
}

// -- Serial command handler ----------------------------------------------------
void handleSerial() {
    if (!Serial.available()) return;
    String cmd = Serial.readStringUntil('\n');
    cmd.trim();
    if (cmd.length() == 0) return;

    if (cmd[0] == 'c' && cmd.length() > 1) {
        uint8_t ch = (uint8_t)cmd.substring(1).toInt();
        if (ch >= SNIFFER_MIN_CHANNEL && ch <= SNIFFER_MAX_CHANNEL) {
            sniffer.stopChannelHop();
            hopping = false;
            sniffer.setChannel(ch);
            ledFlash(COL_WHITE, 100);
        } else {
            Serial.printf("Channel must be %u-%u\n",
                          SNIFFER_MIN_CHANNEL, SNIFFER_MAX_CHANNEL);
        }
    } else if (cmd == "H") {
      show_header();

    } else if (cmd == "B") {
      if (sniffer.no_bcast) 
        sniffer.no_bcast = false;
      else
        sniffer.no_bcast = true;
      Serial.printf("Show %s bcast\n", sniffer.no_bcast ? "No" : "" );

    } else if (cmd == "U") {
      if (sniffer.no_duplicates) 
        sniffer.no_duplicates = false;
      else
        sniffer.no_duplicates = true;
      Serial.printf("Show %s duplicates\n", sniffer.no_duplicates ? "No" : "" );

    } else if (cmd == "h") {
        hopping = !hopping;
        if (hopping) { sniffer.startChannelHop(500); ledFlash(COL_WHITE, 200); }
        else         { sniffer.stopChannelHop();      ledFlash(COL_WHITE, 100); }
    } else if (cmd == "s") {
        Serial.println("-- Sniffer Stats ------------------");
        Serial.printf("  Channel  : %u\n",  sniffer.getChannel());
        Serial.printf("  Total    : %lu\n", sniffer.getFrameCount());
        Serial.printf("  Zigbee   : %lu\n", sniffer.getZigbeeCount());
        Serial.printf("  Thread   : %lu\n", sniffer.getThreadCount());
        Serial.printf("  Dropped  : %lu\n", sniffer.getDroppedCount());
        Serial.println("-----------------------------------");
    } else if (cmd == "r") {
        Serial.println("Stats reset");
    } else if (cmd == "l") {
        sniffer.printHosts();
    } else if (cmd == "p") {
        if (sniffer.isPcapActive()) {
            sniffer.stopPcap();
        } else {
            // For now write to Serial - replace with SD File in future
            sniffer.startPcap(&Serial);
        }
    } else if (cmd == "p") {
        if (sd.isPcapOpen()) sd.stopPcap(sniffer);
        else if (sd.isMounted()) sd.startPcap(sniffer);
        else {
            if (sniffer.isPcapActive()) sniffer.stopPcap();
            else sniffer.startPcap(&Serial);
        }
    } else if (cmd == "W") {
        if (sd.isMounted()) sd.saveHosts(sniffer);
        else Serial.println("SD not mounted");
    } else if (cmd == "K") {
        if (sd.isMounted()) sd.saveKeys(sniffer);
        else Serial.println("SD not mounted");
    } else if (cmd == "F") {
        if (sd.isMounted()) sd.listFiles();
        else Serial.println("SD not mounted");
    } else if (cmd[0] == 't' && cmd.length() > 5) {
        // t<addr>,<type>,<label>  e.g. t04A7,R,Ikea Repeater
        String rest = cmd.substring(1);
        int c1 = rest.indexOf(',');
        int c2 = rest.indexOf(',', c1 + 1);
        if (c1 > 0 && c2 > c1) {
            uint16_t addr = (uint16_t)strtol(rest.substring(0, c1).c_str(), nullptr, 16);
            char type = rest.charAt(c1 + 1);
            String label = rest.substring(c2 + 1);
            if (sniffer.labelHost(addr, type, label.c_str()))
                Serial.printf("Labelled 0x%04X (%c) as '%s'\n", addr, type, label.c_str());
        } else {
            Serial.println("Usage: t<addr>,<type>,<label>  type: C R E");
        }
    } else if (cmd == "k") {
        sniffer.printKeys();
    } else {
        Serial.println("Commands: c<ch>  h(op)  k(eys)  l(ist)  p(cap)  s(tats) H(eader) d(U)ps t<addr>,<type>,<label>  r(eset)");
    }
}

// -- setup() ------------------------------------------------------------------
void setup() {
    Serial.begin(115200);
    delay(1000);

    led_off();

    pinMode(14, OUTPUT);  // disable LCD
    digitalWrite(14, HIGH);


    // led.begin();
    // led.setBrightness(LED_BRIGHT);
    // led.setPixelColor(0, COL_RED);
    // led.show();

    Serial.println("\n╔══════════════════════════════════╗");
    Serial.println(  "║  IEEE 802.15.4 Sniffer v0.1      ║");
    Serial.println(  "║  ESP32-C6  Zigbee + Thread/Matter ║");
    Serial.println(  "╚══════════════════════════════════╝");

    sniffer.onFrame = onSnifferFrame;

    // Wire key capture — fires on every frame, ZbKeyCapture decides what's relevant
    sniffer.onKeyCapture = [](const FrameInfo &info,
                               const uint8_t *payload, uint8_t len) {
        if (keyCapture.processFrame(info, payload, len)) {
            // New network key captured — flash white
            ledFlash(COL_WHITE, 500);
            Serial.println("[!] New network key captured — type 'k' to view");
        }
    };
    Serial.printf("Show %s bcast\n", sniffer.no_bcast ? "No" : "" );
    Serial.printf("Show %s duplicates\n", sniffer.no_duplicates ? "No" : "" );

    if (!sniffer.begin(SNIFFER_DEFAULT_CHANNEL)) {
        Serial.println("ERROR: Failed to start 802.15.4 radio");
        log_e("ERROR: Failed to start 802.15.4 radio");
        // Stay red on error
        while (true) {
            ledFlash(COL_RED, 500);
            // led.setPixelColor(0, COL_RED);
            // led.show();
            // delay(500);
            ledFlash(COL_OFF, 500);
            // led.setPixelColor(0, COL_OFF);
            // led.show();
            delay(1000);
        }
    }

    // Radio up - start blue pulse
    // led.setPixelColor(0, COL_OFF);
    // led.show();

    // Load known device labels
    sniffer.loadLabels(DEVICE_LABELS);

    // SD card
    if (sd.begin()) {
        sd.loadLabels(sniffer);
        sd.listFiles();
    }

    Serial.println("Ready. Commands: c<ch>  h(op)  k(eys)  K(→SD)  l(ist)  p(cap)  W(rite)  F(iles)  s(tats)");
    show_header();
}


// -- loop() -------------------------------------------------------------------
void loop() {
    sniffer.update();
    handleSerial();
    keyCapture.expireJoins();
    // ledUpdate();
}
