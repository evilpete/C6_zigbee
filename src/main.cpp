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
 *   j       Print join status
 *   J[addr] Join network as a plain end device (auto-picks an open host if
 *           addr omitted, e.g. J04A7 to target a specific host)
 *   P<addr> Ping a host (ZDO Node Descriptor request) - requires a join and
 *           a captured network key. P alone sweeps every known host.
 *   L[addr] find_lock: probe a host (or L alone = sweep all) for the Door
 *           Lock cluster (0x0101). Requires a join + network key.
 *   M<addr> Spoof our EUI64 to that of a known host (M alone restores the
 *           real hardware MAC).
 *   R<addr> insecure_rejoin attack: impersonate a host and send an unsecured
 *           rejoin request to try to make the Trust Center re-transport the
 *           network key.  ** authorised testing of your own network only **
 *   A[addr] ack_attack: spoof MAC ACKs to a target to suppress/steal its
 *           traffic (A alone = stop / status).  ** authorised testing only **
 */

#include "USB.h"
#include <Arduino.h>
// #include <Adafruit_NeoPixel.h>
#include "ledQ.h"
#include "IEEE802154Sniffer.h"
#include "SnifferSD.h"
#include "ZbKeyCapture.h"
#include "ZbJoiner.h"
#include "ZbPing.h"
#include "ZbAttack.h"


// -- Known device labels -------------------------------------------------------
// Format: "addr,type,label\n"  type: C=coordinator R=router E=end device
static const char DEVICE_LABELS[] =
    "0000,C,Hub\n"
    "CA77,E,Main\n";


uint8_t Verbose = 0;

// -- Sniffer -------------------------------------------------------------------
IEEE802154Sniffer sniffer;
SnifferSD         sd;
ZbKeyCapture      keyCapture(sniffer);
ZbJoiner          joiner(sniffer);
ZbPing            zping(sniffer, joiner);
ZbAttack          zattack(sniffer);
static bool hopping = false;
static bool scanning = false;
static uint8_t scanChannel = 0;
static uint8_t scanSaveChannel = 0;
static uint32_t _channelScan = 0;
static uint32_t lastScan = 0;

void print_active_ch() {
  if (_channelScan)
    Serial.println("Channel Scan Still Active");
  Serial.print("Active Channels:");
  for (uint8_t i = SNIFFER_MIN_CHANNEL; i <= SNIFFER_MAX_CHANNEL; i++) {
    if (sniffer.active_channels[i - 10]) {
      Serial.print(" ");
      Serial.print(i);
    }
  }
  Serial.println();
}



// -- Active channel scan -------------------------------------------------------
// Sends a beacon request on each channel to solicit beacon responses
// Call from loop() or a timer
void startScanChannels() {
    Serial.println("[Scan] Starting active channel scan 11-26");
    scanning = true;
    scanSaveChannel = sniffer.getChannel();
    scanChannel = SNIFFER_MIN_CHANNEL;
    sniffer.setChannel(scanChannel);
    delay(10);
    // SEND Request beacons
    sniffer.sendBeaconRequest();
    lastScan = millis();
    Serial.printf("[Scan] CH:%02u  \n", SNIFFER_MIN_CHANNEL);  Serial.flush();
    sniffer.active_channels[0] = 1;
}


// the active_channels array contains a lost of channels we found traffic
void updateScan() {
    if (!scanning) return;
    // Serial.printf("millis() - lastScan\n", (millis() - lastScan));
    sniffer.sendBeaconRequest();             // request on current channel
    if (millis() - lastScan < 3000) return;  // dwell 3000 per channel
    lastScan = millis();
    if (scanChannel < SNIFFER_MAX_CHANNEL) {
        scanChannel++;
        sniffer.setChannel(scanChannel);
        delay(10);
        Serial.printf("[Scan] CH:%02u  \n", scanChannel);  Serial.flush();
        sniffer.sendBeaconRequest();             // request on current channel
    } else {
        scanning = false;
        
        // Restore Channel
        if (scanSaveChannel)
          sniffer.setChannel(scanSaveChannel);

        //  [[clang::suppress("type", "bounds")]];  [[clang::suppress]];
        for (int i = 0; i < sniffer.hosts.size(); i++) { 
          HostRecord *h = sniffer.hosts.get(i);
          if (h->channel) {
            sniffer.active_channels.at(h->channel -10)++;
            Serial.printf("GOT active_channels chan=%d  %d %d\n", h->channel, (h->channel -10), sniffer.active_channels.at(h->channel -10));  Serial.flush(); delay(10);
            }
        }
        Serial.println("active_channels Done\n");  Serial.flush();
        print_active_ch();
    }
}


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

    } else if (cmd == "V") {
      if (Verbose) 
        Verbose = 0;
      else
        Verbose = 1;
      Serial.printf("Verbose %s\n", Verbose ? "On" : "Off" );

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
        Serial.printf("  hopping  : %s\n", hopping ? "True" : "False");
        Serial.printf("  scanning : %s\n", scanning ? "True" : "False");
        Serial.println("-----------------------------------");
        if (sniffer.active_channels[0]) {
          print_active_ch();
        }
    } else if (cmd == "r") {
        Serial.println("Stats reset");
    } else if (cmd == "l") {
        sniffer.printHosts();

//   Duplicate
//    } else if (cmd == "p") {
//        if (sniffer.isPcapActive()) {
//            sniffer.stopPcap();
//        } else {
//            // For now write to Serial - replace with SD File in future
//            sniffer.startPcap(&Serial);
//        }

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
    } else if (cmd == "S") {
        startScanChannels();
    } else if (cmd == "j") {
        joiner.printStatus();
    } else if (cmd[0] == 'J') {
        // J          - auto-pick most recently seen host advertising association-permit
        // J<addr>    - join via a specific host (hex short addr, e.g. J04A7)
        HostRecord *parent = nullptr;
        if (cmd.length() > 1) {
            uint16_t addr = (uint16_t)strtol(cmd.substring(1).c_str(), nullptr, 16);
            parent = sniffer.findHost(addr);
            if (!parent)
                Serial.printf("[Join] Unknown host 0x%04X - use 'l' to list hosts\n", addr);
            else if (!parent->beaconSeen || !parent->associationPermit)
                Serial.printf("[Join] 0x%04X not confirmed open for joining - trying anyway\n", addr);
        } else {
            uint32_t newest = 0;
            for (int i = 0; i < sniffer.hosts.size(); i++) {
                HostRecord *h = sniffer.hosts.get(i);
                if (h->beaconSeen && h->associationPermit && h->lastSeen_ms >= newest) {
                    newest = h->lastSeen_ms;
                    parent = h;
                }
            }
            if (!parent)
                Serial.println("[Join] No host currently advertising association-permit");
        }
        if (parent) {
            Serial.printf("[Join] Attempting join via 0x%04X (PAN 0x%04X)\n",
                          parent->shortAddr, parent->panId);
            joiner.start(parent->shortAddr, parent->panId);
        }
    } else if (cmd[0] == 'P' && cmd.length() > 1) {
        // P<addr> - ping a specific host (hex short addr, e.g. P0106)
        uint16_t addr = (uint16_t)strtol(cmd.substring(1).c_str(), nullptr, 16);
        HostRecord *h = sniffer.findHost(addr);
        if (!h)
            Serial.printf("[Ping] Unknown host 0x%04X - use 'l' to list hosts\n", addr);
        else
            zping.ping(h->shortAddr, h->panId);
    } else if (cmd == "P") {
        // P (no addr) - sweep every known host
        if (!joiner.isAssociated()) {
            Serial.println("[Ping] Not associated - run 'J' to join the network first");
        } else if (!sniffer.findLatestNetworkKey()) {
            Serial.println("[Ping] No network key captured yet - can't encrypt ping");
        } else {
            int sent = 0;
            for (int i = 0; i < sniffer.hosts.size(); i++) {
                HostRecord *h = sniffer.hosts.get(i);
                if (h->shortAddr == 0xFFFE || h->shortAddr == 0xFFFF) continue;
                if (zping.ping(h->shortAddr, h->panId)) sent++;
            }
            Serial.printf("[Ping] Sweep sent to %d host(s)\n", sent);
        }
    } else if (cmd[0] == 'L' && cmd.length() > 1) {
        // L<addr> - find_lock on a specific host
        uint16_t addr = (uint16_t)strtol(cmd.substring(1).c_str(), nullptr, 16);
        HostRecord *h = sniffer.findHost(addr);
        if (!h)
            Serial.printf("[Lock] Unknown host 0x%04X - use 'l' to list hosts\n", addr);
        else
            zping.findLock(h->shortAddr, h->panId);
    } else if (cmd == "L") {
        // L (no addr) - sweep all known hosts for the Door Lock cluster
        zping.findLockSweepAll();
    } else if (cmd[0] == 'M' && cmd.length() > 1) {
        // M<addr> - spoof our EUI64 to that of a known host
        uint16_t addr = (uint16_t)strtol(cmd.substring(1).c_str(), nullptr, 16);
        HostRecord *h = sniffer.findHost(addr);
        if (!h)
            Serial.printf("[Spoof] Unknown host 0x%04X - use 'l' to list hosts\n", addr);
        else if (h->extAddr == 0)
            Serial.printf("[Spoof] No captured EUI64 for 0x%04X yet\n", addr);
        else
            sniffer.setOwnEUI64(h->extAddr);
    } else if (cmd == "M") {
        // M (no addr) - restore the real hardware MAC
        sniffer.restoreOwnEUI64();
    } else if (cmd[0] == 'R' && cmd.length() > 1) {
        // R<addr> - insecure_rejoin attack impersonating a known host
        uint16_t addr = (uint16_t)strtol(cmd.substring(1).c_str(), nullptr, 16);
        zattack.insecureRejoin(addr);
    } else if (cmd[0] == 'A' && cmd.length() > 1) {
        // A<addr> - start ack_attack against a host
        uint16_t addr = (uint16_t)strtol(cmd.substring(1).c_str(), nullptr, 16);
        zattack.ackAttack(addr);
    } else if (cmd == "A") {
        // A (no addr) - stop the ack_attack if running, else print status
        if (sniffer.isAckAttackActive()) zattack.stopAckAttack();
        else zattack.printAckAttackStatus();
    } else {
        Serial.println("Commands: c<ch>  h(op)  j/J[addr](oin)  k(eys)  l(ist)  p(cap)  P[addr](ing)  L[addr]ock  M[addr]spoof  R<addr>ejoin  A[addr]ck  s(tats) (S)can H(eader) d(U)ps t<a>,<ty>,<l>  r(eset)");
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

    Serial.println("\n+===================================+");
    Serial.printf(   "|  IEEE 802.15.4 Sniffer v%-4s      |\n", VERSION);
    Serial.println(  "|  ESP32-C6  Zigbee + Thread/Matter |");
    Serial.println(  "+===================================+");

    sniffer.onFrame = onSnifferFrame;

    // Wire key capture callback
    sniffer.onKeyCapture = [](const FrameInfo &info,
                               const uint8_t *rawFrame, uint8_t rawLen,
                               uint8_t macPayloadOffset) {
        if (keyCapture.processFrame(info, rawFrame, rawLen, macPayloadOffset)) {
            ledFlash(COL_WHITE, 500);
            Serial.println("[!] *** Network key captured! type \'k\' to view ***");
        }
        if (joiner.processFrame(info, rawFrame, rawLen, macPayloadOffset)) {
            ledFlash(COL_CYAN, 500);
        }
        if (zping.processFrame(info, rawFrame, rawLen, macPayloadOffset)) {
            ledFlash(COL_CYAN, 150);
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

    Serial.println("Ready. Commands: c<ch>  h(op)  j/J[addr](oin)  k(eys)  K(→SD)  l(ist)  p(cap)  P[addr](ing)  L[addr]ock  M[addr]spoof  R<addr>ejoin  A[addr]ck  W(rite)  F(iles)  s(tats)");
    show_header();
}


// -- loop() -------------------------------------------------------------------
void loop() {
    sniffer.update();
    handleSerial();
    keyCapture.expireJoins();
    joiner.update();
    zping.update();
    updateScan();
}
