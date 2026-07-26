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

// #if defined(ARDUINO_USB_CDC_ON_BOOT) && ARDUINO_USB_CDC_ON_BOOT
//   #define SNIFFER_SERIAL USBSerial
// #else
  #define SNIFFER_SERIAL Serial
// #endif

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

// -- Static members ------------------------------------------------------------
QueueHandle_t IEEE802154Sniffer::_rxQueue = nullptr;

static const uint8_t HOP_CHANNELS[] = {11,15,20,25,26,12,16,21};
static const uint8_t HOP_COUNT = sizeof(HOP_CHANNELS);

static const bool no_bcast = true;
static const bool no_duplicates = true;

// -- ISR callback --------------------------------------------------------------
void IEEE802154Sniffer::rxCallback(uint8_t *frame,
                                    esp_ieee802154_frame_info_t *fi) {
    if (!_rxQueue || !frame) return;
    uint8_t len = frame[0];
    if (len < 3 || len > SNIFFER_MAX_FRAME_LEN) return;

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
IEEE802154Sniffer::IEEE802154Sniffer()
    : _channel(SNIFFER_DEFAULT_CHANNEL), _running(false)
    , _hopping(false), _hopInterval(500), _lastHop(0), _hopIdx(0)
    , _frameCount(0), _zbCount(0), _threadCount(0), _dropped(0)
    , _pcapOut(nullptr), onFrame(nullptr)
{}

// -- begin() ------------------------------------------------------------------
bool IEEE802154Sniffer::begin(uint8_t channel) {
    _channel = constrain(channel, SNIFFER_MIN_CHANNEL, SNIFFER_MAX_CHANNEL);

    _rxQueue = xQueueCreate(SNIFFER_QUEUE_DEPTH, sizeof(SnifferFrame));
    if (!_rxQueue) return false;

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
    if (esp_ieee802154_receive() != ESP_OK) return false;

    _running = true;
    SNIFFER_SERIAL.printf("[Sniffer] Started ch %u\n", _channel);
    return true;
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
    SNIFFER_SERIAL.printf("\r[Hop] CH:%02u  frames:%lu  ", _channel, _frameCount);
}

// -- PCap ----------------------------------------------------------------------
void IEEE802154Sniffer::startPcap(Stream *out) {
    _pcapOut = out;
    PcapGlobalHeader gh = {
        PCAP_MAGIC, PCAP_VERSION_MAJOR, PCAP_VERSION_MINOR,
        0, 0, SNIFFER_MAX_FRAME_LEN, PCAP_LINKTYPE_802154
    };
    _pcapOut->write((uint8_t*)&gh, sizeof(gh));
    SNIFFER_SERIAL.println("[Sniffer] PCap started");
}

void IEEE802154Sniffer::stopPcap() {
    _pcapOut = nullptr;
    SNIFFER_SERIAL.println("[Sniffer] PCap stopped");
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

            // _updateHost(info);
            if (no_duplicates && _updateHost(info)) {
              _printFrame(info);
            }
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

    uint16_t fc      = (uint16_t)p[0] | ((uint16_t)p[1] << 8);
    info.frameType   = fc & FC_FRAME_TYPE_MASK;
    info.srcAddrMode = (fc >> 14) & 0x03;
    info.dstAddrMode = (fc >> 10) & 0x03;
    bool panComp     = (fc >> 6) & 0x01;
    info.seqNum      = p[2];
    info.panId       = 0xFFFF;
    info.macSrc      = 0xFFFF;
    info.macDst      = 0xFFFF;

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
    } else if (info.frameType == FC_FRAME_TYPE_BEACON) {
        info.protocolName = "Beacon";
        info.functionName = "";
    } else if (info.frameType == FC_FRAME_TYPE_ACK) {
        info.protocolName = "ACK";
        info.functionName = "";
    } else if (info.frameType == FC_FRAME_TYPE_MAC_CMD) {
        info.protocolName = "MAC Cmd";
        info.functionName = "";
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

    uint16_t nwkFc   = (uint16_t)p[0] | ((uint16_t)p[1] << 8);
    info.zbNwkType   = nwkFc & 0x03;
    info.route.nwkDst = (uint16_t)p[2] | ((uint16_t)p[3] << 8);
    info.route.nwkSrc = (uint16_t)p[4] | ((uint16_t)p[5] << 8);
    info.route.radius = p[6];
    // p[7] = NWK seq num

    uint8_t off = 8;

    // Optional extended destination address
    if ((nwkFc & ZB_NWK_FC_EXT_DST) && off + 8 <= len) off += 8;

    // Optional extended source address
    if ((nwkFc & ZB_NWK_FC_EXT_SRC) && off + 8 <= len) {
        // Could capture NWK extended src here
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

// return true if new host.
bool IEEE802154Sniffer::_updateHost(const FrameInfo &info) {
    uint32_t now = millis();

    bool ret = false;

    // Update or create record for MAC src
    auto updateRecord = [&](uint16_t addr, bool isSrc) {
        if (addr == 0xFFFF || addr == 0xFFFE || addr == 0x0000) {
            if (addr != 0x0000) return;  // keep coordinator
        }
        HostRecord *h = findHost(addr);
        if (!h) {
            ret = true;
            h = new HostRecord();
            h->shortAddr   = addr;
            h->extAddr     = 0;
            h->panId       = info.panId;
            h->rssiMin     = info.rssi;
            h->rssiMax     = info.rssi;
            h->firstSeen_ms = now;
            h->txCount     = 0;
            h->rxCount     = 0;
            h->frameCount  = 0;
            h->deviceType  = (addr == 0x0000) ? DeviceType::COORDINATOR : DeviceType::UNKNOWN;
            h->protocol    = info.protocol;
            hosts.add(h);
        }
        h->rssiLast    = info.rssi;
        h->lqiLast     = info.lqi;
        h->channel     = info.channel;
        h->lastSeen_ms = now;
        h->frameCount++;
        if (info.rssi < h->rssiMin) h->rssiMin = info.rssi;
        if (info.rssi > h->rssiMax) h->rssiMax = info.rssi;
        if (isSrc) h->txCount++;
        else       h->rxCount++;

        // Infer router if it appears in relay list
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

    return ret;
}

void IEEE802154Sniffer::printHosts() {
    SNIFFER_SERIAL.println("\n-- Host List ------------------------------------------------");
    SNIFFER_SERIAL.println("  Addr   Type        Proto   Frames  TX    RX    RSSI(last/min/max) LQI");
    SNIFFER_SERIAL.println("  -----------------------------------------------------------------");
    for (int i = 0; i < hosts.size(); i++) {
        HostRecord *h = hosts.get(i);
        const char *dtype = "Unknown";
        if (h->deviceType == DeviceType::COORDINATOR) dtype = "Coordinator";
        else if (h->deviceType == DeviceType::ROUTER)  dtype = "Router";
        else if (h->deviceType == DeviceType::END_DEVICE) dtype = "End Device";
        const char *proto = "802.15.4";
        if (h->protocol == FrameProtocol::ZIGBEE) proto = "Zigbee";
        else if (h->protocol == FrameProtocol::THREAD) proto = "Thread";
        SNIFFER_SERIAL.printf("  0x%04X %-12s %-8s %6lu %5lu %5lu  %4d/%4d/%4d  %3u\n",
            h->shortAddr, dtype, proto,
            h->frameCount, h->txCount, h->rxCount,
            h->rssiLast, h->rssiMin, h->rssiMax, h->lqiLast);
    }
    SNIFFER_SERIAL.println("--------------------------------------------------------------\n");
}

// -- Serial output -------------------------------------------------------------
void IEEE802154Sniffer::_printFrame(const FrameInfo &info) {
    // MAC hop
    char macSrc[10], macDst[10];

    // if (no_bcast && info.macSrc == 0xFFFF && info.macDst == 0xFFFF)
    //    return;

    snprintf(macSrc, sizeof(macSrc),
             info.macSrc == 0xFFFF ? "BCAST" : "0x%04X", info.macSrc);
    snprintf(macDst, sizeof(macDst),
             info.macDst == 0xFFFF ? "BCAST" : "0x%04X", info.macDst);

    if (!info.hasRoute || (info.route.nwkSrc == info.macSrc &&
                            info.route.nwkDst == info.macDst &&
                            info.route.hopCount == 0)) {

        // Direct / no route info - single line
        SNIFFER_SERIAL.printf("[%02u] %-8s  %s→%s  PAN:%04X  %-16s  RSSI:%4d LQI:%3u  %3uB\n",
            info.channel, info.protocolName,
            macSrc, macDst, info.panId,
            info.functionName ? info.functionName : "",
            info.rssi, info.lqi, info.len);
    } else {

        // Has route - print full path
        SNIFFER_SERIAL.printf("[%02u] %-8s  MAC:%s→%-6s  NWK:0x%04X→0x%04X",
            info.channel, info.protocolName,
            macSrc, macDst,
            info.route.nwkSrc, info.route.nwkDst);

        if (info.route.hopCount > 0) {
            SNIFFER_SERIAL.print("  Route:[");
            SNIFFER_SERIAL.printf("0x%04X", info.route.nwkSrc);
            for (uint8_t i = 0; i < info.route.hopCount; i++)
                SNIFFER_SERIAL.printf("→0x%04X", info.route.relays[i]);
            SNIFFER_SERIAL.printf("→0x%04X]", info.route.nwkDst);
        }

        SNIFFER_SERIAL.printf("  %-16s  RSSI:%3d LQI:%3u  %3uB\n",
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
