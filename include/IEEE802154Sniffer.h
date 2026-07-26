/*
 * IEEE802154_Sniffer - 802.15.4 promiscuous sniffer for ESP32-C6
 *
 * Features:
 *   - Promiscuous capture of all 802.15.4 frames
 *   - Zigbee NWK decode: full route (MAC hop + NWK src/dst + relay list)
 *   - Thread/Matter 6LoWPAN detection with mesh header route decode
 *   - Host tracking via LinkedList (first seen, last seen, RSSI, LQI, frame count)
 *   - PCap recording to SD card (LINKTYPE_IEEE802_15_4 = 195)
 *   - Channel hop scan mode
 *   - WS2812B LED status via callback
 *   - TFT display hook for future integration
 */

#pragma once

#include "esp_ieee802154_types.h"
#include <Arduino.h>
#include <LinkedList.h>
#include <stdint.h>

// -- Channel config ------------------------------------------------------------
#define SNIFFER_DEFAULT_CHANNEL     26
#define SNIFFER_MIN_CHANNEL         11
#define SNIFFER_MAX_CHANNEL         26

// -- Limits --------------------------------------------------------------------
#define SNIFFER_MAX_FRAME_LEN       128
#define SNIFFER_QUEUE_DEPTH         16
#define SNIFFER_MAX_ROUTE_HOPS      8    // max relay hops in source route

// -- 802.15.4 frame types ------------------------------------------------------
#define FC_FRAME_TYPE_MASK          0x07
#define FC_FRAME_TYPE_BEACON        0x00
#define FC_FRAME_TYPE_DATA          0x01
#define FC_FRAME_TYPE_ACK           0x02
#define FC_FRAME_TYPE_MAC_CMD       0x03

// -- Address modes -------------------------------------------------------------
#define ADDR_MODE_NONE              0x00
#define ADDR_MODE_SHORT             0x02
#define ADDR_MODE_EXTENDED          0x03

// -- Zigbee NWK frame control bits --------------------------------------------
#define ZB_NWK_TYPE_DATA            0x00
#define ZB_NWK_TYPE_CMD             0x01
#define ZB_NWK_FC_SOURCE_ROUTE      (1 << 10)  // bit10 = source route subframe present
#define ZB_NWK_FC_EXT_SRC          (1 << 11)  // bit11 = extended src addr present
#define ZB_NWK_FC_EXT_DST          (1 << 12)  // bit12 = extended dst addr present

// -- Device type ---------------------------------------------------------------
enum class DeviceType : uint8_t {
    UNKNOWN     = 0,
    COORDINATOR = 1,   // short addr 0x0000
    ROUTER      = 2,   // appears in relay lists / forwards traffic
    END_DEVICE  = 3,   // only communicates with parent
};

// -- Protocol -----------------------------------------------------------------
enum class FrameProtocol : uint8_t {
    UNKNOWN,
    ZIGBEE,
    THREAD,
    MATTER,
    RAW_802154,
};

// -- Route: full path from NWK src -> dst via relay hops -----------------------
struct RouteInfo {
    uint16_t nwkSrc;                           // NWK originator
    uint16_t nwkDst;                           // NWK final destination
    uint16_t macSrc;                           // MAC immediate sender (current hop)
    uint16_t macDst;                           // MAC immediate receiver (next hop)
    uint8_t  hopCount;                         // relay hops (0 = direct)
    uint16_t relays[SNIFFER_MAX_ROUTE_HOPS];   // intermediate routers in order
    uint8_t  radius;                           // remaining hop count limit
    bool     hasSourceRoute;                   // source route subframe present
};

// -- Raw frame (ISR -> queue) ---------------------------------------------------
struct SnifferFrame {
    uint8_t  data[SNIFFER_MAX_FRAME_LEN];
    uint8_t  len;
    int8_t   rssi;
    uint8_t  lqi;
    uint8_t  channel;
    uint32_t timestamp_us;   // microseconds from esp_timer_get_time()
};

// -- Decoded frame -------------------------------------------------------------
struct FrameInfo {
    // MAC layer
    uint8_t       frameType;
    uint16_t      panId;
    uint16_t      macSrc;
    uint16_t      macDst;
    uint64_t      srcExtended;
    uint64_t      dstExtended;
    uint8_t       srcAddrMode;
    uint8_t       dstAddrMode;
    uint8_t       seqNum;
    int8_t        rssi;
    uint8_t       lqi;
    uint8_t       channel;
    uint32_t      timestamp_us;
    uint8_t       len;

    // Protocol
    FrameProtocol protocol;
    const char   *protocolName;
    const char   *functionName;   // NWK cmd name / "Data" / "Beacon" etc

    // Route (populated for Zigbee data/cmd and Thread mesh frames)
    RouteInfo     route;
    bool          hasRoute;

    // Zigbee NWK extras
    uint8_t       zbNwkType;
    uint8_t       zbNwkCmd;
};

// -- Host record (stored in LinkedList) ---------------------------------------
struct HostRecord {
    uint16_t   shortAddr;
    uint64_t   extAddr;        // 0 if not yet seen
    uint16_t   panId;
    int8_t     rssiMin;
    int8_t     rssiMax;
    int8_t     rssiLast;
    uint8_t    lqiLast;
    uint8_t    channel;
    uint32_t   firstSeen_ms;
    uint32_t   lastSeen_ms;
    uint32_t   frameCount;
    uint32_t   txCount;        // frames where this host was NWK source
    uint32_t   rxCount;        // frames where this host was NWK dest
    DeviceType deviceType;
    FrameProtocol protocol;
};

// -- PCap ---------------------------------------------------------------------
#define PCAP_MAGIC          0xA1B2C3D4
#define PCAP_VERSION_MAJOR  2
#define PCAP_VERSION_MINOR  4
#define PCAP_LINKTYPE_802154 195   // LINKTYPE_IEEE802_15_4

struct PcapGlobalHeader {
    uint32_t magic;
    uint16_t versionMajor;
    uint16_t versionMinor;
    int32_t  thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;
} __attribute__((packed));

struct PcapPacketHeader {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
} __attribute__((packed));

// -- Sniffer class -------------------------------------------------------------
class IEEE802154Sniffer {
public:
    IEEE802154Sniffer();

    bool    begin(uint8_t channel = SNIFFER_DEFAULT_CHANNEL);
    uint8_t update();

    // Channel control
    void    setChannel(uint8_t channel);
    uint8_t getChannel() const { return _channel; }

    void startChannelHop(uint16_t interval_ms = 500);
    void stopChannelHop();

    // PCap recording - pass an open File or Stream (SD file)
    // Call startPcap() once after opening the file
    void startPcap(Stream *out);
    void stopPcap();
    bool isPcapActive() const { return _pcapOut != nullptr; }

    // Host list - caller may iterate directly
    LinkedList<HostRecord*> hosts;
    HostRecord *findHost(uint16_t shortAddr);
    void        printHosts();

    // Stats
    uint32_t getFrameCount()   const { return _frameCount; }
    uint32_t getZigbeeCount()  const { return _zbCount; }
    uint32_t getThreadCount()  const { return _threadCount; }
    uint32_t getDroppedCount() const { return _dropped; }

    // Callbacks
    void (*onFrame)(const FrameInfo &info) = nullptr;

    // ISR entry point - public for C weak symbol access
    static void rxCallback(uint8_t *frame, esp_ieee802154_frame_info_t *fi);

private:
    uint8_t  _channel;
    bool     _running;
    bool     _hopping;
    uint16_t _hopInterval;
    uint32_t _lastHop;
    uint8_t  _hopIdx;

    uint32_t _frameCount;
    uint32_t _zbCount;
    uint32_t _threadCount;
    uint32_t _dropped;

    Stream  *_pcapOut;

    static QueueHandle_t _rxQueue;

    // Decoders
    bool  _decodeMac(const SnifferFrame &raw, FrameInfo &info);
    bool  _decodeZigbeeNwk(const uint8_t *p, uint8_t len, FrameInfo &info);
    bool  _decodeThreadMesh(const uint8_t *p, uint8_t len, FrameInfo &info);
    bool  _isThread(const uint8_t *payload, uint8_t len);

    // Host tracking
    bool  _updateHost(const FrameInfo &info);

    // Output
    void  _printFrame(const FrameInfo &info);
    void  _writePcap(const SnifferFrame &raw);

    void  updateChannelHop();

    static const char *_frameTypeName(uint8_t type);
    static const char *_zbNwkCmdName(uint8_t cmd);
};
