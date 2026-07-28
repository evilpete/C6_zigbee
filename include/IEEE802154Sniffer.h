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

// -- Route: full path from NWK src → dst via relay hops -----------------------
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

// -- Raw frame (ISR → queue) ---------------------------------------------------
struct SnifferFrame {
    uint8_t  data[SNIFFER_MAX_FRAME_LEN];
    uint8_t  len;
    int8_t   rssi;
    uint8_t  lqi;
    uint8_t  channel;
    uint32_t timestamp_us;   // microseconds from esp_timer_get_time()
};

// -- Broadcast address types ---------------------------------------------------
// Zigbee uses specific broadcast addresses to target device subsets
enum class BcastType : uint8_t {
    NOT_BCAST   = 0,
    ALL         = 1,   // 0xFFFF - all devices
    ROUTERS     = 2,   // 0xFFFC - routers only
    LP_ROUTERS  = 3,   // 0xFFFB - low-power routers
    SLEEPY_ED   = 4,   // 0xFFFD - sleepy end devices
    RESERVED    = 5,
};

// -- Decoded frame -------------------------------------------------------------
struct FrameInfo {
    // -- MAC layer -------------------------------------------------------------
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

    // MAC frame control flags (from FC word)
    bool          macSecurityEnabled;   // frame is encrypted at MAC layer
    bool          macFramePending;      // coordinator has queued data for receiver
    bool          macAckRequest;        // sender wants an ACK
    bool          macIsRetry;           // this is a retransmission
    bool          macPanIdCompressed;   // src/dst share same PAN ID

    // -- Protocol --------------------------------------------------------------
    FrameProtocol protocol;
    const char   *protocolName;
    const char   *functionName;         // NWK cmd / "Data" / "Beacon" etc

    BcastType     bcastType;            // NOT_BCAST or specific broadcast type

    // -- Route -----------------------------------------------------------------
    RouteInfo     route;
    bool          hasRoute;

    // -- Zigbee NWK ------------------------------------------------------------
    uint8_t       zbNwkType;
    uint8_t       zbNwkCmd;
    uint8_t       zbNwkProtoVersion;    // 0x02 = Zigbee 2006+, 0x03 = Zigbee Pro
    bool          zbNwkSecurityEnabled; // NWK layer encryption (separate from MAC)
    bool          zbIsMulticast;        // NWK multicast frame
    uint16_t      zbMulticastGroup;     // multicast group address if isMulticast
    uint8_t       zbNwkRadius;          // hop count limit at time of capture

    // -- Beacon (frameType == FC_FRAME_TYPE_BEACON) ----------------------------
    bool          beaconAssocPermit;    // network is open to new device joins
    bool          beaconCoordinator;    // sender is PAN coordinator
    uint8_t       beaconStackProfile;   // 0x00=Zigbee, 0x01=Zigbee Pro, 0x02=Thread
    uint8_t       beaconProtocolVersion;
    bool          beaconRouterCapacity; // network can accept new routers
    bool          beaconEndDevCapacity; // network can accept new end devices

    // -- Thread/MLE extras -----------------------------------------------------
    uint16_t      threadRloc16;         // RLOC16 if visible (router+child topology)
    uint8_t       threadMleType;        // MLE message type if detectable
};

// -- Host record (stored in LinkedList) ---------------------------------------
#define SNIFFER_MAX_LABEL_LEN   24

struct HostRecord {
    uint16_t   shortAddr;
    uint16_t   nwkAddr;              // NWK address (may differ from MAC short addr)
    uint64_t   extAddr;              // 0 if not yet seen
    uint16_t   panId;
    char       label[SNIFFER_MAX_LABEL_LEN]; // user-assigned name, "" if none
    int8_t     rssiMin;
    int8_t     rssiMax;
    int8_t     rssiLast;
    uint8_t    lqiLast;
    uint8_t    channel;
    uint32_t   firstSeen_ms;
    uint32_t   lastSeen_ms;
    uint32_t   frameCount;
    uint32_t   txCount;
    uint32_t   rxCount;
    uint32_t   retryCount;
    uint32_t   secureCount;
    uint32_t   acksMissed;
    DeviceType deviceType;
    FrameProtocol protocol;

    uint8_t    nwkProtoVersion;
    bool       beaconSeen;
    bool       associationPermit;
    bool       routerCapacity;
    bool       endDevCapacity;

    uint8_t    lastMacSeq;
    uint8_t    lastNwkSeq;
    uint16_t   seqGaps;

    uint32_t   lastPollTime_ms;
    uint32_t   avgPollInterval_ms;
    LinkedList<uint16_t> connected_hosts;   // not a pointer

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

// -- Zigbee key types ----------------------------------------------------------
#define ZIGBEE_KEY_LEN  16

inline bool is_bcast(uint16_t addr) {
    return (addr == 0xFFFF || addr == 0xFFFE || addr == 0xFFFB ||
          addr == 0xFFFC || addr == 0xFFFD);
}

enum class ZbKeyType : uint8_t {
    TRUST_CENTER_LINK = 0,  // TCLK - used to encrypt network key during join
    NETWORK           = 1,  // NWK key - used to encrypt all data frames
    APPLICATION       = 2,  // APS link key - per-device-pair
};

struct ZbKey {
    ZbKeyType type;
    uint8_t   key[ZIGBEE_KEY_LEN];
    uint8_t   seqNum;           // key sequence number (NWK key rotation)
    uint32_t  capturedAt_ms;    // 0 = pre-loaded, else millis() when sniffed
    char      label[16];        // e.g. "Default TCLK", "Network", "Sniffed"
};

// Well-known default Zigbee Trust Center Link Key "ZigBeeAlliance09"
// 5A:69:67:42:65:65:41:6C:6C:69:61:6E:63:65:30:39
static const uint8_t ZIGBEE_DEFAULT_TCLK[ZIGBEE_KEY_LEN] = {
    0x5A, 0x69, 0x67, 0x42, 0x65, 0x65, 0x41, 0x6C,
    0x6C, 0x69, 0x61, 0x6E, 0x63, 0x65, 0x30, 0x39
};


class IEEE802154Sniffer {
public:
    IEEE802154Sniffer();

    // Lifecycle - separated so radio can be configured without starting RX
    bool    init(uint8_t channel = SNIFFER_DEFAULT_CHANNEL); // radio setup only
    bool    start();    // begin receiving - call after init()
    bool    stop();     // halt RX, radio stays configured
    bool    restart();  // stop + start

    // Legacy - init + start in one call
    bool    begin(uint8_t channel = SNIFFER_DEFAULT_CHANNEL);

    uint8_t update();   // call from loop()

    bool    isRunning()     const { return _running; }
    bool    isInitialised() const { return _initialised; }

    // Channel control
    void    setChannel(uint8_t channel);
    uint8_t getChannel() const { return _channel; }

    void startChannelHop(uint16_t interval_ms = 500);
    void stopChannelHop();

    // PCap recording - pass an open File or Stream (SD file)
    void startPcap(Stream *out);
    void stopPcap();
    bool isPcapActive() const { return _pcapOut != nullptr; }

    // Host list - caller may iterate directly
    LinkedList<HostRecord*> hosts;
    HostRecord *findHost(uint16_t shortAddr);
    void        printHosts();

    // Device labeling
    // labelHost(addr, type, label) - manually set type and friendly name
    // type: 'C'=coordinator 'R'=router 'E'=end device '?'=unknown
    bool        labelHost(uint16_t addr, char type, const char *label);

    // Load labels from a CSV string: "addr,type,label\naddr,type,label\n..."
    // e.g. "16CC,E,On-Off W Button\n1A2E,R,Color Bulb 1\n"
    void        loadLabels(const char *csv);

    // Returns label if set, else "0xADDR" - for use in _printFrame
    const char *addrLabel(uint16_t addr, char *buf, uint8_t bufLen);

    // -- Zigbee key management -------------------------------------------------
    // Preloaded with default TCLK on begin() - add more as captured
    LinkedList<ZbKey*> keys;

    // Add a key manually - returns false if duplicate seqNum for same type
    bool        addKey(ZbKeyType type, const uint8_t *key16,
                       uint8_t seqNum = 0, const char *label = nullptr);

    // Print all stored keys
    void        printKeys();

    // Look up network key by sequence number (nullptr if not found)
    ZbKey      *findNetworkKey(uint8_t seqNum);

    // True if we have a network key (can attempt decryption)
    bool        hasNetworkKey();

    // Stats
    uint32_t getFrameCount()   const { return _frameCount; }
    uint32_t getZigbeeCount()  const { return _zbCount; }
    uint32_t getThreadCount()  const { return _threadCount; }
    uint32_t getDroppedCount() const { return _dropped; }

    // Display filters
    bool no_bcast      = false;   // suppress BCAST→BCAST frames from output
    bool no_duplicates = false;   // suppress repeated hostA→hostB output

    // Callbacks
    void (*onFrame)(const FrameInfo &info) = nullptr;

    // Raw frame callback for key capture - receives decoded info + raw NWK payload
    // Set this to ZbKeyCapture::processFrame wrapper in main.cpp
    void (*onKeyCapture)(const FrameInfo &info,
                         const uint8_t *rawPayload, uint8_t rawLen) = nullptr;

    // ISR entry point - public for C weak symbol access
    static void rxCallback(uint8_t *frame, esp_ieee802154_frame_info_t *fi);

    // channel Info: index +11  + one extra for future flags
    std::array<uint8_t, 16> active_channels = {0};
    // uint8_t  active_channels[16] = {0};

private:
    uint8_t  _channel;
    bool     _initialised;  // init() completed
    bool     _running;      // start() called, RX active
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

    // Key interception
    bool  _extractSecurityHeader(const uint8_t *p, uint8_t len,
                                  uint32_t &frameCounter, uint8_t &keySeqNum);
    bool  _tryExtractNetworkKey(const FrameInfo &info,
                                 const uint8_t *payload, uint8_t payloadLen);

    static const char *_frameTypeName(uint8_t type);
    static const char *_zbNwkCmdName(uint8_t cmd);
};
