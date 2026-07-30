/*
 * IEEE802154_Sniffer — 802.15.4 promiscuous sniffer for ESP32-C6
 */

#pragma once

#define VERSION "0.5"
#include "esp_ieee802154_types.h"
#include <Arduino.h>
#include <LinkedList.h>
#include <stdint.h>

#define SNIFFER_DEFAULT_CHANNEL     26
#define SNIFFER_MIN_CHANNEL         11
#define SNIFFER_MAX_CHANNEL         26
#define SNIFFER_MAX_FRAME_LEN       128
#define SNIFFER_QUEUE_DEPTH         16
#define SNIFFER_MAX_ROUTE_HOPS      8

#define FC_FRAME_TYPE_MASK          0x07
#define FC_FRAME_TYPE_BEACON        0x00
#define FC_FRAME_TYPE_DATA          0x01
#define FC_FRAME_TYPE_ACK           0x02
#define FC_FRAME_TYPE_MAC_CMD       0x03

#define ADDR_MODE_NONE              0x00
#define ADDR_MODE_SHORT             0x02
#define ADDR_MODE_EXTENDED          0x03

#define MAC_CMD_ASSOC_REQUEST       0x01
#define MAC_CMD_ASSOC_RESPONSE      0x02
#define MAC_CMD_DATA_REQUEST        0x04

// Association Request capability info bits (802.15.4 5.3.1)
#define ASSOC_CAP_ALT_PAN_COORD     0x01
#define ASSOC_CAP_FFD               0x02  // 0 = RFD (simple/end device)
#define ASSOC_CAP_MAINS_POWER       0x04  // 0 = battery powered
#define ASSOC_CAP_RX_ON_IDLE        0x08  // 0 = sleepy, must poll for data
#define ASSOC_CAP_SECURITY          0x40
#define ASSOC_CAP_ALLOC_ADDR        0x80  // request a short address be assigned

// Simple/plain end device: RFD, battery, sleepy, no security capability,
// request a short address — advertises no active functionality.
#define ASSOC_CAP_SIMPLE_DEVICE     (ASSOC_CAP_ALLOC_ADDR)

#define ZB_NWK_TYPE_DATA            0x00
#define ZB_NWK_TYPE_CMD             0x01
#define ZB_NWK_FC_SECURITY          (1 << 9)
#define ZB_NWK_FC_SOURCE_ROUTE      (1 << 10)
#define ZB_NWK_FC_EXT_SRC           (1 << 11)
#define ZB_NWK_FC_EXT_DST           (1 << 12)

inline bool is_bcast(uint16_t addr) {
    return (addr == 0xFFFF || addr == 0xFFFE || addr == 0xFFFB ||
            addr == 0xFFFC || addr == 0xFFFD);
}

enum class DeviceType : uint8_t {
    UNKNOWN = 0, COORDINATOR = 1, ROUTER = 2, END_DEVICE = 3,
};

enum class FrameProtocol : uint8_t {
    UNKNOWN, ZIGBEE, THREAD, MATTER, RAW_802154,
};

struct RouteInfo {
    uint16_t nwkSrc;
    uint16_t nwkDst;
    uint16_t macSrc;
    uint16_t macDst;
    uint8_t  hopCount;
    uint16_t relays[SNIFFER_MAX_ROUTE_HOPS];
    uint8_t  radius;
    bool     hasSourceRoute;
};

struct SnifferFrame {
    uint8_t  data[SNIFFER_MAX_FRAME_LEN];
    uint8_t  len;
    int8_t   rssi;
    uint8_t  lqi;
    uint8_t  channel;
    uint32_t timestamp_us;
};

enum class BcastType : uint8_t {
    NOT_BCAST=0, ALL=1, ROUTERS=2, LP_ROUTERS=3, SLEEPY_ED=4, RESERVED=5,
};

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
    uint8_t       macPayloadOffset; // offset in raw frame where MAC payload starts

    bool          macSecurityEnabled;
    bool          macFramePending;
    bool          macAckRequest;
    bool          macIsRetry;
    bool          macPanIdCompressed;

    FrameProtocol protocol;
    const char   *protocolName;
    const char   *functionName;
    BcastType     bcastType;
    RouteInfo     route;
    bool          hasRoute;

    // Zigbee NWK
    uint8_t       zbNwkType;
    uint8_t       zbNwkCmd;
    uint8_t       zbNwkProtoVersion;
    bool          zbNwkSecurityEnabled;
    bool          zbIsMulticast;
    uint16_t      zbMulticastGroup;
    uint8_t       zbNwkRadius;

    // Beacon
    bool          beaconAssocPermit;
    bool          beaconCoordinator;
    uint8_t       beaconStackProfile;
    uint8_t       beaconProtocolVersion;
    bool          beaconRouterCapacity;
    bool          beaconEndDevCapacity;

    // Thread
    uint16_t      threadRloc16;
    uint8_t       threadMleType;
};

#define SNIFFER_MAX_LABEL_LEN   24

struct HostRecord {
    uint16_t   shortAddr;
    uint16_t   nwkAddr;
    uint64_t   extAddr;
    uint16_t   panId;
    char       label[SNIFFER_MAX_LABEL_LEN];
    int8_t     rssiMin, rssiMax, rssiLast;
    uint8_t    lqiLast, channel;
    uint32_t   firstSeen_ms, lastSeen_ms;
    uint32_t   frameCount, txCount, rxCount;
    uint32_t   retryCount, secureCount, acksMissed;
    DeviceType deviceType;
    FrameProtocol protocol;
    uint8_t    nwkProtoVersion;
    bool       beaconSeen, associationPermit, routerCapacity, endDevCapacity;
    uint8_t    lastMacSeq, lastNwkSeq;
    uint16_t   seqGaps;
    uint32_t   lastPollTime_ms, avgPollInterval_ms;
    LinkedList<uint16_t> connected_hosts;
};

#define PCAP_MAGIC           0xA1B2C3D4
#define PCAP_VERSION_MAJOR   2
#define PCAP_VERSION_MINOR   4
#define PCAP_LINKTYPE_802154 195

struct PcapGlobalHeader {
    uint32_t magic; uint16_t versionMajor; uint16_t versionMinor;
    int32_t thiszone; uint32_t sigfigs; uint32_t snaplen; uint32_t network;
} __attribute__((packed));

struct PcapPacketHeader {
    uint32_t ts_sec; uint32_t ts_usec; uint32_t incl_len; uint32_t orig_len;
} __attribute__((packed));

#define ZIGBEE_KEY_LEN  16

enum class ZbKeyType : uint8_t {
    TRUST_CENTER_LINK = 0, NETWORK = 1, APPLICATION = 2,
};

struct ZbKey {
    ZbKeyType type;
    uint8_t   key[ZIGBEE_KEY_LEN];
    uint8_t   seqNum;
    uint32_t  capturedAt_ms;
    char      label[16];
};

static const uint8_t ZIGBEE_SEQ_KEY[ZIGBEE_KEY_LEN] = {
    0x01, 0x03, 0x05, 0x07, 0x09, 0x0B, 0x0D, 0x0F,
    0x00, 0x02, 0x04, 0x06, 0x08, 0x0A, 0x0C, 0x0D
};

static const uint8_t ZIGBEE_ZERO_KEY[ZIGBEE_KEY_LEN] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static const uint8_t ZIGBEE_DEFAULT_TCLK[ZIGBEE_KEY_LEN] = {
    0x5A, 0x69, 0x67, 0x42, 0x65, 0x65, 0x41, 0x6C,
    0x6C, 0x69, 0x61, 0x6E, 0x63, 0x65, 0x30, 0x39
};

static const uint8_t ZIGBEE_EISY_TCLK[ZIGBEE_KEY_LEN] = {
      // 1, 164, 16, 98, 191, 158, 173, 122,
      // 143, 231, 42, 189, 182, 248, 24, 131
      0x01, 0xA4, 0x10, 0x62, 0xBF, 0x9E, 0xAD, 0x7A,
      0x8F, 0xE7, 0x2A, 0xBD, 0xB6, 0xF8, 0x18, 0x83
};

class IEEE802154Sniffer {
public:
    IEEE802154Sniffer();

    bool    init(uint8_t channel = SNIFFER_DEFAULT_CHANNEL);
    bool    start();
    bool    stop();
    bool    restart();
    bool    begin(uint8_t channel = SNIFFER_DEFAULT_CHANNEL);
    uint8_t update();

    bool    isRunning()     const { return _running; }
    bool    isInitialised() const { return _initialised; }

    void    setChannel(uint8_t channel);
    uint8_t getChannel() const { return _channel; }
    void    startChannelHop(uint16_t interval_ms = 500);
    void    stopChannelHop();

    // Beacon request TX — for active channel scanning
    bool    sendBeaconRequest();

    // Join TX — for associating with an open network as a plain end device
    uint64_t getOwnEUI64() const { return _ownEUI64; }
    bool    sendAssociationRequest(uint16_t dstPan, uint16_t dstShortAddr,
                                    uint8_t capabilityInfo = ASSOC_CAP_SIMPLE_DEVICE);
    // Poll parent for a queued (indirect) frame. Before association completes
    // we have no short address yet, so poll using our extended address;
    // afterwards pass useOwnShortAddr=true with the address the parent assigned.
    bool    sendDataRequest(uint16_t dstPan, uint16_t dstShortAddr,
                             bool useOwnShortAddr, uint16_t ownShortAddr = 0xFFFE);

    // Generic raw-MAC-frame transmit, for higher layers (e.g. ZbPing) that
    // build their own complete NWK/APS frames. Handles the stop-RX/TX/resume-RX
    // plumbing; caller supplies the full frame, FCS is appended by the radio.
    bool    sendRawFrame(const uint8_t *frame, uint8_t frameLen);

    void    startPcap(Stream *out);
    void    stopPcap();
    bool    isPcapActive() const { return _pcapOut != nullptr; }

    LinkedList<HostRecord*> hosts;
    HostRecord *findHost(uint16_t shortAddr);
    void        printHosts();
    bool        labelHost(uint16_t addr, char type, const char *label);
    void        loadLabels(const char *csv);
    const char *addrLabel(uint16_t addr, char *buf, uint8_t bufLen);

    LinkedList<ZbKey*> keys;
    bool        addKey(ZbKeyType type, const uint8_t *key16,
                       uint8_t seqNum = 0, const char *label = nullptr);
    void        printKeys();
    ZbKey      *findNetworkKey(uint8_t seqNum);
    ZbKey      *findLatestNetworkKey();  // most recently captured/added NETWORK key
    bool        hasNetworkKey();

    uint32_t getFrameCount()   const { return _frameCount; }
    uint32_t getZigbeeCount()  const { return _zbCount; }
    uint32_t getThreadCount()  const { return _threadCount; }
    uint32_t getDroppedCount() const { return _dropped; }

    bool no_bcast      = true;
    bool no_duplicates = false;

    void (*onFrame)(const FrameInfo &info) = nullptr;

    // Key capture callback — receives decoded info + raw frame + MAC payload offset
    // ZbKeyCapture sets this to intercept join frames
    void (*onKeyCapture)(const FrameInfo &info,
                         const uint8_t *rawFrame, uint8_t rawLen,
                         uint8_t macPayloadOffset) = nullptr;


    static void rxCallback(uint8_t *frame, esp_ieee802154_frame_info_t *fi);

    std::array<uint8_t, 18> active_channels = {0};

private:
    uint8_t  _channel;
    bool     _initialised;
    bool     _running;
    bool     _hopping;
    uint16_t _hopInterval;
    uint32_t _lastHop;
    uint8_t  _hopIdx;
    uint32_t _frameCount, _zbCount, _threadCount, _dropped;
    Stream  *_pcapOut;
    uint64_t _ownEUI64 = 0;

    static QueueHandle_t _rxQueue;

    bool  _decodeMac(const SnifferFrame &raw, FrameInfo &info);
    bool  _decodeZigbeeNwk(const uint8_t *p, uint8_t len, FrameInfo &info);
    bool  _decodeThreadMesh(const uint8_t *p, uint8_t len, FrameInfo &info);
    bool  _isThread(const uint8_t *payload, uint8_t len);
    bool  _updateHost(const FrameInfo &info);
    void  _printFrame(const FrameInfo &info);
    void  _writePcap(const SnifferFrame &raw);
    void  updateChannelHop();
    bool  _extractSecurityHeader(const uint8_t *p, uint8_t len,
                                  uint32_t &frameCounter, uint8_t &keySeqNum);
    bool  _tryExtractNetworkKey(const FrameInfo &info,
                                 const uint8_t *payload, uint8_t payloadLen);

    static const char *_frameTypeName(uint8_t type);
    static const char *_zbNwkCmdName(uint8_t cmd);
};
