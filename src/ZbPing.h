/*
 * ZbPing.h — application-layer "ping" via ZDO Node Descriptor Request/Response
 *
 * Zigbee has no ICMP-style ping. Reachability is tested here the same way
 * ZHA / Zigbee2MQTT do it: send a ZDO Node_Desc_req (cluster 0x0002) asking
 * a device to describe itself, and wait for its Node_Desc_rsp (0x8002).
 *
 * This requires the sniffer to be an actual network member — the request
 * and response are NWK-layer encrypted with the network key, and framed as a
 * normal short-address unicast, so we need our own assigned short address
 * (from ZbJoiner, after a successful 'J' join) plus a captured network key.
 *
 * Every decoded Node Descriptor is cached per host; a repeat ping reports
 * whether the descriptor is unchanged, or logs exactly which fields are new
 * or different from the previous sighting.
 *
 * find_lock (ZigDiggity "find_lock"): enumerate a device's endpoints
 * (Active_EP_req) and each endpoint's clusters (Simple_Desc_req), and flag
 * any device exposing the Door Lock cluster (0x0101). Reuses the same ZDO
 * request/response + NWK crypto machinery as ping.
 */

#pragma once
#include <Arduino.h>
#include "IEEE802154Sniffer.h"
#include "ZbJoiner.h"

#define ZB_ZDO_PROFILE_ID           0x0000
#define ZB_ZDO_EP                   0x00
#define ZB_ZDO_NODE_DESC_REQ        0x0002
#define ZB_ZDO_NODE_DESC_RSP        0x8002
#define ZB_ZDO_SIMPLE_DESC_REQ      0x0004
#define ZB_ZDO_SIMPLE_DESC_RSP      0x8004
#define ZB_ZDO_ACTIVE_EP_REQ        0x0005
#define ZB_ZDO_ACTIVE_EP_RSP        0x8005

#define ZB_CLUSTER_DOOR_LOCK        0x0101

#define MAX_PENDING_PINGS   6
#define MAX_NODE_DESC_CACHE 32
#define MAX_LOCK_ENDPOINTS  16
#define MAX_LOCK_SWEEP      32
#define PING_TIMEOUT_MS     3000
#define LOCK_STEP_TIMEOUT_MS 2500

struct PendingPing {
    bool     active;
    uint16_t target;
    uint16_t pan;
    uint8_t  zdoSeq;
    uint32_t sentAt_ms;
};

// Decoded Zigbee Node Descriptor (2.3.2.3), cached per short address so we
// can report what changed between pings.
struct NodeDescCache {
    bool     valid;
    uint16_t addr;
    uint8_t  logicalType;         // 0=coordinator 1=router 2=end device
    bool     complexDescAvail;
    bool     userDescAvail;
    uint8_t  macCapability;
    uint16_t manufacturerCode;
    uint8_t  maxBufferSize;
    uint16_t maxInTransferSize;
    uint16_t serverMask;
    uint16_t maxOutTransferSize;
    uint8_t  descCapability;
};

enum class LockScanPhase : uint8_t { IDLE, WAIT_ACTIVE_EP, WAIT_SIMPLE_DESC };

class ZbPing {
public:
    ZbPing(IEEE802154Sniffer &sniffer, ZbJoiner &joiner);

    // Send a Node_Desc_req to targetShortAddr (on network targetPan).
    // Requires joiner.isAssociated() and a captured network key.
    bool ping(uint16_t targetShortAddr, uint16_t targetPan);

    // find_lock: enumerate endpoints/clusters of one host and flag it if it
    // exposes the Door Lock cluster. findLockSweepAll() scans every known host
    // sequentially. Same prerequisites as ping (joined + network key).
    bool findLock(uint16_t targetShortAddr, uint16_t targetPan);
    void findLockSweepAll();
    void printLockStatus() const;

    void update();  // drives pending-ping + lock-scan timeouts — call every loop()

    // Call for every decoded frame — watches for ZDO responses addressed to us.
    bool processFrame(const FrameInfo &info, const uint8_t *rawFrame,
                       uint8_t rawLen, uint8_t macPayloadOffset);

private:
    IEEE802154Sniffer &_sniffer;
    ZbJoiner          &_joiner;

    PendingPing    _pending[MAX_PENDING_PINGS];
    NodeDescCache  _cache[MAX_NODE_DESC_CACHE];
    uint32_t       _nwkFrameCounter;
    uint8_t        _macSeq;
    uint8_t        _nwkSeq;
    uint8_t        _apsCounter;
    uint8_t        _zdoSeq;

    // find_lock scan state (one target at a time; sweep queues the rest).
    LockScanPhase  _lockPhase;
    uint16_t       _lockTarget, _lockPan;
    uint8_t        _lockEndpoints[MAX_LOCK_ENDPOINTS];
    uint8_t        _lockEpCount, _lockEpIndex;
    uint32_t       _lockSentAt_ms;
    bool           _lockFound, _lockSweeping;
    uint16_t       _sweepQueue[MAX_LOCK_SWEEP];
    uint8_t        _sweepLen, _sweepIdx;
    uint16_t       _sweepPan;

    PendingPing   *_findPending(uint16_t target);
    PendingPing   *_allocPending(uint16_t target, uint16_t pan, uint8_t zdoSeq);
    NodeDescCache *_findCache(uint16_t addr);
    NodeDescCache *_allocCache(uint16_t addr);

    // Locates the AUX security header within a NWK payload (after the fixed
    // + optional header fields), mirroring _decodeZigbeeNwk's field walk.
    bool _findAuxHeader(const uint8_t *nwk, uint8_t len, uint16_t nwkFc,
                        uint8_t &auxOffset);

    // Build APS+ZDO header, NWK-encrypt and send. `extra` is the ZDO payload
    // after the transaction-sequence byte. Returns the ZDP seq, or -1 on fail.
    int  _sendZdoReq(uint16_t cluster, uint16_t target, uint16_t pan,
                     const uint8_t *extra, uint8_t extraLen);
    bool _nwkEncryptAndSend(uint16_t dstPan, uint16_t dstShort,
                            const uint8_t *apsFrame, uint8_t apsLen);
    bool _nwkDecrypt(const uint8_t *nwk, uint8_t nwkLen, uint16_t nwkSrc,
                     uint8_t *plainOut, uint8_t &plainLen);

    void _reportNodeDesc(uint16_t addr, const uint8_t *nodeDesc, uint32_t rtt_ms);
    static const char *_logicalTypeName(uint8_t t);

    // find_lock helpers
    bool _startLockScan(uint16_t target, uint16_t pan);
    void _sendSimpleDescReq(uint8_t endpoint);
    void _handleActiveEpRsp(uint16_t src, const uint8_t *zdo, uint8_t zdoLen);
    void _handleSimpleDescRsp(uint16_t src, const uint8_t *zdo, uint8_t zdoLen);
    void _finishLockTarget();
    void _nextSweepOrIdle();
};
