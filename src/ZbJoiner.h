/*
 * ZbJoiner.h — join a Zigbee network as a plain end device
 *
 * Manually triggered (serial command). Sends a MAC Association Request to a
 * parent (coordinator/router) that is advertising association-permit, then
 * polls the parent with MAC Data Requests until the (indirectly-queued)
 * Association Response arrives — mirroring how a real sleepy end device
 * joins. No active application functionality is advertised; capability info
 * defaults to ASSOC_CAP_SIMPLE_DEVICE (RFD, battery, sleepy, alloc-addr).
 *
 * Once associated, the Transport Key exchange that follows is already
 * captured passively by ZbKeyCapture, since the sniffer is promiscuous.
 */

#pragma once
#include <Arduino.h>
#include "IEEE802154Sniffer.h"

enum class JoinPhase : uint8_t {
    IDLE = 0, WAIT_ASSOC_RESP = 1, ASSOCIATED = 2, FAILED = 3,
};

class ZbJoiner {
public:
    ZbJoiner(IEEE802154Sniffer &sniffer);

    // Kick off a join attempt against a specific parent.
    bool start(uint16_t parentShortAddr, uint16_t parentPan,
               uint8_t capabilityInfo = ASSOC_CAP_SIMPLE_DEVICE);
    void abort();

    // Call every loop() — drives Data Request polling / timeout.
    void update();

    // Call for every decoded frame — watches for our Association Response.
    bool processFrame(const FrameInfo &info, const uint8_t *rawFrame,
                       uint8_t rawLen, uint8_t macPayloadOffset);

    JoinPhase phase()        const { return _phase; }
    bool      isActive()     const { return _phase == JoinPhase::WAIT_ASSOC_RESP; }
    bool      isAssociated() const { return _phase == JoinPhase::ASSOCIATED; }
    uint16_t  shortAddr()    const { return _assignedShortAddr; }
    void      printStatus()  const;

private:
    IEEE802154Sniffer &_sniffer;
    JoinPhase _phase;
    uint16_t  _parentShort, _parentPan;
    uint16_t  _assignedShortAddr;
    uint32_t  _startTime_ms, _lastPoll_ms;
    uint8_t   _pollCount;

    static const char *_statusName(uint8_t status);
};
