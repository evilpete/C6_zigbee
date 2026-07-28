/*
 * ZbKeyCapture.h — Zigbee Network Key interception via APS Transport Key
 */

#pragma once
#include <Arduino.h>
#include "IEEE802154Sniffer.h"

struct JoinState {
    uint16_t  shortAddr;
    uint64_t  extAddr;
    uint32_t  assocTime_ms;
    bool      active;
};

#define MAX_PENDING_JOINS  4

class ZbKeyCapture {
public:
    ZbKeyCapture(IEEE802154Sniffer &sniffer);

    bool processFrame(const FrameInfo &info, const uint8_t *rawFrame,
                      uint8_t rawLen, uint8_t macPayloadOffset);

    void (*onKeyCapture)(const ZbKey &key) = nullptr;

    void expireJoins(uint32_t timeout_ms = 30000);

private:
    IEEE802154Sniffer &_sniffer;
    JoinState          _joins[MAX_PENDING_JOINS];
    uint64_t           _coordinatorEUI64;   // captured from NWK EXT_SRC

    JoinState *_findJoin(uint16_t addr);
    JoinState *_allocJoin(uint16_t addr);
    void       _freeJoin(JoinState *j);

    void _handleAssocResponse(const FrameInfo &info);
    bool _handleTransportKey(const FrameInfo &info,
                              const uint8_t *nwkPayload, uint8_t nwkLen);

    bool _skipNwkHeader(const uint8_t *p, uint8_t len, uint8_t &apsOffset);

    bool _decryptApsPayload(const uint8_t *nwkPayload, uint8_t nwkLen,
                             uint8_t apsOffset,
                             const uint8_t *key,
                             uint64_t knownExtSrc,
                             uint8_t *plaintextOut, uint8_t &plaintextLen);

    bool _parseTransportKey(const uint8_t *aps, uint8_t apsLen,
                             uint8_t *networkKeyOut, uint8_t &seqNumOut);

    bool _ccmDecrypt(const uint8_t *key,
                     const uint8_t *nonce,
                     const uint8_t *aad,    uint8_t aadLen,
                     const uint8_t *ciphertext, uint8_t ciphertextLen,
                     uint8_t       *plaintext,
                     const uint8_t *mic,    uint8_t micLen);
};
