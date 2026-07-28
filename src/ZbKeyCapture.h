/*
 * ZbKeyCapture.h — Zigbee Network Key interception via APS Transport Key
 *
 * When a device joins a Zigbee network:
 *   1. Device sends Association Request (MAC Cmd 0x01)
 *   2. Coordinator sends Association Response (MAC Cmd 0x02)
 *   3. Coordinator sends Transport Key (APS Cmd 0x05) encrypted with TCLK
 *   4. Device sends Device Announce (ZDP 0x0013)
 *
 * Step 3 contains the Network Key encrypted with AES-128-CCM* using the TCLK.
 * If the network uses the default TCLK "ZigBeeAlliance09", we can decrypt it.
 *
 * Frame structure at the point we receive it:
 *   [MAC header] [NWK header] [NWK AUX security header] [encrypted APS payload] [MIC-32]
 *
 * APS Transport Key payload (after decryption):
 *   APS FC (1) | APS Cmd = 0x05 (1) | Key type = 0x01 NWK (1) |
 *   Network Key (16) | Key seq num (1) | Dest EUI64 (8) | Src EUI64 (8)
 */

#pragma once
#include <Arduino.h>
#include "IEEE802154Sniffer.h"

// Join state machine — tracks devices mid-join
struct JoinState {
    uint16_t  shortAddr;      // device being joined
    uint64_t  extAddr;        // EUI64 from association
    uint32_t  assocTime_ms;   // when association response was seen
    bool      active;         // slot in use
};

#define MAX_PENDING_JOINS  4  // max simultaneous joining devices

class ZbKeyCapture {
public:
    ZbKeyCapture(IEEE802154Sniffer &sniffer);

    // Call from update() after frame is decoded — checks for join frames
    // Returns true if a new network key was captured
    bool processFrame(const FrameInfo &info, const uint8_t *rawFrame,
                      uint8_t rawLen, uint8_t macPayloadOffset);

    // Callback — fires when a network key is successfully extracted
    void (*onKeyCapture)(const ZbKey &key) = nullptr;

    // Expire stale join states (call periodically)
    void expireJoins(uint32_t timeout_ms = 30000);

private:
    IEEE802154Sniffer &_sniffer;
    JoinState         _joins[MAX_PENDING_JOINS];

    // Join state management
    JoinState *_findJoin(uint16_t addr);
    JoinState *_allocJoin(uint16_t addr);
    void       _freeJoin(JoinState *j);

    // Frame handlers
    void _handleAssocResponse(const FrameInfo &info);
    bool _handleTransportKey(const FrameInfo &info,
                              const uint8_t *nwkPayload, uint8_t nwkLen);

    // Navigate NWK layer to find the encrypted APS payload
    bool _skipNwkHeader(const uint8_t *p, uint8_t len, uint8_t &apsOffset);

    // Parse NWK AUX security header, build nonce, decrypt APS payload
    bool _decryptNwkPayload(const uint8_t *frame, uint8_t frameLen,
                             uint8_t apsOffset,
                             const uint8_t *key,
                             uint8_t *plaintextOut, uint8_t &plaintextLen);

    // Parse decrypted APS Transport Key command
    bool _parseTransportKey(const uint8_t *aps, uint8_t apsLen,
                             uint8_t *networkKeyOut, uint8_t &seqNumOut);

    // AES-128-CCM* via mbedtls
    bool _ccmDecrypt(const uint8_t *key,
                     const uint8_t *nonce,    // 13 bytes
                     const uint8_t *aad,      // additional auth data
                     uint8_t        aadLen,
                     const uint8_t *ciphertext,
                     uint8_t        ciphertextLen,
                     uint8_t       *plaintext,
                     const uint8_t *mic,      // 4 bytes MIC-32
                     uint8_t        micLen);
};
