/*
 * ZbPing.cpp — ZDO Node Descriptor ping
 *
 * Outgoing frame layers built here (innermost to outermost):
 *   ZDO Node_Desc_req payload: TransactionSeq(1) + NWKAddrOfInterest(2,LE)
 *   APS frame:  FC(1) dstEP(1) cluster(2,LE) profile(2,LE) srcEP(1) counter(1) + ZDO payload
 *   NWK frame:  FC(2) dst(2) src(2) radius(1) seq(1)
 *               AUX: secCtrl(1) frameCounter(4,LE) extSrc(8,LE) keySeq(1)
 *               CCM*-encrypted APS frame + MIC(4)
 *   MAC frame:  FC(2) seq(1) dstPAN(2) dstAddr(2) srcAddr(2) [PAN-ID compressed] + NWK frame
 *
 * CCM* nonce = srcEUI64(8,LE) | frameCounter(4,LE) | secCtrl(1)
 * AAD        = NWK header + AUX header (everything before the ciphertext)
 * (Same conventions already established/validated in ZbKeyCapture.cpp for
 * APS-layer Transport Key decryption - reused here at the NWK layer.)
 */

#include "ZbPing.h"
#include "mbedtls/ccm.h"

extern "C" {
#include "esp_random.h"
}

extern uint8_t Verbose;

ZbPing::ZbPing(IEEE802154Sniffer &sniffer, ZbJoiner &joiner)
    : _sniffer(sniffer), _joiner(joiner)
    , _nwkFrameCounter(0), _macSeq(0), _nwkSeq(0), _apsCounter(0), _zdoSeq(0)
{
    memset(_pending, 0, sizeof(_pending));
    memset(_cache, 0, sizeof(_cache));

    // Seed all counters from HWRNG so a reboot doesn't restart the NWK frame
    // counter at a value a receiver may have already seen from our EUI64
    // (frame-counter reuse breaks CCM* nonce uniqueness under the same key).
    uint32_t seed = esp_random();
    _nwkFrameCounter = seed;
    _macSeq          = (uint8_t)(seed >> 8);
    _nwkSeq          = (uint8_t)(seed >> 16);
    _apsCounter       = (uint8_t)(seed >> 24);
}

// -- Public -------------------------------------------------------------------

bool ZbPing::ping(uint16_t targetShortAddr, uint16_t targetPan) {
    if (!_joiner.isAssociated()) {
        Serial.println("[Ping] Not associated - run 'J' to join the network first");
        return false;
    }
    if (!_sniffer.findLatestNetworkKey()) {
        Serial.println("[Ping] No network key captured yet - can't encrypt ping");
        return false;
    }

    uint8_t seq = _zdoSeq++;
    uint8_t apsFrame[11];
    apsFrame[0]  = 0x00;  // APS FC: type=Data, delivery=unicast, unsecured
    apsFrame[1]  = ZB_ZDO_EP;
    apsFrame[2]  = (uint8_t)(ZB_ZDO_NODE_DESC_REQ & 0xFF);
    apsFrame[3]  = (uint8_t)(ZB_ZDO_NODE_DESC_REQ >> 8);
    apsFrame[4]  = (uint8_t)(ZB_ZDO_PROFILE_ID & 0xFF);
    apsFrame[5]  = (uint8_t)(ZB_ZDO_PROFILE_ID >> 8);
    apsFrame[6]  = ZB_ZDO_EP;
    apsFrame[7]  = _apsCounter++;
    apsFrame[8]  = seq;                                // ZDP transaction seq
    apsFrame[9]  = (uint8_t)(targetShortAddr & 0xFF);  // NWKAddrOfInterest
    apsFrame[10] = (uint8_t)(targetShortAddr >> 8);

    if (Verbose) {
        Serial.print(YEL);
        Serial.printf("[Ping] APS+ZDO plaintext: ");
        for (uint8_t b : apsFrame) Serial.printf("%02X ", b);
        Serial.println();
        Serial.print(ENDC);
    }

    if (!_nwkEncryptAndSend(targetPan, targetShortAddr, apsFrame, sizeof(apsFrame)))
        return false;

    _allocPending(targetShortAddr, targetPan, seq);
    Serial.printf("[Ping] Sent Node_Desc_req to 0x%04X (zdoSeq=%u)\n", targetShortAddr, seq);
    return true;
}

void ZbPing::update() {
    uint32_t now = millis();
    for (int i = 0; i < MAX_PENDING_PINGS; i++) {
        if (_pending[i].active && (now - _pending[i].sentAt_ms) > PING_TIMEOUT_MS) {
            Serial.printf("[Ping] Timeout: no response from 0x%04X after %ums\n",
                          _pending[i].target, (unsigned)PING_TIMEOUT_MS);
            _pending[i].active = false;
        }
    }
}

bool ZbPing::processFrame(const FrameInfo &info, const uint8_t *rawFrame,
                           uint8_t rawLen, uint8_t macPayloadOffset) {
    if (info.protocol != FrameProtocol::ZIGBEE)       return false;
    if (info.frameType != FC_FRAME_TYPE_DATA)         return false;
    if (!info.hasRoute || info.zbNwkType != ZB_NWK_TYPE_DATA) return false;
    if (!info.zbNwkSecurityEnabled)                   return false;
    if (is_bcast(info.route.nwkDst))                  return false;

    // Only spend effort decrypting if we're actually waiting on this source.
    PendingPing *p = _findPending(info.route.nwkSrc);
    if (!p) return false;

    if (macPayloadOffset >= rawLen) return false;
    const uint8_t *nwk = rawFrame + macPayloadOffset;
    uint8_t nwkLen = rawLen - macPayloadOffset;

    uint8_t plain[96];
    uint8_t plainLen = 0;
    if (!_nwkDecrypt(nwk, nwkLen, info.route.nwkSrc, plain, plainLen)) {
        if (Verbose) {
            Serial.print(YEL);
            Serial.printf("[Ping] Decrypt failed for response from 0x%04X\n", info.route.nwkSrc);
            Serial.print(ENDC);
        }
        return false;
    }

    if (plainLen < 8) return false;
    uint8_t apsFc = plain[0];
    if ((apsFc & 0x03) != 0x00) return false;  // not an APS Data frame
    if ((apsFc >> 5) & 0x01) {
        Serial.println("[Ping] Response is APS-secured - not supported, skipping");
        return false;
    }

    uint16_t cluster = (uint16_t)plain[2] | ((uint16_t)plain[3] << 8);
    uint16_t profile = (uint16_t)plain[4] | ((uint16_t)plain[5] << 8);
    if (cluster != ZB_ZDO_NODE_DESC_RSP || profile != ZB_ZDO_PROFILE_ID) return false;

    const uint8_t *zdo = plain + 8;
    uint8_t zdoLen = plainLen - 8;
    if (zdoLen < 17) return false;  // seq(1)+status(1)+nwkAddr(2)+nodeDesc(13)

    uint32_t rtt = millis() - p->sentAt_ms;
    p->active = false;

    uint8_t status = zdo[1];
    if (status != 0x00) {
        Serial.printf("[Ping] 0x%04X returned ZDO status 0x%02X (no descriptor)\n",
                      info.route.nwkSrc, status);
        return true;
    }

    _reportNodeDesc(info.route.nwkSrc, &zdo[4], rtt);
    return true;
}

// -- Pending / cache tables -----------------------------------------------------

PendingPing *ZbPing::_findPending(uint16_t target) {
    for (int i = 0; i < MAX_PENDING_PINGS; i++)
        if (_pending[i].active && _pending[i].target == target) return &_pending[i];
    return nullptr;
}

PendingPing *ZbPing::_allocPending(uint16_t target, uint16_t pan, uint8_t zdoSeq) {
    for (int i = 0; i < MAX_PENDING_PINGS; i++) {
        if (!_pending[i].active) {
            _pending[i].active    = true;
            _pending[i].target    = target;
            _pending[i].pan       = pan;
            _pending[i].zdoSeq    = zdoSeq;
            _pending[i].sentAt_ms = millis();
            return &_pending[i];
        }
    }
    PendingPing *oldest = &_pending[0];
    for (int i = 1; i < MAX_PENDING_PINGS; i++)
        if (_pending[i].sentAt_ms < oldest->sentAt_ms) oldest = &_pending[i];
    oldest->active    = true;
    oldest->target    = target;
    oldest->pan       = pan;
    oldest->zdoSeq    = zdoSeq;
    oldest->sentAt_ms = millis();
    return oldest;
}

NodeDescCache *ZbPing::_findCache(uint16_t addr) {
    for (int i = 0; i < MAX_NODE_DESC_CACHE; i++)
        if (_cache[i].valid && _cache[i].addr == addr) return &_cache[i];
    return nullptr;
}

NodeDescCache *ZbPing::_allocCache(uint16_t addr) {
    for (int i = 0; i < MAX_NODE_DESC_CACHE; i++) {
        if (!_cache[i].valid) {
            _cache[i].valid = true;
            _cache[i].addr  = addr;
            return &_cache[i];
        }
    }
    // Table full - best-effort cache, just recycle the first slot.
    _cache[0].valid = true;
    _cache[0].addr  = addr;
    return &_cache[0];
}

// -- NWK header walk (locates AUX header) --------------------------------------

bool ZbPing::_findAuxHeader(const uint8_t *nwk, uint8_t len, uint16_t nwkFc,
                             uint8_t &auxOffset) {
    uint8_t off = 8;  // FC(2)+dst(2)+src(2)+radius(1)+seq(1)
    if (off > len) return false;

    bool multicast = (nwkFc >> 8) & 0x01;
    if (multicast) { if (off + 1 > len) return false; off++; }

    if ((nwkFc & ZB_NWK_FC_EXT_DST) && off + 8 <= len) off += 8;
    if ((nwkFc & ZB_NWK_FC_EXT_SRC) && off + 8 <= len) off += 8;

    if (nwkFc & ZB_NWK_FC_SOURCE_ROUTE) {
        if (off + 2 > len) return false;
        uint8_t relayCount = nwk[off];
        off += 2 + relayCount * 2;
        if (off > len) return false;
    }

    if (!(nwkFc & ZB_NWK_FC_SECURITY)) return false;
    auxOffset = off;
    return true;
}

// -- NWK-layer CCM* decrypt (incoming) -------------------------------------------

bool ZbPing::_nwkDecrypt(const uint8_t *nwk, uint8_t nwkLen, uint16_t nwkSrc,
                          uint8_t *plainOut, uint8_t &plainLen) {
    if (nwkLen < 10) return false;
    uint16_t nwkFc = (uint16_t)nwk[0] | ((uint16_t)nwk[1] << 8);

    uint8_t auxOffset;
    if (!_findAuxHeader(nwk, nwkLen, nwkFc, auxOffset)) return false;
    if (auxOffset + 6 > nwkLen) return false;  // secCtrl(1)+fc(4)+keySeq(1) minimum

    uint8_t secCtrl  = nwk[auxOffset];
    uint8_t secLevel = secCtrl & 0x07;
    bool    hasExtSrc = (secCtrl >> 5) & 0x01;  // spec bit5 = Extended Nonce

    uint8_t off = auxOffset + 1;
    const uint8_t *frameCounterBytes = &nwk[off];
    off += 4;

    uint64_t srcEui64 = 0;
    if (hasExtSrc) {
        if (off + 8 > nwkLen) return false;
        for (int i = 0; i < 8; i++) srcEui64 |= ((uint64_t)nwk[off + i] << (8 * i));
        off += 8;
    } else {
        HostRecord *h = _sniffer.findHost(nwkSrc);
        if (!h || h->extAddr == 0) {
            Serial.printf("[Ping] No cached EUI64 for 0x%04X - can't build nonce\n", nwkSrc);
            return false;
        }
        srcEui64 = h->extAddr;  // same canonical-order convention as _ownEUI64
    }

    if (off + 1 > nwkLen) return false;
    uint8_t keySeq = nwk[off];
    off += 1;

    uint8_t cipherStart = off;

    bool encrypted = (secLevel & 0x04) != 0;
    uint8_t micLen;
    switch (secLevel & 0x03) {
        case 0:  micLen = 0;  break;
        case 1:  micLen = 4;  break;
        case 2:  micLen = 8;  break;
        default: micLen = 16; break;
    }

    if (cipherStart + micLen > nwkLen) return false;
    uint8_t cipherLen = nwkLen - cipherStart - micLen;
    if (cipherLen == 0 || cipherLen > 96) return false;

    ZbKey *key = _sniffer.findNetworkKey(keySeq);
    if (!key) {
        Serial.printf("[Ping] No network key for seq=%u - can't decrypt response\n", keySeq);
        return false;
    }

    if (!encrypted) {
        // MIC-only: payload already plaintext (MIC not verified here).
        memcpy(plainOut, &nwk[cipherStart], cipherLen);
        plainLen = cipherLen;
        return true;
    }

    uint8_t nonce[13];
    for (int i = 0; i < 8; i++) nonce[i] = (uint8_t)(srcEui64 >> (8 * i));
    memcpy(nonce + 8, frameCounterBytes, 4);
    nonce[12] = secCtrl;

    mbedtls_ccm_context ctx;
    mbedtls_ccm_init(&ctx);
    int ret = mbedtls_ccm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key->key, 128);
    if (ret == 0) {
        ret = mbedtls_ccm_star_auth_decrypt(&ctx, cipherLen,
                                             nonce, sizeof(nonce),
                                             nwk, cipherStart,  // AAD: header + AUX
                                             &nwk[cipherStart], plainOut,
                                             &nwk[cipherStart + cipherLen], micLen);
    }
    mbedtls_ccm_free(&ctx);
    if (ret != 0) {
        Serial.printf("[Ping] NWK decrypt failed for 0x%04X (keySeq=%u)\n", nwkSrc, keySeq);
        return false;
    }
    plainLen = cipherLen;
    return true;
}

// -- NWK-layer CCM* encrypt + transmit (outgoing) --------------------------------

bool ZbPing::_nwkEncryptAndSend(uint16_t dstPan, uint16_t dstShort,
                                 const uint8_t *apsFrame, uint8_t apsLen) {
    ZbKey *key = _sniffer.findLatestNetworkKey();
    if (!key) return false;
    if (apsLen > 32) return false;

    uint16_t ownShort = _joiner.shortAddr();
    uint64_t ownEui64 = _sniffer.getOwnEUI64();

    // NWK header: FC(2) dst(2) src(2) radius(1) seq(1)
    // type=Data, protoVersion=2 (Zigbee PRO), discoverRoute=1 (we're a brand
    // new device - routers likely have no route to us yet), security=1.
    uint16_t nwkFc = 0x0048 | ZB_NWK_FC_SECURITY;
    uint8_t nwk[8];
    nwk[0] = (uint8_t)(nwkFc & 0xFF);
    nwk[1] = (uint8_t)(nwkFc >> 8);
    nwk[2] = (uint8_t)(dstShort & 0xFF);
    nwk[3] = (uint8_t)(dstShort >> 8);
    nwk[4] = (uint8_t)(ownShort & 0xFF);
    nwk[5] = (uint8_t)(ownShort >> 8);
    nwk[6] = 30;  // radius
    nwk[7] = _nwkSeq++;

    // AUX header: secCtrl(1) frameCounter(4,LE) extSrc(8,LE) keySeq(1)
    // secLevel=5 (ENC-MIC32), keyIdentifier=1 (Network Key), hasExtSrc=1 so any
    // receiver can build the nonce even without our EUI64 cached.
    uint8_t aux[14];
    aux[0] = 5 | (0x01 << 3) | (0x01 << 5);
    _nwkFrameCounter++;
    aux[1] = (uint8_t)(_nwkFrameCounter & 0xFF);
    aux[2] = (uint8_t)(_nwkFrameCounter >> 8);
    aux[3] = (uint8_t)(_nwkFrameCounter >> 16);
    aux[4] = (uint8_t)(_nwkFrameCounter >> 24);
    for (int i = 0; i < 8; i++) aux[5 + i] = (uint8_t)(ownEui64 >> (8 * i));
    aux[13] = key->seqNum;

    uint8_t aad[8 + 14];
    memcpy(aad, nwk, 8);
    memcpy(aad + 8, aux, 14);

    uint8_t nonce[13];
    for (int i = 0; i < 8; i++) nonce[i] = (uint8_t)(ownEui64 >> (8 * i));
    memcpy(nonce + 8, &aux[1], 4);
    nonce[12] = aux[0];

    uint8_t ciphertext[32];
    uint8_t tag[4];

    mbedtls_ccm_context ctx;
    mbedtls_ccm_init(&ctx);
    int ret = mbedtls_ccm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key->key, 128);
    if (ret == 0) {
        ret = mbedtls_ccm_star_encrypt_and_tag(&ctx, apsLen,
                                                nonce, sizeof(nonce),
                                                aad, sizeof(aad),
                                                apsFrame, ciphertext,
                                                tag, sizeof(tag));
    }
    mbedtls_ccm_free(&ctx);
    if (ret != 0) {
        Serial.println("[Ping] NWK encrypt failed");
        return false;
    }

    // MAC header: FC(2) seq(1) dstPAN(2) dstAddr(2) srcAddr(2), PAN-ID compressed.
    uint8_t frame[SNIFFER_MAX_FRAME_LEN];
    uint8_t off = 0;
    frame[off++] = 0x61;  // type=Data, ack request=1, PAN ID compression=1
    frame[off++] = 0x88;  // dst addr mode=short, src addr mode=short
    frame[off++] = _macSeq++;
    frame[off++] = (uint8_t)(dstPan & 0xFF);
    frame[off++] = (uint8_t)(dstPan >> 8);
    frame[off++] = (uint8_t)(dstShort & 0xFF);
    frame[off++] = (uint8_t)(dstShort >> 8);
    frame[off++] = (uint8_t)(ownShort & 0xFF);
    frame[off++] = (uint8_t)(ownShort >> 8);
    memcpy(&frame[off], nwk, 8);              off += 8;
    memcpy(&frame[off], aux, 14);             off += 14;
    memcpy(&frame[off], ciphertext, apsLen);  off += apsLen;
    memcpy(&frame[off], tag, 4);              off += 4;

    if (Verbose) {
        Serial.print(YEL);
        Serial.printf("[Ping] TX nonce: ");
        for (int i = 0; i < 13; i++) Serial.printf("%02X", nonce[i]);
        Serial.printf(" fc=%08lX secCtrl=%02X\n", _nwkFrameCounter, aux[0]);
        Serial.print(ENDC);
    }

    return _sniffer.sendRawFrame(frame, off);
}

// -- Reporting ------------------------------------------------------------------

void ZbPing::_reportNodeDesc(uint16_t addr, const uint8_t *d, uint32_t rtt_ms) {
    uint8_t  logicalType      = d[0] & 0x07;
    bool     complexDescAvail = (d[0] >> 3) & 0x01;
    bool     userDescAvail    = (d[0] >> 4) & 0x01;
    uint8_t  macCapability    = d[2];
    uint16_t manufacturerCode = (uint16_t)d[3] | ((uint16_t)d[4] << 8);
    uint8_t  maxBufferSize    = d[5];
    uint16_t maxInTransferSize  = (uint16_t)d[6]  | ((uint16_t)d[7]  << 8);
    uint16_t serverMask         = (uint16_t)d[8]  | ((uint16_t)d[9]  << 8);
    uint16_t maxOutTransferSize = (uint16_t)d[10] | ((uint16_t)d[11] << 8);
    uint8_t  descCapability     = d[12];

    Serial.printf("[Ping] 0x%04X responded in %lums - %s, MAC cap=0x%02X, mfg=0x%04X\n",
                  addr, rtt_ms, _logicalTypeName(logicalType), macCapability, manufacturerCode);

    NodeDescCache *c = _findCache(addr);
    bool isNew = (c == nullptr);
    if (!c) c = _allocCache(addr);

    if (isNew) {
        Serial.printf("[Ping]   NEW device descriptor for 0x%04X (first sighting)\n", addr);
    } else {
        bool changed = false;
        #define REPORT_CHANGE(field, fmt) \
            if (c->field != field) { \
                Serial.printf("[Ping]   CHANGED %-19s " fmt " -> " fmt "\n", \
                              #field, c->field, field); \
                changed = true; \
            }
        REPORT_CHANGE(logicalType, "%u")
        REPORT_CHANGE(macCapability, "0x%02X")
        REPORT_CHANGE(manufacturerCode, "0x%04X")
        REPORT_CHANGE(maxBufferSize, "%u")
        REPORT_CHANGE(maxInTransferSize, "%u")
        REPORT_CHANGE(serverMask, "0x%04X")
        REPORT_CHANGE(maxOutTransferSize, "%u")
        REPORT_CHANGE(descCapability, "0x%02X")
        #undef REPORT_CHANGE
        if (!changed)
            Serial.println("[Ping]   Descriptor unchanged since last sighting");
    }

    c->valid               = true;
    c->addr                = addr;
    c->logicalType         = logicalType;
    c->complexDescAvail    = complexDescAvail;
    c->userDescAvail       = userDescAvail;
    c->macCapability       = macCapability;
    c->manufacturerCode    = manufacturerCode;
    c->maxBufferSize       = maxBufferSize;
    c->maxInTransferSize   = maxInTransferSize;
    c->serverMask          = serverMask;
    c->maxOutTransferSize  = maxOutTransferSize;
    c->descCapability      = descCapability;
}

const char *ZbPing::_logicalTypeName(uint8_t t) {
    switch (t) {
        case 0:  return "Coordinator";
        case 1:  return "Router";
        case 2:  return "End Device";
        default: return "Reserved";
    }
}
