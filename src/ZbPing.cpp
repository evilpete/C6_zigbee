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
    , _lockPhase(LockScanPhase::IDLE), _lockTarget(0xFFFF), _lockPan(0xFFFF)
    , _lockEpCount(0), _lockEpIndex(0), _lockSentAt_ms(0)
    , _lockFound(false), _lockSweeping(false)
    , _sweepLen(0), _sweepIdx(0), _sweepPan(0xFFFF)
{
    memset(_pending, 0, sizeof(_pending));
    memset(_cache, 0, sizeof(_cache));
    memset(_lockEndpoints, 0, sizeof(_lockEndpoints));
    memset(_sweepQueue, 0, sizeof(_sweepQueue));

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

// Build an APS+ZDO request, NWK-encrypt and transmit it. `extra` is the ZDO
// payload following the transaction-sequence byte. Returns the ZDP transaction
// sequence used, or -1 on failure. Shared by ping() and find_lock.
int ZbPing::_sendZdoReq(uint16_t cluster, uint16_t target, uint16_t pan,
                         const uint8_t *extra, uint8_t extraLen) {
    uint8_t seq = _zdoSeq++;
    uint8_t aps[16];
    if (9 + extraLen > (int)sizeof(aps)) return -1;
    aps[0] = 0x00;  // APS FC: type=Data, delivery=unicast, unsecured
    aps[1] = ZB_ZDO_EP;
    aps[2] = (uint8_t)(cluster & 0xFF);
    aps[3] = (uint8_t)(cluster >> 8);
    aps[4] = (uint8_t)(ZB_ZDO_PROFILE_ID & 0xFF);
    aps[5] = (uint8_t)(ZB_ZDO_PROFILE_ID >> 8);
    aps[6] = ZB_ZDO_EP;
    aps[7] = _apsCounter++;
    aps[8] = seq;                       // ZDP transaction seq
    for (uint8_t i = 0; i < extraLen; i++) aps[9 + i] = extra[i];
    uint8_t apsLen = 9 + extraLen;

    if (Verbose) {
        Serial.printf("[ZDO] cluster=0x%04X -> 0x%04X plaintext: ", cluster, target);
        for (uint8_t i = 0; i < apsLen; i++) Serial.printf("%02X ", aps[i]);
        Serial.println();
    }

    if (!_nwkEncryptAndSend(pan, target, aps, apsLen)) return -1;
    return seq;
}

bool ZbPing::ping(uint16_t targetShortAddr, uint16_t targetPan) {
    if (!_joiner.isAssociated()) {
        Serial.println("[Ping] Not associated - run 'J' to join the network first");
        return false;
    }
    if (!_sniffer.findLatestNetworkKey()) {
        Serial.println("[Ping] No network key captured yet - can't encrypt ping");
        return false;
    }

    uint8_t noi[2] = { (uint8_t)(targetShortAddr & 0xFF), (uint8_t)(targetShortAddr >> 8) };
    int seq = _sendZdoReq(ZB_ZDO_NODE_DESC_REQ, targetShortAddr, targetPan, noi, 2);
    if (seq < 0) return false;

    _allocPending(targetShortAddr, targetPan, (uint8_t)seq);
    Serial.printf("[Ping] Sent Node_Desc_req to 0x%04X (zdoSeq=%u)\n", targetShortAddr, seq);
    return true;
}

// -- find_lock -----------------------------------------------------------------

bool ZbPing::findLock(uint16_t targetShortAddr, uint16_t targetPan) {
    if (!_joiner.isAssociated()) {
        Serial.println("[Lock] Not associated - run 'J' to join the network first");
        return false;
    }
    if (!_sniffer.findLatestNetworkKey()) {
        Serial.println("[Lock] No network key captured yet - can't probe");
        return false;
    }
    if (_lockPhase != LockScanPhase::IDLE) {
        Serial.printf("[Lock] Busy scanning 0x%04X - try again shortly\n", _lockTarget);
        return false;
    }
    _lockSweeping = false;
    return _startLockScan(targetShortAddr, targetPan);
}

void ZbPing::findLockSweepAll() {
    if (!_joiner.isAssociated() || !_sniffer.findLatestNetworkKey()) {
        Serial.println("[Lock] Need a join ('J') and a captured network key first");
        return;
    }
    _sweepLen = 0;
    _sweepIdx = 0;
    _sweepPan = 0xFFFF;
    for (int i = 0; i < _sniffer.hosts.size() && _sweepLen < MAX_LOCK_SWEEP; i++) {
        HostRecord *h = _sniffer.hosts.get(i);
        if (h->shortAddr == 0xFFFE || h->shortAddr == 0xFFFF) continue;
        if (h->shortAddr == 0x0000) continue;  // skip coordinator (that's us-ward)
        _sweepQueue[_sweepLen++] = h->shortAddr;
        if (_sweepPan == 0xFFFF && h->panId && h->panId != 0xFFFF) _sweepPan = h->panId;
    }
    if (_sweepLen == 0) {
        Serial.println("[Lock] No hosts to sweep");
        return;
    }
    _lockSweeping = true;
    Serial.printf("[Lock] Sweeping %u host(s) for the Door Lock cluster (0x0101)\n", _sweepLen);
    _nextSweepOrIdle();
}

bool ZbPing::_startLockScan(uint16_t target, uint16_t pan) {
    _lockTarget  = target;
    _lockPan     = pan;
    _lockFound   = false;
    _lockEpCount = 0;
    _lockEpIndex = 0;

    uint8_t noi[2] = { (uint8_t)(target & 0xFF), (uint8_t)(target >> 8) };
    if (_sendZdoReq(ZB_ZDO_ACTIVE_EP_REQ, target, pan, noi, 2) < 0) {
        Serial.printf("[Lock] TX failed for 0x%04X\n", target);
        _lockPhase = LockScanPhase::IDLE;
        return false;
    }
    _lockPhase     = LockScanPhase::WAIT_ACTIVE_EP;
    _lockSentAt_ms = millis();
    Serial.printf("[Lock] Probing 0x%04X (Active_EP_req)...\n", target);
    return true;
}

void ZbPing::_sendSimpleDescReq(uint8_t endpoint) {
    uint8_t body[3] = { (uint8_t)(_lockTarget & 0xFF), (uint8_t)(_lockTarget >> 8), endpoint };
    _sendZdoReq(ZB_ZDO_SIMPLE_DESC_REQ, _lockTarget, _lockPan, body, 3);
    _lockSentAt_ms = millis();
}

void ZbPing::_finishLockTarget() {
    if (_lockFound)
        Serial.printf("[Lock] *** 0x%04X IS A DOOR LOCK (exposes cluster 0x0101) ***\n",
                      _lockTarget);
    else if (!_lockSweeping)
        Serial.printf("[Lock] 0x%04X: no Door Lock cluster found\n", _lockTarget);
    _lockPhase = LockScanPhase::IDLE;
    _nextSweepOrIdle();
}

void ZbPing::_nextSweepOrIdle() {
    if (!_lockSweeping) return;
    if (_sweepIdx >= _sweepLen) {
        _lockSweeping = false;
        Serial.println("[Lock] Sweep complete");
        return;
    }
    uint16_t next = _sweepQueue[_sweepIdx++];
    _startLockScan(next, _sweepPan);
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

    // find_lock step timeouts
    if (_lockPhase != LockScanPhase::IDLE &&
        (now - _lockSentAt_ms) > LOCK_STEP_TIMEOUT_MS) {
        if (_lockPhase == LockScanPhase::WAIT_ACTIVE_EP) {
            if (!_lockSweeping)
                Serial.printf("[Lock] 0x%04X: no Active_EP response (offline or refused)\n",
                              _lockTarget);
            _lockPhase = LockScanPhase::IDLE;
            _nextSweepOrIdle();
        } else {  // WAIT_SIMPLE_DESC — skip this endpoint, try the next
            if (Verbose)
                Serial.printf("[Lock] 0x%04X ep %u: Simple_Desc timeout\n",
                              _lockTarget,
                              _lockEpIndex < _lockEpCount ? _lockEndpoints[_lockEpIndex] : 0);
            _lockEpIndex++;
            if (_lockEpIndex < _lockEpCount)
                _sendSimpleDescReq(_lockEndpoints[_lockEpIndex]);
            else
                _finishLockTarget();
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

    // Only spend effort decrypting if we're actually waiting on this source —
    // either for a ping response or as part of an in-flight find_lock scan.
    uint16_t src = info.route.nwkSrc;
    PendingPing *p = _findPending(src);
    bool wantLock = (_lockPhase != LockScanPhase::IDLE && src == _lockTarget);
    if (!p && !wantLock) return false;

    if (macPayloadOffset >= rawLen) return false;
    const uint8_t *nwk = rawFrame + macPayloadOffset;
    uint8_t nwkLen = rawLen - macPayloadOffset;

    uint8_t plain[96];
    uint8_t plainLen = 0;
    if (!_nwkDecrypt(nwk, nwkLen, src, plain, plainLen)) {
        if (Verbose)
            Serial.printf("[ZDO] Decrypt failed for response from 0x%04X\n", src);
        return false;
    }

    if (plainLen < 8) return false;
    uint8_t apsFc = plain[0];
    if ((apsFc & 0x03) != 0x00) return false;  // not an APS Data frame
    if ((apsFc >> 5) & 0x01) {
        if (Verbose) Serial.println("[ZDO] Response is APS-secured - not supported");
        return false;
    }

    uint16_t cluster = (uint16_t)plain[2] | ((uint16_t)plain[3] << 8);
    uint16_t profile = (uint16_t)plain[4] | ((uint16_t)plain[5] << 8);
    if (profile != ZB_ZDO_PROFILE_ID) return false;

    const uint8_t *zdo = plain + 8;
    uint8_t zdoLen = plainLen - 8;

    switch (cluster) {
        case ZB_ZDO_NODE_DESC_RSP: {
            if (!p) return false;
            if (zdoLen < 17) return false;  // seq+status+nwkAddr+nodeDesc(13)
            uint32_t rtt = millis() - p->sentAt_ms;
            p->active = false;
            uint8_t status = zdo[1];
            if (status != 0x00) {
                Serial.printf("[Ping] 0x%04X returned ZDO status 0x%02X (no descriptor)\n",
                              src, status);
                return true;
            }
            _reportNodeDesc(src, &zdo[4], rtt);
            return true;
        }
        case ZB_ZDO_ACTIVE_EP_RSP:
            if (!wantLock) return false;
            _handleActiveEpRsp(src, zdo, zdoLen);
            return true;
        case ZB_ZDO_SIMPLE_DESC_RSP:
            if (!wantLock) return false;
            _handleSimpleDescRsp(src, zdo, zdoLen);
            return true;
        default:
            return false;
    }
}

// -- find_lock response handlers ----------------------------------------------

// Active_EP_rsp: seq(1) status(1) nwkAddr(2) epCount(1) endpoints(epCount)
void ZbPing::_handleActiveEpRsp(uint16_t src, const uint8_t *zdo, uint8_t zdoLen) {
    if (_lockPhase != LockScanPhase::WAIT_ACTIVE_EP) return;
    if (zdoLen < 5) return;
    uint8_t status = zdo[1];
    if (status != 0x00) {
        if (!_lockSweeping)
            Serial.printf("[Lock] 0x%04X Active_EP status 0x%02X\n", src, status);
        _finishLockTarget();
        return;
    }
    uint8_t epCount = zdo[4];
    if (epCount == 0 || (5 + epCount) > zdoLen) {
        _finishLockTarget();
        return;
    }
    _lockEpCount = (epCount > MAX_LOCK_ENDPOINTS) ? MAX_LOCK_ENDPOINTS : epCount;
    for (uint8_t i = 0; i < _lockEpCount; i++) _lockEndpoints[i] = zdo[5 + i];
    _lockEpIndex = 0;
    _lockPhase   = LockScanPhase::WAIT_SIMPLE_DESC;
    if (Verbose)
        Serial.printf("[Lock] 0x%04X has %u endpoint(s), reading descriptors\n",
                      src, _lockEpCount);
    _sendSimpleDescReq(_lockEndpoints[0]);
}

// Simple_Desc_rsp: seq(1) status(1) nwkAddr(2) length(1) then the Simple
// Descriptor: endpoint(1) profile(2) device(2) devVer(1) inCount(1)
// inClusters(2*inCount) outCount(1) outClusters(2*outCount)
void ZbPing::_handleSimpleDescRsp(uint16_t src, const uint8_t *zdo, uint8_t zdoLen) {
    if (_lockPhase != LockScanPhase::WAIT_SIMPLE_DESC) return;
    if (zdoLen >= 5 && zdo[1] == 0x00) {
        const uint8_t *d = &zdo[5];
        uint8_t descLen = zdo[4];
        // Need at least endpoint(1)+profile(2)+device(2)+ver(1)+inCount(1) = 7
        if (descLen >= 7 && (5 + descLen) <= zdoLen) {
            uint8_t ep      = d[0];
            uint16_t profId = (uint16_t)d[1] | ((uint16_t)d[2] << 8);
            uint8_t inCount = d[6];
            uint8_t o = 7;
            bool epHasLock = false;
            for (uint8_t i = 0; i < inCount && (o + 1) < descLen; i++, o += 2) {
                uint16_t c = (uint16_t)d[o] | ((uint16_t)d[o + 1] << 8);
                if (c == ZB_CLUSTER_DOOR_LOCK) epHasLock = true;
            }
            if (o < descLen) {
                uint8_t outCount = d[o++];
                for (uint8_t i = 0; i < outCount && (o + 1) < descLen; i++, o += 2) {
                    uint16_t c = (uint16_t)d[o] | ((uint16_t)d[o + 1] << 8);
                    if (c == ZB_CLUSTER_DOOR_LOCK) epHasLock = true;
                }
            }
            if (epHasLock) {
                _lockFound = true;
                Serial.printf("[Lock] 0x%04X ep %u (profile 0x%04X) exposes Door Lock cluster\n",
                              src, ep, profId);
            } else if (Verbose) {
                Serial.printf("[Lock] 0x%04X ep %u: %u input cluster(s), no lock\n",
                              src, ep, inCount);
            }
        }
    }

    _lockEpIndex++;
    if (_lockEpIndex < _lockEpCount)
        _sendSimpleDescReq(_lockEndpoints[_lockEpIndex]);
    else
        _finishLockTarget();
}

void ZbPing::printLockStatus() const {
    switch (_lockPhase) {
        case LockScanPhase::IDLE:
            Serial.println("[Lock] Idle");
            break;
        case LockScanPhase::WAIT_ACTIVE_EP:
            Serial.printf("[Lock] Scanning 0x%04X (waiting for endpoint list)\n", _lockTarget);
            break;
        case LockScanPhase::WAIT_SIMPLE_DESC:
            Serial.printf("[Lock] Scanning 0x%04X (endpoint %u/%u)\n",
                          _lockTarget, _lockEpIndex + 1, _lockEpCount);
            break;
    }
    if (_lockSweeping)
        Serial.printf("[Lock] Sweep in progress (%u/%u)\n", _sweepIdx, _sweepLen);
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
        Serial.printf("[Ping] TX nonce: ");
        for (int i = 0; i < 13; i++) Serial.printf("%02X", nonce[i]);
        Serial.printf(" fc=%08lX secCtrl=%02X\n", _nwkFrameCounter, aux[0]);
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
