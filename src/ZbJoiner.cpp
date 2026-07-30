/*
 * ZbJoiner.cpp — join a Zigbee network as a plain end device
 */

#include "ZbJoiner.h"

extern uint8_t Verbose;

static const uint32_t JOIN_POLL_INTERVAL_MS = 300;
static const uint32_t JOIN_TIMEOUT_MS       = 8000;
static const uint8_t  JOIN_MAX_POLLS        = 30;

ZbJoiner::ZbJoiner(IEEE802154Sniffer &sniffer)
    : _sniffer(sniffer), _phase(JoinPhase::IDLE)
    , _parentShort(0xFFFF), _parentPan(0xFFFF)
    , _assignedShortAddr(0xFFFE)
    , _startTime_ms(0), _lastPoll_ms(0), _pollCount(0)
{}

bool ZbJoiner::start(uint16_t parentShortAddr, uint16_t parentPan,
                      uint8_t capabilityInfo) {
    if (!_sniffer.sendAssociationRequest(parentPan, parentShortAddr, capabilityInfo))
        return false;

    _parentShort        = parentShortAddr;
    _parentPan          = parentPan;
    _assignedShortAddr  = 0xFFFE;
    _startTime_ms       = millis();
    _lastPoll_ms        = _startTime_ms;
    _pollCount          = 0;
    _phase              = JoinPhase::WAIT_ASSOC_RESP;

    Serial.printf("[Join] Association Request sent to 0x%04X (PAN 0x%04X), "
                  "own EUI64=%016llX cap=0x%02X\n",
                  parentShortAddr, parentPan, _sniffer.getOwnEUI64(), capabilityInfo);
    return true;
}

void ZbJoiner::abort() {
    if (_phase == JoinPhase::WAIT_ASSOC_RESP) {
        Serial.println("[Join] Aborted by user");
        _phase = JoinPhase::IDLE;
    }
}

void ZbJoiner::update() {
    if (_phase != JoinPhase::WAIT_ASSOC_RESP) return;

    uint32_t now = millis();
    if ((now - _startTime_ms) > JOIN_TIMEOUT_MS || _pollCount >= JOIN_MAX_POLLS) {
        Serial.printf("[Join] Timed out waiting for Association Response from 0x%04X\n",
                      _parentShort);
        _phase = JoinPhase::FAILED;
        return;
    }

    if ((now - _lastPoll_ms) < JOIN_POLL_INTERVAL_MS) return;
    _lastPoll_ms = now;
    _pollCount++;

    if (Verbose)
        Serial.printf("[Join] Polling parent 0x%04X for pending response (attempt %u)\n",
                      _parentShort, _pollCount);
    _sniffer.sendDataRequest(_parentPan, _parentShort, false);
}

bool ZbJoiner::processFrame(const FrameInfo &info, const uint8_t *rawFrame,
                             uint8_t rawLen, uint8_t macPayloadOffset) {
    if (_phase != JoinPhase::WAIT_ASSOC_RESP) return false;
    if (info.frameType != FC_FRAME_TYPE_MAC_CMD) return false;

    uint8_t cmdId = (macPayloadOffset < rawLen) ? rawFrame[macPayloadOffset] : 0xFF;
    if (cmdId != MAC_CMD_ASSOC_RESPONSE) return false;

    // Association Response addresses us by our extended (EUI64) address —
    // ignore responses meant for some other joining device.
    if (info.dstExtended != _sniffer.getOwnEUI64()) return false;

    uint8_t off = macPayloadOffset;
    if (off + 4 > rawLen) return false;  // cmd(1)+shortAddr(2)+status(1)

    uint16_t shortAddr = (uint16_t)rawFrame[off + 1] | ((uint16_t)rawFrame[off + 2] << 8);
    uint8_t  status    = rawFrame[off + 3];

    if (status == 0x00) {
        _assignedShortAddr = shortAddr;
        _phase = JoinPhase::ASSOCIATED;
        Serial.printf("[Join] *** Associated! Assigned short address 0x%04X via parent 0x%04X ***\n",
                      shortAddr, _parentShort);
        Serial.println("[Join] Waiting for Transport Key (captured automatically if seen) — "
                        "type 'k' to check.");
    } else {
        _phase = JoinPhase::FAILED;
        Serial.printf("[Join] Association rejected by 0x%04X: %s (0x%02X)\n",
                      _parentShort, _statusName(status), status);
    }
    return true;
}

const char *ZbJoiner::_statusName(uint8_t status) {
    switch (status) {
        case 0x00: return "SUCCESS";
        case 0x01: return "PAN_AT_CAPACITY";
        case 0x02: return "PAN_ACCESS_DENIED";
        default:   return "RESERVED";
    }
}

void ZbJoiner::printStatus() const {
    switch (_phase) {
        case JoinPhase::IDLE:
            Serial.println("[Join] Idle — no join attempt in progress");
            break;
        case JoinPhase::WAIT_ASSOC_RESP:
            Serial.printf("[Join] Waiting for response from 0x%04X (%u polls sent)\n",
                          _parentShort, _pollCount);
            break;
        case JoinPhase::ASSOCIATED:
            Serial.printf("[Join] Associated as 0x%04X via parent 0x%04X\n",
                          _assignedShortAddr, _parentShort);
            break;
        case JoinPhase::FAILED:
            Serial.printf("[Join] Last attempt to 0x%04X failed/timed out\n", _parentShort);
            break;
    }
}
