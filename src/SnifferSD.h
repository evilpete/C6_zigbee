/*
 * SnifferSD.h - SD card support for IEEE802154 Sniffer
 * Waveshare ESP32-C6-LCD-1.47 pin assignments:
 *   MISO = GPIO5, MOSI = GPIO6, SCLK = GPIO7, CS = GPIO4
 *   (MOSI/SCLK shared with LCD - LCD CS kept high since display unused)
 *
 * Saves:
 *   /capture.pcap   - raw 802.15.4 frames (Wireshark LINKTYPE_IEEE802_15_4)
 *   /hosts.json     - host list with labels, RSSI, frame counts, device type
 *   /keys.json      - Zigbee keys (TCLK + any captured network keys)
 */

#pragma once
#include <Arduino.h>
#include <SPI.h>
#include <SD.h>
#include "IEEE802154Sniffer.h"

// -- Pin definitions -----------------------------------------------------------
#define SD_MISO_PIN     5
#define SD_MOSI_PIN     6
#define SD_SCLK_PIN     7
#define SD_CS_PIN       4

class SnifferSD {
public:
    SnifferSD() : _mounted(false), _pcapFile(), _pcapOpen(false) {}

    // Mount SD card - call once in setup() after SPI.begin()
    bool begin() {
        SPI.begin(SD_SCLK_PIN, SD_MISO_PIN, SD_MOSI_PIN, SD_CS_PIN);
        if (!SD.begin(SD_CS_PIN)) {
            Serial.println("[SD] Mount failed - check card");
            return false;
        }
        _mounted = true;
        uint64_t mb = SD.cardSize() / (1024 * 1024);
        Serial.printf("[SD] Mounted - %lluMB  free: %lluMB\n",
                      mb, (SD.totalBytes() - SD.usedBytes()) / (1024 * 1024));
        return true;
    }

    bool isMounted() const { return _mounted; }

    // -- PCap ------------------------------------------------------------------
    // Opens /capture.pcap and hooks it into the sniffer's pcap stream
    // Appends if file exists, creates new if not
    bool startPcap(IEEE802154Sniffer &sniffer, const char *path = "/capture.pcap") {
        if (!_mounted) return false;
        _pcapFile = SD.open(path, FILE_APPEND);
        if (!_pcapFile) {
            Serial.printf("[SD] Cannot open %s\n", path);
            return false;
        }
        _pcapOpen = true;
        sniffer.startPcap(&_pcapFile);
        Serial.printf("[SD] PCap → %s\n", path);
        return true;
    }

    void stopPcap(IEEE802154Sniffer &sniffer) {
        sniffer.stopPcap();
        if (_pcapOpen) {
            _pcapFile.flush();
            _pcapFile.close();
            _pcapOpen = false;
            Serial.println("[SD] PCap closed");
        }
    }

    bool isPcapOpen() const { return _pcapOpen; }

    // -- hosts.json ------------------------------------------------------------
    bool saveHosts(IEEE802154Sniffer &sniffer,
                   const char *path = "/hosts.json") {
        if (!_mounted) return false;
        File f = SD.open(path, FILE_WRITE);
        if (!f) { Serial.printf("[SD] Cannot write %s\n", path); return false; }

        f.println("[");
        for (int i = 0; i < sniffer.hosts.size(); i++) {
            HostRecord *h = sniffer.hosts.get(i);
            if (!h->frameCount) continue;

            const char *dtype =
                h->deviceType == DeviceType::COORDINATOR ? "coordinator" :
                h->deviceType == DeviceType::ROUTER      ? "router"      :
                h->deviceType == DeviceType::END_DEVICE  ? "end_device"  : "unknown";

            const char *proto =
                h->protocol == FrameProtocol::ZIGBEE ? "zigbee" :
                h->protocol == FrameProtocol::THREAD ? "thread" : "802154";

            f.printf("  {\"addr\":\"0x%04X\",\"label\":\"%s\","
                     "\"type\":\"%s\",\"protocol\":\"%s\","
                     "\"frames\":%lu,\"tx\":%lu,\"rx\":%lu,"
                     "\"rssi_last\":%d,\"rssi_min\":%d,\"rssi_max\":%d,"
                     "\"lqi\":%u,\"channel\":%u,"
                     "\"first_seen\":%lu,\"last_seen\":%lu",
                h->shortAddr, h->label[0] ? h->label : "",
                dtype, proto,
                h->frameCount, h->txCount, h->rxCount,
                h->rssiLast, h->rssiMin, h->rssiMax,
                h->lqiLast, h->channel,
                h->firstSeen_ms, h->lastSeen_ms);

            if (h->avgPollInterval_ms > 0)
                f.printf(",\"poll_interval_ms\":%lu", h->avgPollInterval_ms);
            if (h->retryCount > 0)
                f.printf(",\"retries\":%lu", h->retryCount);
            if (h->seqGaps > 0)
                f.printf(",\"seq_gaps\":%u", h->seqGaps);

            // connected hosts
            if (h->connected_hosts.size() > 0) {
                f.print(",\"connected\":[");
                for (int j = 0; j < h->connected_hosts.size(); j++) {
                    f.printf("\"0x%04X\"%s",
                             h->connected_hosts.get(j),
                             j < h->connected_hosts.size()-1 ? "," : "");
                }
                f.print("]");
            }

            bool last = (i == sniffer.hosts.size() - 1);
            f.println(last ? "\n  }" : "\n  },");
        }
        f.println("]");
        f.flush();
        f.close();
        Serial.printf("[SD] Saved %s (%d hosts)\n", path, sniffer.hosts.size());
        return true;
    }

    // -- keys.json -------------------------------------------------------------
    bool saveKeys(IEEE802154Sniffer &sniffer,
                  const char *path = "/keys.json") {
        if (!_mounted) return false;
        File f = SD.open(path, FILE_WRITE);
        if (!f) { Serial.printf("[SD] Cannot write %s\n", path); return false; }

        f.println("[");
        for (int i = 0; i < sniffer.keys.size(); i++) {
            ZbKey *k = sniffer.keys.get(i);
            const char *tname =
                k->type == ZbKeyType::NETWORK           ? "network"    :
                k->type == ZbKeyType::TRUST_CENTER_LINK ? "tclk"       : "app";

            f.printf("  {\"type\":\"%s\",\"seq\":%u,\"label\":\"%s\","
                     "\"captured_ms\":%lu,\"key\":\"",
                     tname, k->seqNum, k->label, k->capturedAt_ms);

            for (int j = 0; j < ZIGBEE_KEY_LEN; j++)
                f.printf("%02X%s", k->key[j], j < ZIGBEE_KEY_LEN-1 ? ":" : "");

            bool last = (i == sniffer.keys.size() - 1);
            f.println(last ? "\"}" : "\"},");
        }
        f.println("]");
        f.flush();
        f.close();
        Serial.printf("[SD] Saved %s (%d keys)\n", path, sniffer.keys.size());
        return true;
    }

    // -- Load labels from SD /labels.csv ---------------------------------------
    bool loadLabels(IEEE802154Sniffer &sniffer,
                    const char *path = "/labels.csv") {
        if (!_mounted) return false;
        File f = SD.open(path, FILE_READ);
        if (!f) {
            Serial.printf("[SD] No %s found\n", path);
            return false;
        }
        String csv = f.readString();
        f.close();
        sniffer.loadLabels(csv.c_str());
        Serial.printf("[SD] Loaded labels from %s\n", path);
        return true;
    }

    // -- List SD files ---------------------------------------------------------
    void listFiles(const char *dir = "/") {
        File root = SD.open(dir);
        if (!root) return;
        Serial.println("[SD] Files:");
        File f = root.openNextFile();
        while (f) {
            Serial.printf("  %-30s %8lu bytes\n", f.name(), f.size());
            f = root.openNextFile();
        }
    }

private:
    bool _mounted;
    File _pcapFile;
    bool _pcapOpen;
};
