#include <Arduino.h>
#include "esp32-hal-ledc.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"

#include "ledQ.h"

static TaskHandle_t _ledq_task = NULL;
static QueueHandle_t _ledq_queue = NULL;

Adafruit_NeoPixel led(LED_COUNT, LED_PIN, NEO_GRB + NEO_KHZ800);

#ifndef LEDQ_PRIORITY
  #define LEDQ_PRIORITY 8
#endif

typedef enum {
  LED_ON,
  LED_OFF
} ledq_cmd_t;

typedef struct {
  ledq_cmd_t ledq_cmd;
  uint32_t color;
  uint16_t duration;
} ledq_msg_t;

static uint32_t _flashColor    = 0;
static uint32_t _flashUntil    = 0;
static uint32_t _pulseLastMs   = 0;
static uint8_t  _pulseBright   = 0;
static int8_t   _pulseDir      = 1;

static void ledq_task(void *) {
  ledq_msg_t ledq_msg;
  while (1) {
    // xQueueReceive(_ledq_queue, &ledq_msg, portMAX_DELAY);
    BaseType_t got = xQueueReceive(_ledq_queue, &ledq_msg, pdMS_TO_TICKS(20));

    // Serial.printf("%d Task received from queue LED_ON: color=%u Hz, duration=%lu ms\n", got, ledq_msg.color, ledq_msg.duration);
    if (got) 
     switch (ledq_msg.ledq_cmd) {
      case LED_ON:
        // log_d("Task received from queue LED_ON: color=%u Hz, duration=%lu ms", ledq_msg.color, ledq_msg.duration);

        led.setBrightness(LED_BRIGHT * 3);
        led.setPixelColor(0, ledq_msg.color);
        led.show();

        if (ledq_msg.duration) {
          delay(ledq_msg.duration);
          led.setPixelColor(0, COL_OFF);
          led.show();
        }
        continue;
        //break;

      case LED_OFF:
        // log_d("Task received from queue LED_OFF");
        led.setPixelColor(0, COL_OFF);
        led.show();
        continue;
        //break;

      default:;  // do nothing
    }  // switch

    // Blue pulse when idle (no flash pending)
    uint32_t now = millis();
    if (now - _pulseLastMs > 20) {
        // Serial.println("Blue pulse");
        _pulseLastMs = now;
        _pulseBright += _pulseDir * 3;
        if (_pulseBright >= 60)  { _pulseBright = 60;  _pulseDir = -1; }
        if (_pulseBright == 0)   { _pulseBright = 0;   _pulseDir =  1; }
        led.setBrightness(LED_BRIGHT);
        led.setPixelColor(0, led.Color(0, 0, _pulseBright));
        led.show();
    }
    delay(4);   // sleep a little

  }  // infinite loop
}


static bool _ledq_initialised = false;

int ledq_init() {
    if (_ledq_initialised) return 1;  // ← already done, skip
    _ledq_initialised = true;

    Serial.println("led.begin");
    led.begin();
    led.setBrightness(LED_BRIGHT);
    led.clear();
    led.show();


    if (_ledq_queue == NULL) {
        _ledq_queue = xQueueCreate(128, sizeof(ledq_msg_t));
        if (_ledq_queue == NULL) {
            log_e("Could not create led queue");
            _ledq_initialised = false;  // allow retry
            return 0;
        }
    }

    if (_ledq_task == NULL) {
        xTaskCreate(ledq_task, "ledqTask", 3500, NULL, LEDQ_PRIORITY, &_ledq_task);
        if (_ledq_task == NULL) {
            log_e("Could not create ledq task");
            _ledq_initialised = false;  // allow retry
            return 0;
        }
    }
    return 1;
}

void led_off() {
  Serial.println("led_off called");
  log_d("led_off called");
  if (ledq_init()) {
    ledq_msg_t ledq_msg = {
      .ledq_cmd = LED_OFF,
      .color = 0,  // Ignored
      .duration = 0,   // Ignored
    };
    xQueueReset(_ledq_queue);  // clear queue
    xQueueSend(_ledq_queue, &ledq_msg, portMAX_DELAY);
  } else {
    log_e("LED Task not running"); // Delete this later
  }
}

// parameters:
// color - Neo color
// duration - time in ms - how long the led color will be outputted.
//   If not provided, or 0 you must manually call led_off to end output
void ledFlash(uint32_t color, uint16_t duration = 80) {
  // log_d("color=%X, duration=%u ms", color, duration);
  // Serial.printf("ledFlash 0x%X %d\n", color, duration);
    if (ledq_init()) {
      ledq_msg_t ledq_msg = {
        .ledq_cmd = LED_ON,
        .color = color,
        .duration = duration,
      };
      xQueueSend(_ledq_queue, &ledq_msg, portMAX_DELAY);
      return;
  } else {
    log_e("LED Task not running"); // Delete this later
  }
}



