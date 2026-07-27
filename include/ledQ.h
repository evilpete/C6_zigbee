
#ifndef LEDQ_H_
#define LEDQ_H_

 /*
 * WS2812B LED on GPIO8:
 *   Blue pulsing  - scanning, no packets
 *   Green flash   - Zigbee packet
 *   Purple flash  - Thread / Matter packet
 *   Yellow flash  - unknown 802.15.4
 *   Red solid     - radio error
 */

#include <Adafruit_NeoPixel.h>
#define LED_BRIGHT  40   // 0-255, keep low for power/heat

#define LED_COUNT   1
#define LED_PIN     8

// Colours
#define COL_BLUE    0x000050
#define COL_GREEN   0x005000
#define COL_OFF     0x000000
#define COL_PURPLE  0x3C0050
#define COL_RED     0x500000
#define COL_WHITE   0x282828
#define COL_YELLOW  0x503C00



void led_off();
void ledFlash(uint32_t color, uint16_t duration);


/*
#define COL_OFF     led.Color(0,   0,   0)
#define COL_BLUE    led.Color(0,   0,   80)
#define COL_GREEN   led.Color(0,   80,  0)
#define COL_PURPLE  led.Color(60,  0,   80)
#define COL_YELLOW  led.Color(80,  60,  0)
#define COL_RED     led.Color(80,  0,   0)
#define COL_WHITE   led.Color(40,  40,  40)
*/

#endif   // LEDQ_H_
