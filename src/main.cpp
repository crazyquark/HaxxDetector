/*      __  __                ____       __            __
 *     / / / /___ __  ___  __/ __ \___  / /____  _____/ /_____  _____
 *    / /_/ / __ `/ |/_/ |/_/ / / / _ \/ __/ _ \/ ___/ __/ __ \/ ___/
 *   / __  / /_/ />  <_>  </ /_/ /  __/ /_/  __/ /__/ /_/ /_/ / /
 *  /_/ /_/\__,_/_/|_/_/|_/_____/\___/\__/\___/\___/\__/\____/_/
 *
 *  A simple deauth + dissassociation attack detector written for the WiFi Nugget
 *  github.com/crazyquark/HaxxDetector
 *
 *  By Alex Lynd | alexlynd.com
 *
 *  Hacked modestly by @crazyquark
 *  to run on any ESP8266 device with an OLED screen.
 */

#include <Arduino.h>
#include <WiFi.h>
#include <SSD1306.h>
#include <OLEDDisplayUi.h>

#include "esp_wifi.h"
#include "esp_wifi_types.h"

#include "nuggs.h" // Nugget Face bitmap files
// Initialize the OLED display using SPI
// GPIO5 -> SDA
// GPIO4 -> SCL
SSD1306 display(0x3c, 5, 4);
OLEDDisplayUi ui(&display);

const short channels[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13}; // Max: US 11, EU 13, JAP 14

int ch_index{0};
int packet_rate{0};
int attack_counter{0};
unsigned long update_time{0};
unsigned long ch_time{0};

void sniffer(void *buf, wifi_promiscuous_pkt_type_t type)
{
  wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
  wifi_pkt_rx_ctrl_t ctrl = (wifi_pkt_rx_ctrl_t)pkt->rx_ctrl;

  if (type == WIFI_PKT_MGMT && (pkt->payload[0] == 0xA0 || pkt->payload[0] == 0xC0))
    ++packet_rate;
}

void displayDeadNugg()
{
  display.clear();
  display.drawXbm(0, 0, alive_nugg_width, alive_nugg_height, dead_nugg);
  display.display();
}

void displayAliveNugg()
{
  display.clear();
  display.drawXbm(0, 0, alive_nugg_width, alive_nugg_height, alive_nugg);
  display.display();
}

void attack_started()
{
  // pixels.setPixelColor(0, pixels.Color(150, 0, 0));
  // pixels.show(); // red
  displayDeadNugg();
}

void attack_stopped()
{
  // pixels.setPixelColor(0, pixels.Color(0, 150, 0));
  // pixels.show(); // green
  displayAliveNugg();
}

void setup()
{
  ui.setTargetFPS(60);
  ui.init(); // initialize OLED screen

  // initalize WiFi card for scanning
  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  esp_wifi_init(&cfg);
  esp_wifi_set_storage(WIFI_STORAGE_RAM);
  esp_wifi_set_mode(WIFI_MODE_NULL);
  esp_wifi_start();
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(&sniffer);
  esp_wifi_set_channel(1, WIFI_SECOND_CHAN_NONE);

  Serial.begin(9600);

  Serial.println();
  Serial.println("   __ __                ___      __          __          ");
  Serial.println("  / // /__ ___ ____ __ / _ \\___ / /____ ____/ /____  ____");
  Serial.println(" / _  / _ `/\\ \\ /\\ \\ // // / -_) __/ -_) __/ __/ _ \/ __/");
  Serial.println("/_//_/\_,_//_\\_\\/_\\_\\/____/\\__/\\__/\\__/\\__/\\__/\\___/_/  ");
  Serial.println("\ngithub.com/HakCat-Tech/HaxxDetector");
  Serial.println("A WiFi Nugget sketch by Alex Lynd");

  display.clear();
  display.flipScreenVertically();
  // pixels.setPixelColor(0, pixels.Color(0, 150, 0));
  // pixels.show();
  displayAliveNugg();
}

void loop()
{
  unsigned long current_time = millis();

  if (current_time - update_time >= (sizeof(channels) * 100))
  {
    update_time = current_time;

    if (packet_rate >= 1)
    {
      ++attack_counter;
    }
    else
    {
      if (attack_counter >= 1)
        attack_stopped();
      attack_counter = 0;
    }

    if (attack_counter == 1)
    {
      attack_started();
    }
    packet_rate = 0;
  }

  // Channel hopping
  if (sizeof(channels) > 1 && current_time - ch_time >= 100)
  {
    ch_time = current_time; // Update time variable
    ch_index = (ch_index + 1) % (sizeof(channels) / sizeof(channels[0]));
    short ch = channels[ch_index];
    esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
  }
}
