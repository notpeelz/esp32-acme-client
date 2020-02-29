/*
 * DynDNS sample
 *
 * Copyright (c) 2019, 2020 Danny Backx
 *
 * License (MIT license):
 *   Permission is hereby granted, free of charge, to any person obtaining a copy
 *   of this software and associated documentation files (the "Software"), to deal
 *   in the Software without restriction, including without limitation the rights
 *   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 *   copies of the Software, and to permit persons to whom the Software is
 *   furnished to do so, subject to the following conditions:
 *
 *   The above copyright notice and this permission notice shall be included in
 *   all copies or substantial portions of the Software.
 *
 *   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 *   THE SOFTWARE.
 */

#include <Arduino.h>

#include "acmeclient/Dyndns.h"

#include <esp_spiffs.h>
#include <esp_wifi.h>
#include <apps/sntp/sntp.h>

#include "secrets.h"

#include <esp_event_loop.h>
#include <esp_http_server.h>
#include "mqtt_client.h"
#include <freertos/task.h>
#include <sys/socket.h>
#include <dirent.h>

#include "webserver.h"

static const char *dyndnsclient_tag = "DynDNS client";
static const char *network_tag = "Network";

// Forward
void SetupWifi();
void WaitForWifi();
void NoIP();

time_t		nowts, boot_time;
boolean		wifi_up = false;

// Initial function
void setup(void) {
  esp_err_t err;

  ESP_LOGI(dyndnsclient_tag, "%s (c) 2019, 2020 by Danny Backx", dyndnsclient_tag);

  // Make stuff from the underlying libraries quieter
  esp_log_level_set("wifi", ESP_LOG_ERROR);
  esp_log_level_set("system_api", ESP_LOG_ERROR);

  ESP_LOGD(dyndnsclient_tag, "Starting WiFi "); 
  SetupWifi();

  WaitForWifi();
  ESP_LOGD(dyndnsclient_tag, "... end of setup()");
}

void loop()
{
  delay(2500);
}

extern "C" {
  /*
   * Arduino startup code, if you build with ESP-IDF without the startup code enabled.
   */
  void app_main() {
    initArduino();

    Serial.begin(115200);
    setup();
    while (1)
      loop();
  }
}

// Put your WiFi credentials in "secrets.h", see the sample file.
struct mywifi {
  const char *ssid, *pass, *bssid;
} mywifi[] = {
#ifdef MY_SSID_1
  { MY_SSID_1, MY_WIFI_PASSWORD_1, MY_WIFI_BSSID_1 },
#endif
#ifdef MY_SSID_2
  { MY_SSID_2, MY_WIFI_PASSWORD_2, MY_WIFI_BSSID_2 },
#endif
#ifdef MY_SSID_3
  { MY_SSID_3, MY_WIFI_PASSWORD_3, MY_WIFI_BSSID_3 },
#endif
#ifdef MY_SSID_4
  { MY_SSID_4, MY_WIFI_PASSWORD_4, MY_WIFI_BSSID_4 },
#endif
  { NULL, NULL, NULL}
};

static esp_err_t wifi_event_handler(void *ctx, system_event_t *event) {
  switch (event->event_id) {
    case SYSTEM_EVENT_STA_START:
      esp_wifi_connect();
      break;

    case SYSTEM_EVENT_GOT_IP6:
      ESP_LOGI(network_tag, "We have an IPv6 address");
      // FIXME
      break;

    case SYSTEM_EVENT_STA_GOT_IP:
      ESP_LOGI(network_tag, "SYSTEM_EVENT_STA_GOT_IP");
      wifi_up = true;

      sntp_init();
#ifdef	NTP_SERVER_0
      sntp_setservername(0, (char *)NTP_SERVER_0);
#endif
#ifdef	NTP_SERVER_1
      sntp_setservername(1, (char *)NTP_SERVER_1);
#endif

      NoIP();
      break;

    case SYSTEM_EVENT_STA_DISCONNECTED:
      wifi_up = false;
      delay(1000);
      esp_wifi_connect();
      // Uh oh
      break;

    default:
      break;
  }
  return ESP_OK;
}

/*
 * This needs to be done before we can query the adapter MAC,
 * which we need to pass to Config.
 * After this, we can also await attachment to a network.
 */
void SetupWifi(void)
{
  esp_err_t err;

  tcpip_adapter_init();
  err = esp_event_loop_init(wifi_event_handler, NULL);
  if (err != ESP_OK) {
      /*
       * ESP_FAIL here means we've already done this, see components/esp32/event_loop.c :
       * esp_err_t esp_event_loop_init(system_event_cb_t cb, void *ctx)
       * {
       *     if (s_event_init_flag) {
       *         return ESP_FAIL;
       *     }
       */
  }
  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  err = esp_wifi_init(&cfg);
  if (err != ESP_OK) {
      ESP_LOGE(network_tag, "Failed esp_wifi_init, reason %d", (int)err);
      // FIXME
      return;
  }
  err = esp_wifi_set_storage(WIFI_STORAGE_RAM);
  if (err != ESP_OK) {
      ESP_LOGE(network_tag, "Failed esp_wifi_set_storage, reason %d", (int)err);
      // FIXME
      return;
  }
}

void WaitForWifi(void)
{
  ESP_LOGD(network_tag, "Waiting for wifi");
 
  wifi_config_t wifi_config;
  for (int ix = 0; mywifi[ix].ssid != 0; ix++) {
    memset(&wifi_config, 0, sizeof(wifi_config));
    strcpy((char *)wifi_config.sta.ssid, mywifi[ix].ssid);
    strcpy((char *)wifi_config.sta.password, mywifi[ix].pass);
    if (mywifi[ix].bssid) {
      int r = sscanf(mywifi[ix].bssid, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx", 
        &wifi_config.sta.bssid[0],
        &wifi_config.sta.bssid[1],
        &wifi_config.sta.bssid[2],
        &wifi_config.sta.bssid[3],
        &wifi_config.sta.bssid[4],
        &wifi_config.sta.bssid[5]);
      wifi_config.sta.bssid_set = true;
      if (r != 6) {
	ESP_LOGE(network_tag, "Could not convert MAC %s into acceptable format", mywifi[ix].bssid);
	memset(wifi_config.sta.bssid, 0, sizeof(wifi_config.sta.bssid));
	wifi_config.sta.bssid_set = false;
      }
    } else
      memset(wifi_config.sta.bssid, 0, sizeof(wifi_config.sta.bssid));

    esp_err_t err = esp_wifi_set_mode(WIFI_MODE_STA);
    if (err != ESP_OK) {
      ESP_LOGE(network_tag, "Failed to set wifi mode to STA");
      // FIXME
      return;
    }
    err = esp_wifi_set_config(ESP_IF_WIFI_STA, &wifi_config);
    if (err != ESP_OK) {
      ESP_LOGE(network_tag, "Failed to set wifi config");
      // FIXME
      return;
    }
    ESP_LOGI(network_tag, "Try wifi ssid [%s]", wifi_config.sta.ssid);
    err = esp_wifi_start();
    if (err != ESP_OK) {
      ESP_LOGE(network_tag, "Failed to start wifi");
      // FIXME
      return;
    }

    for (int cnt = 0; cnt < 40; cnt++) {
      delay(100);
      if (wifi_up) {
        ESP_LOGI(network_tag, ".. connected to wifi (attempt %d)", cnt+1);
        return;
      }
    }
  }
}

void NoIP() {
  ESP_LOGI(dyndnsclient_tag, "Registering with cloudns.net ... ");
  Dyndns *d = new Dyndns(DD_CLOUDNS);

  d->setHostname(DD_CLOUDNS_MY_URL);

  // Choose between valid and invalid auth
  d->setAuth(DD_CLOUDNS_VALID_AUTH);
  // d->setAuth(DD_CLOUDNS_INVALID_AUTH);

  if (d->update())
    ESP_LOGI(dyndnsclient_tag, "succeeded");
  else
    ESP_LOGE(dyndnsclient_tag, "failed");
}
