/*
 * Sample client for the ACME library
 *
 * Copyright (c) 2019, 2020 Danny Backx
 *
 * License (GNU Lesser General Public License) :
 *
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU Lesser General Public
 *   License as published by the Free Software Foundation; either
 *   version 3 of the License, or (at your option) any later version.
 *
 *   This library is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *   Lesser General Public License for more details.
 *
 *   You should have received a copy of the GNU Lesser General Public
 *   License along with this library; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <Arduino.h>
#include "Config.h"
#include "StableTime.h"
#include "Acme.h"

#include <esp_spiffs.h>
#include <esp_wifi.h>
#include <apps/sntp/sntp.h>

#include "secrets.h"

#include <esp_event_loop.h>
#include "mqtt_client.h"
#include <freertos/task.h>
#include <sys/socket.h>

static const char *acmeclient_tag = "ACME client";
static const char *network_tag = "Network";

// Forward
void SetupWifi();
void WaitForWifi();

Acme		*acme = 0;
time_t		nowts, boot_time;
boolean		wifi_up = false;

// Initial function
void setup(void) {
  esp_err_t err;

  ESP_LOGI(acmeclient_tag, "ACME client (c) 2019, 2020 by Danny Backx");

  // Make stuff from the underlying libraries quieter
  esp_log_level_set("wifi", ESP_LOG_ERROR);
  esp_log_level_set("system_api", ESP_LOG_ERROR);

  ESP_LOGD(acmeclient_tag, "Starting WiFi "); 
  SetupWifi();

  // Configure file system access
  esp_vfs_spiffs_conf_t scfg;
  scfg.base_path = "/spiffs";
  scfg.partition_label = NULL;
  scfg.max_files = 10;
  scfg.format_if_mount_failed = false;
  if ((err = esp_vfs_spiffs_register(&scfg)) != ESP_OK) {
    ESP_LOGE(acmeclient_tag, "Failed to register SPIFFS %s (%d)", esp_err_to_name(err), err);
  }

  /*
   * Set up the time
   *
   * See https://www.di-mgt.com.au/wclock/help/wclo_tzexplain.html for examples of TZ strings.
   * This one works for Europe : CET-1CEST,M3.5.0/2,M10.5.0/3
   * I assume that this one would work for the US : EST5EDT,M3.2.0/2,M11.1.0
   */
  sntp_setoperatingmode(SNTP_OPMODE_POLL);
  setenv("TZ", "CET-1CEST,M3.5.0/2,M10.5.0/3", 1);
  stableTime = new StableTime();

  acme = new Acme();
  acme->setFilenamePrefix("/spiffs");
  acme->setUrl(SECRET_URL);
  acme->setEmail(SECRET_EMAIL);

  acme->setFtpServer(SECRET_FTP_SERVER);
  acme->setFtpPath(SECRET_FTP_PATH);
  acme->setFtpUser(SECRET_FTP_USER);
  acme->setFtpPassword(SECRET_FTP_PASS);

  // Watch out before you try this with the production server, it has rate limits, not suitable for debugging.
  // acme->setAcmeServer("https://acme-v02.api.letsencrypt.org/directory");		// Production server
  acme->setAcmeServer("https://acme-staging-v02.api.letsencrypt.org/directory");	// Staging server

  acme->setAccountFilename("account.json");
  acme->setOrderFilename("order.json");
  acme->setAccountKeyFilename("account.pem");
  acme->setCertKeyFilename("certkey.pem");
  acme->setCertificateFilename("certificate.pem");

  if (acme->getAccountKey() == 0) {
    acme->GenerateAccountKey();
  }
  if (acme->getCertificateKey() == 0) {
    acme->GenerateCertificateKey();
  }

  WaitForWifi();

  acme->CreateNewAccount();
  acme->CreateNewOrder();

  ESP_LOGD(acmeclient_tag, "... end of setup()");
}

void loop()
{
  struct timeval tv;
  gettimeofday(&tv, 0);
  stableTime->loop(&tv);

  if (! stableTime->timeIsValid())
    return;
  nowts = tv.tv_sec;

  // Record boot time
  if (boot_time == 0) {
    boot_time = nowts;

    char msg[80], ts[24];
    struct tm *tmp = localtime(&boot_time);
    strftime(ts, sizeof(ts), "%Y-%m-%d %T", tmp);
    sprintf(msg, "ACME client boot at %s", ts);
  }

  acme->loop(nowts);
  delay(2500);

  {
    static int nrenews = 0;

    if (nrenews == 1 && boot_time > 35000) {
      nrenews--;
      ESP_LOGI(acmeclient_tag, "Renewing certificate from simple.cpp");
      acme->RenewCertificate();
    }
  }
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

      if (acme) acme->NetworkConnected(ctx, event);

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

    for (int cnt = 0; cnt < 20; cnt++) {
      delay(100);
      if (wifi_up) {
        ESP_LOGI(network_tag, ".. connected to wifi (attempt %d)", cnt+1);
        return;
      }
    }
  }
}
