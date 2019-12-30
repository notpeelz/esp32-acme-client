#if 0
/*
 * Sample client for the ACME library
 *
 * Copyright (c) 2017, 2018, 2019 Danny Backx
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
#include "Network.h"
#include "Acme.h"

#include <esp_spiffs.h>
#include <esp_wifi.h>
#include <apps/sntp/sntp.h>

static const char *acmeclient_tag = "ACME client";

uint8_t			smac[20];
char			lmac[18];

Config			*config;
Network			*network = 0;
Acme			*acme = 0;
bool			ftp_inited = false;

time_t			nowts, boot_time;

// Initial function
void setup(void) {
  Serial.begin(115200);

  delay(250);

  ESP_LOGI(acmeclient_tag, "ACME client (c) 2017, 2018, 2019 by Danny Backx");
  extern const char *build;
  ESP_LOGI(acmeclient_tag, "Build timestamp %s", build);
  ESP_LOGD(acmeclient_tag, "Free heap : %d", ESP.getFreeHeap());

  /* Network */
  network = new Network();

  /* Print chip information */
  esp_chip_info_t chip_info;
  esp_chip_info(&chip_info);

  ESP_LOGI(acmeclient_tag, "ESP32 chip with %d CPU cores, WiFi%s%s, silicon revision %d",
    chip_info.cores,
    (chip_info.features & CHIP_FEATURE_BT) ? "/BT" : "",
    (chip_info.features & CHIP_FEATURE_BLE) ? "/BLE" : "",
    chip_info.revision);

#if defined(IDF_MAJOR_VERSION)
  ESP_LOGI(acmeclient_tag, "IDF version %s (build v%d.%d)",
      esp_get_idf_version(), IDF_MAJOR_VERSION, IDF_MINOR_VERSION);
#elif defined(IDF_VER)
  ESP_LOGI(acmeclient_tag, "IDF version %s (build %s)", esp_get_idf_version(), IDF_VER);
#else
  ESP_LOGI(acmeclient_tag, "IDF version %s (build version unknown)", esp_get_idf_version());
#endif

  // Set log levels FIXME
  // Make stuff from the underlying libraries quieter
  esp_log_level_set("wifi", ESP_LOG_ERROR);
  esp_log_level_set("system_api", ESP_LOG_ERROR);

  ESP_LOGD(acmeclient_tag, "Starting WiFi "); 
  // First stage, so we can query the MAC
  network->SetupWifi();

  // Get short MAC
  ESP_ERROR_CHECK(esp_wifi_get_mac(ESP_IF_WIFI_STA, smac));

  // Translate into readable format
  String macs = "";
  for (int i=0; i<6; i++) {
    char xx[3];
    sprintf(xx, "%02x", smac[i]);
    macs += xx;
    if (i < 5)
      macs += ":";
  }
  strcpy(lmac, macs.c_str());

  // Pass the MAC to Config
  config = new Config(lmac);

  // Configure file system access
  esp_vfs_spiffs_conf_t scfg;
  scfg.base_path = config->base_path;
  scfg.partition_label = NULL;
  scfg.max_files = 5;
  scfg.format_if_mount_failed = false;
  esp_err_t err = esp_vfs_spiffs_register(&scfg);
  if (err != ESP_OK) {
    ESP_LOGE(acmeclient_tag, "Failed to register SPIFFS %s (%d)", esp_err_to_name(err), err);
  }

  /*
   * Set up the time
   *
   * See https://www.di-mgt.com.au/wclock/help/wclo_tzexplain.html for examples of TZ strings.
   * This one works for Europe : CET-1CEST,M3.5.0/2,M10.5.0/3
   * I assume that this one would work for the US : EST5EDT,M3.2.0/2,M11.1.0
   */
  setenv("TZ", config->GetTimezone(), 1);
  stableTime = new StableTime();

  char *msg = (char *)malloc(180), s[32];
  msg[0] = 0;
  if (config->runAcme()) {
    sprintf(s, " ACME");
    strcat(msg, s);
  }
  if (config->runFtp()) {
    sprintf(s, " FTP");
    strcat(msg, s);
  }

  ESP_LOGI(acmeclient_tag, "My name is %s, have :%s ", config->myName(), msg);
  free(msg);
  msg = 0;

  if (config->runAcme()) {
    acme = new Acme();
  }

  network->WaitForWifi();
  sntp_setoperatingmode(SNTP_OPMODE_POLL);

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

  // Stuff after this only runs when we have NTP time info
  if (config->runFtp() && !ftp_inited) {
    extern void ftp_init();
    ftp_init();
    ftp_inited = true;
  }

  // Record boot time
  if (boot_time == 0) {
    boot_time = nowts;

    char msg[80], ts[24];
    struct tm *tmp = localtime(&boot_time);
    strftime(ts, sizeof(ts), "%Y-%m-%d %T", tmp);
    sprintf(msg, "ACME client %s boot at %s", config->myName(), ts);
  }

  network->loop(nowts);
  acme->loop(nowts);
}

extern "C" {
  int heap() {
    return ESP.getFreeHeap();
  }

  /*
   * Arduino startup code, if you build with ESP-IDF without the startup code enabled.
   */
  void app_main() {
    initArduino();

    Serial.begin(115200);
    Serial.printf("Yow ... starting sketch\n");

    setup();
    while (1)
      loop();
  }
}
#endif
