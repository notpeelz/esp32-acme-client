/*
 * This module manages unexpected disconnects (and recovery) from the network.
 *
 * Copyright (c) 2019 Danny Backx
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

#include "secrets.h"
#include "Config.h"
#include "StableTime.h"
#include "Acme.h"
#include "Network.h"

#include <esp_wifi.h>
#include <esp_event_loop.h>
#include "mqtt_client.h"
#include <freertos/task.h>
#include <sys/socket.h>
#include <apps/sntp/sntp.h>

Network::Network() {
  // FIXME get from config
  reconnect_interval = 30;

  status = NS_NONE;
  restart_time = 0;
}

// Not really needed
Network::~Network() {
}

struct mywifi {
  const char *ssid, *pass, *bssid;
} mywifi[] = {
#ifdef MY_SSID_1
# ifdef MY_WIFI_BSSID_1
  { MY_SSID_1, MY_WIFI_PASSWORD_1, MY_WIFI_BSSID_1 },
# else
  { MY_SSID_1, MY_WIFI_PASSWORD_1, NULL },
# endif
#endif
#ifdef MY_SSID_2
# ifdef MY_WIFI_BSSID_2
  { MY_SSID_2, MY_WIFI_PASSWORD_2, MY_WIFI_BSSID_2 },
# else
  { MY_SSID_2, MY_WIFI_PASSWORD_2, NULL },
# endif
#endif
#ifdef MY_SSID_3
# ifdef MY_WIFI_BSSID_3
  { MY_SSID_3, MY_WIFI_PASSWORD_3, MY_WIFI_BSSID_3 },
# else
  { MY_SSID_3, MY_WIFI_PASSWORD_3, NULL },
# endif
#endif
#ifdef MY_SSID_4
# ifdef MY_WIFI_BSSID_4
  { MY_SSID_4, MY_WIFI_PASSWORD_4, MY_WIFI_BSSID_4 },
# else
  { MY_SSID_4, MY_WIFI_PASSWORD_4, NULL },
# endif
#endif
  { NULL, NULL, NULL}
};

const char *snetwork_tag = "Network static";

static esp_err_t wifi_event_handler(void *ctx, system_event_t *event) {
  switch (event->event_id) {
    case SYSTEM_EVENT_STA_START:
      esp_wifi_connect();
      break;

    case SYSTEM_EVENT_GOT_IP6:
      ESP_LOGI(snetwork_tag, "We have an IPv6 address");
      // FIXME
      break;

    case SYSTEM_EVENT_STA_GOT_IP:
      ESP_LOGI(snetwork_tag, "SYSTEM_EVENT_STA_GOT_IP");

      network->setWifiOk(true);
      sntp_init();
#ifdef	NTP_SERVER_0
      sntp_setservername(0, (char *)NTP_SERVER_0);
#endif
#ifdef	NTP_SERVER_1
      sntp_setservername(1, (char *)NTP_SERVER_1);
#endif

      if (network) network->NetworkConnected(ctx, event);
      if (acme) acme->NetworkConnected(ctx, event);

      break;

    case SYSTEM_EVENT_STA_DISCONNECTED:
      ESP_LOGE(snetwork_tag, "STA_DISCONNECTED, restarting");

      if (acme) acme->NetworkDisconnected(ctx, event);
      if (network) network->NetworkDisconnected(ctx, event);

      network->StopWifi();			// This also schedules a restart
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
void Network::SetupWifi(void)
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
      // ESP_LOGE(network_tag, "Failed esp_event_loop_init, reason %d", (int)err);

      // esp_restart();
      // return;
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

  status = NS_SETUP_DONE;
}

void Network::WaitForWifi(void)
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

    if (status == NS_SETUP_DONE) {
      for (int cnt = 0; cnt < 20; cnt++) {
        delay(100);
	ESP_LOGI(network_tag, ".. connected to wifi (attempt %d)", cnt+1);
	status = NS_CONNECTING;
        return;
      }
    } else {
	ESP_LOGE(network_tag, "Invalid status %d, expected %d", status, NS_SETUP_DONE);
    }
  }
}

// Flag the connection as ok
void Network::setWifiOk(boolean ok) {
  wifi_ok = ok;
  status = NS_RUNNING;
}

void Network::StopWifi() {
  esp_err_t err;

  ESP_LOGI(network_tag, "StopWifi");

  err = esp_wifi_disconnect();
  if (err != ESP_OK)
    ESP_LOGE(network_tag, "%s: esp_wifi_disconnect failed, reason %d (%s)", __FUNCTION__,
      err, esp_err_to_name(err));
  err = esp_wifi_stop();
  if (err != ESP_OK)
    ESP_LOGE(network_tag, "%s: esp_wifi_stop failed, reason %d (%s)", __FUNCTION__,
      err, esp_err_to_name(err));
  err = esp_wifi_deinit();
  if (err != ESP_OK)
    ESP_LOGE(network_tag, "%s: esp_wifi_deinit failed, reason %d (%s)", __FUNCTION__,
      err, esp_err_to_name(err));

  // ScheduleRestartWifi();
}

/*
 * This function is called when we see a problem.
 */
void Network::disconnected(const char *fn, int line) {
    ESP_LOGE(network_tag, "Network::disconnected (caller: %s line %d)", fn, line);
}

void Network::eventDisconnected(const char *fn, int line) {
    ESP_LOGE(network_tag, "Disconnect event (caller: %s line %d)", fn, line);
}

static esp_err_t mqtt_event_handler(esp_mqtt_event_handle_t event);
esp_mqtt_client_config_t mqtt_config;
esp_mqtt_client_handle_t mqtt;
#define MQTT_URI	"mqtt://192.168.0.251"

void Network::NetworkConnected(void *ctx, system_event_t *event) {
  ESP_LOGD(network_tag, "Initializing MQTT");
  memset(&mqtt_config, 0, sizeof(mqtt_config));
  mqtt_config.uri = MQTT_URI;
  mqtt_config.event_handle = mqtt_event_handler;

  // Note Tuan's MQTT component starts a separate task for event handling
  mqtt = esp_mqtt_client_init(&mqtt_config);
  esp_err_t err = esp_mqtt_client_start(mqtt);

  if (err == ESP_OK)
    ESP_LOGD(network_tag, "MQTT Client Start ok");
  else
    ESP_LOGE(network_tag, "MQTT Client Start failure : %d", err);

}

void Network::NetworkDisconnected(void *ctx, system_event_t *event) {
}


/*
 * Check whether the broadcast at startup to find peers was succesfull.
 */
void Network::loop(time_t now) {
  // NoPeerLoop(now);
  // LoopRestartWifi(now);
}

bool Network::isConnected() {
  return (status == NS_RUNNING);
}

void Network::GotDisconnected(const char *fn, int line) {
  ESP_LOGE(network_tag, "Network is not connected (caller: %s line %d)", fn, line);
  status = NS_NONE;
}

static void HandleMqtt(char *topic, char *message) {
  ESP_LOGI(snetwork_tag, "MQTT topic %s message %s", topic, message);

  if (strcmp(message, "remove") == 0 || message[0] == '0') {
    if (message[0] == '0' && message[1] == ' ' && message[2] != 0)
      acme->OrderRemove(message+2);
    else
      acme->OrderRemove("");
  } else if (strcmp(message, "start") == 0 || message[0] == '1')
    acme->OrderStart();
  else if (strcmp(message, "challenge") == 0 || message[0] == '2')
    acme->ChallengeStart();
  else if (strcmp(message, "certificate") == 0 || message[0] == '3')
    acme->CertificateDownload();
  else if (strcmp(message, "dir") == 0 || strcmp(message, "list") == 0) {
    acme->ListFiles();
  } else if (strcmp(message, "order") == 0) {
    acme->setCertificate("https://acme-staging-v02.api.letsencrypt.org/acme/cert/fa738f7761ac7f2dcebe3124113c5c13a447");
  }
}

static esp_err_t mqtt_event_handler(esp_mqtt_event_handle_t event) {
  char topic[80], message[80];				// FIX ME limitation
  void HandleMqtt(char *topic, char *payload);

  switch (event->event_id) {
  case MQTT_EVENT_CONNECTED:
    ESP_LOGI(snetwork_tag, "mqtt connected");
    esp_mqtt_client_subscribe(mqtt, "/alarm", 0);
    break;
  case MQTT_EVENT_DISCONNECTED:
    ESP_LOGE(snetwork_tag, "mqtt disconnected");
    break;
  case MQTT_EVENT_SUBSCRIBED:
    ESP_LOGI(snetwork_tag, "mqtt subscribed");
    break;
  case MQTT_EVENT_UNSUBSCRIBED:
    ESP_LOGE(snetwork_tag, "mqtt subscribed");
    break;
  case MQTT_EVENT_PUBLISHED:
    break;
  case MQTT_EVENT_DATA:
    ESP_LOGD(snetwork_tag, "MQTT topic %.*s message %.*s",
      event->topic_len, event->topic, event->data_len, event->data);

    // Make safe copies, then call business logic handler
    strncpy(topic, event->topic, event->topic_len);
    topic[(event->topic_len > 79) ? 79 : event->topic_len] = 0;
    strncpy(message, event->data, event->data_len);
    message[(event->data_len > 79) ? 79 : event->data_len] = 0;

    // Handle it already
    HandleMqtt(topic, message);
    break;
  case MQTT_EVENT_ERROR:
    ESP_LOGD(snetwork_tag, "mqtt event error");
    break;
  case MQTT_EVENT_BEFORE_CONNECT:
    ESP_LOGD(snetwork_tag, "mqtt event before connect");
    break;
  }

  return ESP_OK;
}
