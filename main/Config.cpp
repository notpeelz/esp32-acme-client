/*
 * This module manages configuration data on local flash storage
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
#include "secrets.h"
#include <ArduinoJson.h>
#include "Default.h"

Config::Config(String mac) {
  name = 0;

  ca_cert = my_cert = my_key = trusted = acme_user_private_key_file = acme_cert_private_key_file = 0;
  acme_cert_fn = 0;
  run_acme = false;
  acme_email_address = 0;
  acme_url = acme_server_url = 0;
  acme_account_fn = acme_order_fn = 0;
  check_local_certificates = true;

  run_ftp = false;
  ftp_user = ftp_pass = 0;

  tz = NULL;

  my_config.mac = strdup(mac.c_str());
  HardCodedConfig(my_config.mac);
  ReadConfig();
}

Config::Config(char *mac) {
  name = 0;

  ca_cert = my_cert = my_key = trusted = acme_user_private_key_file = acme_cert_private_key_file = 0;
  acme_cert_fn = 0;
  run_acme = false;
  acme_email_address = 0;
  acme_url = acme_server_url = 0;
  acme_account_fn = acme_order_fn = 0;
  check_local_certificates = true;

  run_ftp = false;
  ftp_user = ftp_pass = 0;

  tz = NULL;

  my_config.mac = strdup(mac);
  HardCodedConfig(mac);
  ReadConfig();
}

Config::~Config() {
}

void Config::ReadConfig() {
#ifdef	USE_SPIFFS
  File f = SPIFFS.open(PREF_CONFIG_FN, "r");
  if (!f)
    return;	// Silently

  DynamicJsonBuffer jb;
  JsonObject &json = jb.parseObject(f);
  if (json.success()) {
    ESP_LOGD(config_tag, "Reading config from SPIFFS %s\n", PREF_CONFIG_FN);
    ParseConfig(json);
  } else {
    ESP_LOGE(config_tag, "Could not parse JSON from %s\n", PREF_CONFIG_FN);
  }

  f.close();
#endif
}

void Config::ReadConfig(const char *js) {
  ESP_LOGD(config_tag, "ReadConfig %s\n", js);

  DynamicJsonBuffer jb;
  JsonObject &json = jb.parseObject(js);
  if (json.success()) {
    ParseConfig(json);
  } else {
    ESP_LOGE(config_tag, "Could not parse JSON");
  }
}

void Config::ParseConfig(JsonObject &jo) {
  const char *z = (const char *)jo["timezone"];
  tz = strdup((z != NULL) ? z : ESPALARM_DEFAULT_TIMEZONE);

  name = jo["name"];
  // Note the missing else case gets treated in Config::myName()
  if (name) {
    name = strdup(name);	// Storage from JSON library doesn't last
  }

  run_acme = jo["run_acme"] | false;

  run_ftp = jo["run_ftp"] | false;
  const char *ftpu = jo["ftp_user"];
  ftp_user = 0;
  if (ftpu)
    ftp_user = strdup(ftpu);
  const char *ftpp = jo["ftp_pass"];
  ftp_pass = 0;
  if (ftpp)
    ftp_pass = strdup(ftpp);

  const char *aea = jo["acme_email_address"];
  if (aea)
    acme_email_address = strdup(aea);
  else
    acme_email_address = ACME_DEFAULT_EMAIL_ADDRESS;

  const char *au = jo["acme_url"];
  if (au)
    acme_url = strdup(au);
  else
    acme_url = ACME_DEFAULT_URL;

  const char *asu = jo["acme_server_url"];
  if (asu)
    acme_server_url = strdup(asu);
  else
    acme_server_url = ACME_DEFAULT_SERVER_URL;

  const char *ca_c = jo["ca_cert"];
  if (ca_c)
    ca_cert = strdup(ca_c);
  else
    ca_cert = (char *)"fullchain.pem";
  const char *my_c = jo["my_cert"];
  if (my_c)
    my_cert = strdup(my_c);
  else
    my_cert = (char *)"cert.pem";
  const char *my_k = jo["my_key"];
  if (my_k)
    my_key = strdup(my_k);
  else
    my_key = (char *)"privkey.pem";
  const char *tks = jo["trusted_keystore"];
  if (tks)
    trusted = strdup(tks);
  else
    trusted = (char *)"trust-client.crt";

  const char *aupkf = jo["acme_user_private_key_file"];
  if (aupkf)
    acme_user_private_key_file = strdup(aupkf);
  else
    acme_user_private_key_file = (char *)"user-private.pem";

  const char *acpkf = jo["acme_cert_private_key_file"];
  if (acpkf)
    acme_cert_private_key_file = strdup(acpkf);
  else
    acme_cert_private_key_file = (char *)"cert-private.pem";

  const char *acfn = jo["acme_cert_fn"];
  if (acfn)
    acme_cert_fn = strdup(acfn);
  else
    acme_cert_fn = (char *)"acme/certificate.pem";

  const char *aafn = jo["acme_account_file_name"];
  if (aafn)
    acme_account_fn = strdup(aafn);
  else
    acme_account_fn = (char *)"acme/account.json";

  const char *aofn = jo["acme_order_file_name"];
  if (aofn)
    acme_order_fn = strdup(aofn);
  else
    acme_order_fn = (char *)"acme/order.json";
}

void Config::HardCodedConfig(const char *mac) {
  boolean found = false;
  for (int i=0; configs[i].mac != 0; i++) {
    // Decode only the entry we need for auto-configuration purpose
    if (strcasecmp(configs[i].mac, mac) == 0) {
      ESP_LOGD(config_tag, "Hardcoded config %s\n", mac);
      ReadConfig(configs[i].config);
      found = true;
    }
  }

  if (! found)
    ESP_LOGE(config_tag, "No hardcoded config for %s\n", mac);
}

/*
 * Caller should free the result
 */
char *Config::QueryConfig() {
  DynamicJsonBuffer jb;
  JsonObject &json = jb.createObject();

  json["timezone"] = tz;

  json["run_ftp"] = run_ftp;
  json["ftp_user"] = ftp_user;
  json["ftp_pass"] = ftp_pass;

  json["run_acme"] = run_acme;
  json["acme_mail_address"] = acme_email_address;
  json["acme_url"] = acme_url;
  json["acme_server_url"] = acme_server_url;
  json["acme_user_private_key_file"] = acme_user_private_key_file;
  json["acme_cert_private_key_file"] = acme_cert_private_key_file;
  json["acme_cert_fn"] = acme_cert_fn;

  json["ca_cert"] = ca_cert;
  json["my_cert"] = my_cert;
  json["my_key"] = my_key;
  json["trusted_keystore"] = trusted;

  int bs = 512;
  char *buffer = (char *)malloc(bs);

  if (json.printTo(buffer, bs) == 0) {
    ESP_LOGE(config_tag, "Failed to write to buffer (size %d)", bs);
    return 0;
  }
  return buffer;
}

void Config::WriteConfig() {
#ifdef	USE_SPIFFS
  SPIFFS.remove(PREF_CONFIG_FN);

  File f = SPIFFS.open(PREF_CONFIG_FN, "w");
  if (!f) {
    ESP_LOGE(config_tag, "Failed to save config to %s\n", PREF_CONFIG_FN);
    return;
  }
  char *s = QueryConfig();
  int sl = strlen(s);

  if (f.write((uint8_t *)s, sl) == 0) {
    ESP_LOGE(config_tag, "Failed to write to config file %s\n", PREF_CONFIG_FN);
    return;
  }
  f.close();
#endif
}

/*
 * Hardcoded configuration JSON per MAC address
 * Store these in secrets.h in the MODULES_CONFIG_STRING macro definition.
 */
struct config Config::configs[] = {
#if 0
  { "12:34:56:78:90:ab",
    "{ \"radioPin\" : 4, \"haveOled\" : true, \"name\" : \"Keypad gang\" }"
  },
  { "01:23:45:67:89:0a",
    "{ \"name\" : \"ESP32 d1 mini\" }"
  },
#endif
  MODULES_CONFIG_STRING
  { 0, 0 }
};

const char *Config::myName(void) {
  if (name == 0) {
    name = (char *)malloc(40);
    sprintf((char *)name, "Controller %s", my_config.mac);
  }
  return name;
}

void Config::SetTimezone(const char *t) {
  if (tz)
    free(tz);
  tz = strdup(t);
}

char *Config::GetTimezone() {
  if (tz)
    return tz;
  return (char *)"CET-1CEST,M3.5.0/2,M10.5.0/3";
}

bool Config::runAcme() {
  return run_acme;
}

bool Config::runFtp() {
  return run_ftp;
}

char *Config::ftpUser() {
  return ftp_user;
}

char *Config::ftpPass() {
  return ftp_pass;
}

const char *Config::acmeEmailAddress() {
  return acme_email_address;
}

const char *Config::acmeServerUrl() {
  return acme_server_url;
}

const char *Config::acmeUrl() {
  return acme_url;
}

char *Config::getCaCert() {
  return ca_cert;
}

char *Config::getMyCert() {
  return my_cert;
}

char *Config::getMyKey() {
  return my_key;
}

const char *Config::getAccountKeyFileName() {
  return acme_user_private_key_file;
}

const char *Config::getAcmeCertificateKeyFileName() {
  return acme_cert_private_key_file;
}

const char *Config::getAcmeCertificateFileName() {
  return acme_cert_fn;
}

const char *Config::getAcmeAccountFileName() {
  return acme_account_fn;
}

const char *Config::getAcmeOrderFileName() {
  return acme_order_fn;
}

const char *Config::getAcmeAuthorizationFileName() {
  return "acme/auth.json";
}

const char *Config::getFileNamePrefix() {
  return "/spiffs";
}
