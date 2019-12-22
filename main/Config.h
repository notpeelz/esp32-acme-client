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

#ifndef	_ESPALARM_CONFIG_H_
#define	_ESPALARM_CONFIG_H_

#include <ArduinoJson.h>

struct config {
  const char *mac;
  const char *config;
};

class Config {
public:
  Config(String);
  Config(char *);
  ~Config();

  const char *getFilePrefix();

  char *QueryConfig();		// Caller must free the string

  const char *myName();

  void SetTimezone(const char *);
  char *GetTimezone();

  // Secure JSON
  char *getCaCert();
  char *getMyCert();
  char *getMyKey();
  char *getTrustedKeyStore();
  bool checkLocalCertificates();

  // ACME
  bool runAcme();
  const char *acmeEmailAddress();
  const char *acmeUrl();
  const char *acmeServerUrl();
  const char *getMyAcmeUserKeyFile();

  const char *getAcmeAccountFileName();
  const char *getAcmeOrderFileName();
  const char *getAcmeAuthorizationFileName();

  // FTP server
  bool runFtp();
  char *ftpUser(), *ftpPass();

  // Where to mount spiffs
  const char	*base_path = "/spiffs",
  		*base_fmt = "/spiffs/%s";

private:
  const char *config_tag = "Config";
  const char *name;
  char *tz;

  int dirty;
  void ReadConfig();
  void ReadConfig(const char *);
  void WriteConfig();
  void ParseConfig(JsonObject &jo);
  void HardCodedConfig(const char *mac);

  struct config my_config;
  static struct config configs[];

  // Certificates, keys for JSON server
  char *ca_cert, *my_cert, *my_key, *trusted;
  bool check_local_certificates;	// Check connection against certificates on local storage

  // ACME
  bool run_acme;			// Do a periodic call to renew our own certificate
  char *acme_user_private_key_file;	// file on SPIFFS where we store the ACME user's private key
  const char *acme_email_address;	//
  const char *acme_url;
  const char *acme_server_url;

  const char *acme_account_fn, *acme_order_fn;

  // FTP
  bool run_ftp;				// Simplistic FTP server
  char *ftp_user, *ftp_pass;
};

extern Config *config;

#endif	/* _ESPALARM_CONFIG_H_ */
