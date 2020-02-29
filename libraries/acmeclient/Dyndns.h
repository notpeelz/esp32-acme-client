/*
 * Copyright (c) 2016, 2017, 2020 Danny Backx
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
#ifndef _INCLUDE_DYNDNS_H_
#define _INCLUDE_DYNDNS_H_

#include <Arduino.h>
#include <esp_http_client.h>
#include <esp_event_loop.h>

enum dyndns_provider {
 DD_UNKNOWN,
 DD_NOIP,
 DD_CLOUDNS
};

class Dyndns {
public:
  Dyndns();
  Dyndns(dyndns_provider);
  ~Dyndns();
  boolean update();
  void setHostname(const char *);
  void setAddress(const char *);
  void setAuth(const char *);

private:
  esp_http_client_handle_t	http_client;
  esp_http_client_config_t	http_config;

  char				*hostname, *ip, *auth;
  dyndns_provider		provider;
  char				*buf;

  // NoIP
  const char *get_template1 =	"http://dynupdate.no-ip.com/nic/update?hostname=%s";
  const char *get_template2 =	"http://dynupdate.no-ip.com/nic/update?hostname=%s&myip=%s";
  // cloudns
  const char *get_template3 =	"http://ipv4.cloudns.net/api/dynamicURL/?q=%s";

  const char *hdr_header =	"Authorization";
  const char *hdr_template =	"Basic %s";

  const char *dyndns_tag =	"dyndns";

  static esp_err_t _http_event_handler(esp_http_client_event_t *);
};

extern Dyndns *dyndns;
#endif
