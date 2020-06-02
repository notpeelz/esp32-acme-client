/*
 * This module implements the ACME (Automated Certicifate Management Environment) protocol.
 * A client for Let's Encrypt (https://letsencrypt.org).
 *
 * ACME relies on the presence of a web server for validation.
 * We're using a FTP client to store a file on a web server for this purpose.
 * So we're not relying on accessibility of the IoT device itself, but on a nearby and
 * writable (for us) webserver. This allows for several IoT devices to hide between a NAT
 * device and still use ACME to have certificates.
 *
 * We're implementing ACME v2 (RFC 8555), which has status "proposed standard".
 * ACME v1 has risks and should be avoided.
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
#include "secrets.h"
#include "esp_log.h"

#include "Acme.h"

#include <sys/socket.h>
#include <lwip/etharp.h>
#include <mbedtls/base64.h>
#include <mbedtls/sha1.h>
#include <mbedtls/x509_csr.h>
#include <esp_http_client.h>

#include <dirent.h>

/*
 * CTOR / DTOR
 */
Acme::Acme() {
  directory = 0;
  account = 0;
  order = 0;
  challenge = 0;
  // location = 0;
  account_location = 0;
  nonce = 0;
  reply_buffer = 0;
  reply_buffer_len = 0;
  http01_ix = -1;
  last_run = 0;
  certificate = 0;

  acme_url = 0;
  email_address = 0;
  acme_server_url = 0;
  account_fn = 0;
  account_key_fn = 0;
  order_fn = 0;
  cert_key_fn = 0;
  cert_fn = 0;

  ftp_server = 0;
  ftp_user = ftp_pass = 0;
  ftp_path = 0;

  webserver = 0;
  ws_registered = false;
  ovf = 0;

  accountkey = 0;
  certkey = 0;
  rsa = 0;

  filename_prefix = "";

  connected = false;

  ctr_drbg = (mbedtls_ctr_drbg_context *)calloc(1, sizeof(mbedtls_ctr_drbg_context));
  mbedtls_ctr_drbg_init(ctr_drbg);

  entropy = (mbedtls_entropy_context *)calloc(1, sizeof(mbedtls_entropy_context));
  mbedtls_entropy_init(entropy);

  int err;
  if ((err = mbedtls_ctr_drbg_seed(ctr_drbg, mbedtls_entropy_func, entropy, NULL, 0))) {
    char buf[80];
    mbedtls_strerror(err, buf, sizeof(buf));
    ESP_LOGE(acme_tag, "mbedtls_ctr_drbg_seed failed %d %s", err, buf);
  }

#if 0
  ESP_LOGI(acme_tag, "ACME Configuration summary : %s", config->runAcme() ? "active" : "disabled");
  ESP_LOGI(acme_tag, "\tServer URL : %s", config->acmeServerUrl());
  ESP_LOGI(acme_tag, "\temail address : %s", config->acmeEmailAddress());
  ESP_LOGI(acme_tag, "\tMy URL : %s", config->acmeUrl());
  ESP_LOGI(acme_tag, "\tAccount private key : %s", config->getAccountKeyFileName());
  ESP_LOGI(acme_tag, "\tCertificate private key : %s", config->getAcmeCertificateKeyFileName());
  ESP_LOGI(acme_tag, "\tAccount info file : %s", config->getAcmeAccountFileName());
  ESP_LOGI(acme_tag, "\tOrder info file : %s", config->getAcmeOrderFileName());
#endif

#if 0
  GeneratePrivateKey();
  WritePrivateKey("/spiffs/acme/newkey.pem");
#endif

#if 0
  /*
   * Don't generate private keys automatically.
   * Do load the private keys early on (from files) if they're here.
   */
  if (account_key_fn && (accountkey = ReadPrivateKey(account_key_fn))) {
    rsa = mbedtls_pk_rsa(*accountkey);
  }
  if (cert_key_fn)
    certkey = ReadPrivateKey(cert_key_fn);
#endif
}

Acme::~Acme() {
  ClearAccount();
  ClearOrder();
  ClearChallenge();
  ClearDirectory();
  if (nonce)
    free(nonce);
  if (reply_buffer)
    free(reply_buffer);
  reply_buffer_len = 0;

  free(rsa);
  rsa = 0;
  free(entropy);
  entropy = 0;
  free(ctr_drbg);
  ctr_drbg = 0;

#if 0
  // Don't do this, they're just copies
  if (acme_url) free(acme_url);
  if (email_address) free(email_address);
  if (acme_server_url) free(acme_server_url);
  if (account_fn) free(account_fn);
  if (account_key_fn) free(account_key_fn);
  if (order_fn) free(order_fn);
  if (cert_key_fn) free(cert_key_fn);

  if (ftp_server) free(ftp_server);
  if (ftp_user) free(ftp_user);
  if (ftp_pass) free(ftp_pass);
  if (ftp_path) free(ftp_path);
#endif

  if (certificate) {
    mbedtls_x509_crt_free(certificate);
    free(certificate);
    certificate = 0;
  }
}

void Acme::GenerateAccountKey() {
  accountkey = GeneratePrivateKey();
  rsa = mbedtls_pk_rsa(*accountkey);
  if (account_key_fn)
    WritePrivateKey(accountkey, account_key_fn);
}

void Acme::GenerateCertificateKey() {
  certkey = GeneratePrivateKey();
  if (cert_key_fn)
    WritePrivateKey(certkey, cert_key_fn);
}

/*
 * Private keys
 * Very simplistic setter/getters.
 * Assumption is to pass a pointer, the original objects are managed elsewhere if supplied.
 * There will be a leak if you allow the class to read from a file, as well as supplying a key.
 * Setters also write the key into a file.
 */
mbedtls_pk_context *Acme::getAccountKey() {
  if (accountkey == 0) {
    ReadAccountKey();
  }
  return accountkey;
}

mbedtls_pk_context *Acme::getCertificateKey() {
  if (certkey == 0) {
    ReadCertKey();
  }
  return certkey;
}

void Acme::setAccountKey(mbedtls_pk_context *ak) {
  accountkey = ak;
  if (accountkey) {
    rsa = mbedtls_pk_rsa(*accountkey);
    if (account_key_fn)
      WritePrivateKey(accountkey, account_key_fn);
  }
}

void Acme::setCertificateKey(mbedtls_pk_context *ck) {
  certkey = ck;
  if (certkey && cert_key_fn)
    WritePrivateKey(certkey, cert_key_fn);
}

/*
 * Network connect / disconnect handlers.
 * These use the esp-idf API for such functions.
 */
void Acme::NetworkConnected(void *ctx, system_event_t *event) {
  ESP_LOGD(acme_tag, "%s", __FUNCTION__);

  connected = true;

  /*
   * Get startup info :
   * - the API calls for the ACME server
   * - an initial nonce
   * - our account and order status
   * See if we already have a local certificate
   *
   * FIX ME it may be a good idea to postpone the network calls.
   * Now we do them at each reboot...
   */
  QueryAcmeDirectory();
  RequestNewNonce();
  RequestNewAccount(email_address, true);	// This looks up the account, doesn't create one.

  ReadCertificate();
}

void Acme::NetworkDisconnected(void *ctx, system_event_t *event) {
  connected = false;
}

/*
 * This is supposed to get called periodically to continue work.
 * The parameter should be the current timestamp.
 *
 * Two types of action occur :
 *  - trigger the ACME request engine (finite state machine) to advance order status
 *  - check if the current certificate should be renewed, and cause that (which stumbles into the above)
 *    The last_run member ensures we either do this at reboot, or only once per hour.
 */
void Acme::loop(time_t now) {
  if (order) {
    AcmeProcess();
    return;		// FIXME ? Only look into renewal if we're not processing here.
  }

  // Only do stuff on first call or wait an hour
  if ((last_run != 0) && (now - last_run < 3600))
      return;
  last_run = now;

  // If we have a certificate, are we inside the renewal time range
  if (certificate == 0)
    return;
  time_t until = TimeMbedToTimestamp(certificate->valid_to);
  time_t month = 60 * 60 * 24 * 31;

  // TODO
  if (until - month < now) {
    ESP_LOGI(acme_tag, "Renewing certificate from %s", __FUNCTION__);
    RenewCertificate();
  }
}

/*
 * This runs the engine to reacquire a certificate.
 * RFC 8555 describes the states the server objects can be in; the client side must match that,
 * but also keep track of a couple of other state aspects :
 * - we may have "order = valid" but did we download the certificate yet ?
 * - ..
 *
 * This function does not start the order process, see RenewCertificate(), but advances it once it's started.
 * This function also doesn't create private keys, use the public API to do that or to supply them.
 */
static int process_count = 5;

void Acme::AcmeProcess() {
  /*
   * Note keep the two checks in this order.
   * If directory == 0 we only print limited number of error messages.
   */
  if (process_count-- < 0) {
    return;
  }
  if (directory == 0) {
    ESP_LOGE(acme_tag, "%s: no directory", __FUNCTION__);
    return;
  }

  ESP_LOGI(acme_tag, "%s", __FUNCTION__);

  if (account == 0) {
    ESP_LOGI(acme_tag, "%s account 0", __FUNCTION__);
    if (! ReadAccountInfo()) {
      ESP_LOGI(acme_tag, "%s requesting new account", __FUNCTION__);
      RequestNewAccount(email_address, true);
      ESP_LOGI(acme_tag, "%s writing new account", __FUNCTION__);
      WriteAccountInfo();
    }
    if (account == 0) {
      ESP_LOGE(acme_tag, "%s: fail, no account", __FUNCTION__);
      return;
    }
  }

  if (order == 0) {	// We haven't read storage yet, and we've not been kickstarted by the application.
    ESP_LOGI(acme_tag, "%s Read order info", __FUNCTION__);
    ReadOrderInfo();
  }
  if (order == 0)
    return;		// Return silently

  if (order->status == 0) {
    ESP_LOGI(acme_tag, "%s order status 0", __FUNCTION__);
    ReadOrderInfo();
    if (order == 0 || order->status == 0) {
      ESP_LOGI(acme_tag, "%s request new order", __FUNCTION__);
      RequestNewOrder(acme_url);
      WriteOrderInfo();
      return;
    }
  }
  if (order->status == 0) {
    ESP_LOGI(acme_tag, "%s order status 0+", __FUNCTION__);
    return;
  }

  // Check deeper
  boolean invalid = false;
  if (challenge && strcmp(challenge->status, acme_status_invalid) == 0) {
    ESP_LOGE(acme_tag, "%s : %s challenge, starting a new order", __FUNCTION__, acme_status_invalid);
    invalid = true;
  } else if (challenge && challenge->challenges)
    for (int i=0; challenge->challenges[i].status; i++)
      if (strcmp(challenge->challenges[i].status, acme_status_invalid) == 0) {
	ESP_LOGE(acme_tag, "%s : %s challenge[%d], starting a new order", __FUNCTION__, acme_status_invalid, i);
        invalid = true;
	break;
      }

  if (invalid) {
    RequestNewOrder(acme_url);
    WriteOrderInfo();
    return;
  }

  if (strcmp(order->status, acme_status_pending) == 0) {
    boolean ok = ValidateOrder();
    ESP_LOGI(acme_tag, "%s: ValidateOrder -> %s", __FUNCTION__, ok ? "ok" : "fail");
    WriteOrderInfo();
  }
  if (strcmp(order->status, acme_status_ready) == 0) {
    FinalizeOrder();
    WriteOrderInfo();
  }
  if (strcmp(order->status, acme_status_processing) == 0) {
    ;
  }
  if (strcmp(order->status, acme_status_downloaded) == 0) {
    // There shouldn't be anything here, but if the downloaded file goes bust, download it again.
    if (certificate == 0) {
      free(order->status);
      order->status = strdup(acme_status_valid);
      WriteOrderInfo();
    }
  }
  if (strcmp(order->status, acme_status_valid) == 0) {
    if (order->certificate) {
      DownloadCertificate();
      WriteOrderInfo();
    }

    if (ws_registered)
      DisableLocalWebServer();

    free(order->status);
    order->status = strdup(acme_status_downloaded);		// an additional status
    WriteOrderInfo();
  }
  if (strcmp(order->status, acme_status_invalid) == 0) {
    // Something went wrong with this order, need to restart a new order
    RequestNewOrder(acme_url);
    WriteOrderInfo();

    if (ws_registered)
      DisableLocalWebServer();

    return;
  }
}

boolean Acme::CreateNewAccount() {
  if (!connected) return false;
  if (directory == 0) {
    QueryAcmeDirectory();
    RequestNewNonce();
  }

  if (email_address == 0) {
    ESP_LOGE(acme_tag, "%s failed : no email address", __FUNCTION__);
    return false;
  }

  ESP_LOGI(acme_tag, "%s: check whether account already exists", __FUNCTION__);
  // Check if it exists already
  if (RequestNewAccount(email_address, true)) {
    ESP_LOGI(acme_tag, "%s: ... it does !", __FUNCTION__);
    WriteAccountInfo();
    return true;	// Return successfully then
  }

  ESP_LOGI(acme_tag, "%s: creating account %s ...", __FUNCTION__, email_address);
  // Otherwise, try to create one
  boolean ok = RequestNewAccount(email_address, false);
  if (ok) {
    ESP_LOGI(acme_tag, "%s: success : account %s created", __FUNCTION__, email_address);
    WriteAccountInfo();
  } else {
    ESP_LOGE(acme_tag, "%s: failed", __FUNCTION__);
  }

  return ok;
}

/*
 * This creates a structure so the process gets triggered
 */
void Acme::CreateNewOrder() {
  ClearOrder();
  order = (Order *)malloc(sizeof(Order));
  memset((void *)order, 0, sizeof(Order));
}

/*
 * Strings need to be translated into proper format, see the JWS RFC : https://tools.ietf.org/html/rfc7515 .
 * Caller needs to free the result.
 */
char *Acme::Base64(const char *s) {
  size_t olen;

  if (s == 0) {
    ESP_LOGD(acme_tag, "%s : null", __FUNCTION__);
    return 0;
  }

  int sl = strlen(s);
  if (sl == 0) {
    ESP_LOGD(acme_tag, "%s : empty string", __FUNCTION__);
    char *r = (char *)malloc(1);
    *r = 0;
    return r;
  }

  (void) mbedtls_base64_encode(0, 0, &olen, (const unsigned char *)s, sl);
  char *r = (char *)malloc(olen + 1);
  (void) mbedtls_base64_encode((unsigned char *)r, olen+1, &olen, (const unsigned char *)s, sl);

  // Replace some characters by acceptable ones, without making the string longer. Also in the RFCs.
  for (int i=0; i<=olen; i++)
    if (r[i] == '+')
      r[i] = '-';
    else if (r[i] == '/')
      r[i] = '_';
    else if (r[i] == '=')
      r[i] = 0;	

  return r;
}

// And the opposite
char *Acme::Unbase64(const char *s) {
  int len = strlen(s);
  char *r = (char *)malloc(len+4);	// For a trailing 0 and up to 2 trailing '='
  for (int i=0; i<=len; i++)
    if (s[i] == '-')
      r[i] = '+';
    else if (s[i] == '_')
      r[i] = '/';
    else if (s[i] == 0) {
      r[i]   = '=';
      r[i+1] = '=';
      r[i+2] = 0;
    } else
      r[i] = s[i];

  size_t olen = 0;
  (void) mbedtls_base64_decode(0, 0, &olen, (const unsigned char *)r, len);

  ESP_LOGI(acme_tag, "%s: strlen -> %d, olen %d", __FUNCTION__, len, olen);
  char *obuf = (char *)malloc(olen+1);
  if (obuf == 0) {
    ESP_LOGE(acme_tag, "%s: malloc -> 0, errno %d", __FUNCTION__, errno);
    free(r);
    return 0;
  }
  int err = mbedtls_base64_decode((unsigned char *)obuf, olen+1, &olen, (const unsigned char *)r, len);
  if (err != 0) {
    char buf[80];
    mbedtls_strerror(err, buf, sizeof(buf));
    ESP_LOGE(acme_tag, "%s: mbedtls_base64_decode error %d %s", __FUNCTION__, err, buf);
    free(r);
    free(obuf);
    return 0;
  }
  free(r);
  return obuf;
}

/*
 * Support stuff
 */
char *Acme::Base64(const char *s, int len) {
  if (s == 0)
    return 0;

  size_t olen;
  (void) mbedtls_base64_encode(0, 0, &olen, (const unsigned char *)s, len);

  char *r = (char *)malloc(olen + 1);
  (void) mbedtls_base64_encode((unsigned char *)r, olen+1, &olen, (const unsigned char *)s, len);

  // Replace some characters by acceptable ones, without making the string longer. Also in the RFCs.
  for (int i=0; i<=olen; i++)
    if (r[i] == '+')
      r[i] = '-';
    else if (r[i] == '/')
      r[i] = '_';
    else if (r[i] == '=')
      r[i] = 0;	

  return r;
}

/*
 * Make an ACME message, this version makes the ones that include a "jwk" field.
 *
 * Some of the relevant parts of RFC 8555 (§6.2) :
 *   It must have the fields "alg", "nonce", "url", and either "jwk" or "kid".
 *   newAccount and revokeCert messages must use jwk, this field must contain the public key
 *   corresponding to the private key used to sign the JWS.
 *   All other requests are signed using an existing account, and there must be a kid field
 *   which contains the account URL received by POSTing to newAcount.
 *
 * So this must only be used in newAccount or revokeCert.
 *
 * {"url": "https://acme-staging-v02.api.letsencrypt.org/acme/new-acct", "jwk": {"kty": "RSA",
 *  "n": "...", "e": "AQAB"}, "alg": "ES256", "nonce": "U8b_2ZGRATuySa9yPOF3JDN4JXTyEdAfrL--WTzqYKQ"}
 */
char *Acme::MakeMessageJWK(char *url, char *payload, char *jwk) {
  ESP_LOGD(acme_tag, "%s(%s,%s,%s)", __FUNCTION__, url, payload, jwk);

  String p_rotected = String("{\"url\": \"") + url + "\", \"jwk\": " + jwk + ", \"alg\": \"RS256\", \"nonce\": \"" + nonce + "\"}";	// ? Fixed
  String p_rotected64 = Base64(p_rotected.c_str());
  ESP_LOGD(acme_tag, "PR %s", p_rotected.c_str());
  String p_ayload = Base64(payload);
  String s_ignature = Signature(p_rotected64, p_ayload);

  String js = String("{\n  \"protected\": \"") + p_rotected64
    + "\",\n  \"payload\": \"" + p_ayload + "\",\n  \"signature\": \"" + s_ignature + "\"\n}";

  return strdup(js.c_str());
}

/*
 * Caller must free
 *
 * This basically prints out the N (public key modulus) field from the key in the RSA context pointer.
 * We're extracting the N and E mpi's. Note that their type is char * but they're not strings.
 * Can start with 0 if not allocated properly, and not null-terminated. Hence the two-parameter call to Base64().
 */
char *Acme::MakeJWK() {
  int err;

  int ne = 4;						// E will be at the rear end of this array
  unsigned char	E[4];
  int nl = mbedtls_rsa_get_len(rsa);
  unsigned char *N = (unsigned char *)malloc(nl);	// Allocate exactly long enough, don't add one more for trailing 0.

  if ((err = mbedtls_rsa_export_raw(rsa, N, nl, /* P */ 0, 0, /* Q */ 0, 0, /* D */ 0, 0, E, ne)) != 0) {
    char buf[80];
    mbedtls_strerror(err, buf, sizeof(buf));
    ESP_LOGE(acme_tag, "%s: failed rsa_export_raw %d %s", __FUNCTION__, err, buf);
    return 0;
  }

  // E is at the rear end of this array, point q to it
  char *q = (char *)E;
  for (; *q == 0; q++,ne--);			// Skip initial zeroes

  char *bN = Base64((char *)N, nl);		// Note RFC remark not to apply padding, N has been allocated exactly the right size
  char *bE = Base64(q, ne);			// This returns "AQAB" under normal circumstances

  ESP_LOGD(acme_tag, "%s: N %s, E %s", __FUNCTION__, bN, bE);

  free(N);

  int len = strlen(acme_jwk_template) + strlen((char *)bN) + strlen((char *)bE) + 4;
  char *r = (char *)malloc(len);
  sprintf(r, acme_jwk_template, bN, bE);
  free(bN);
  free(bE);

  ESP_LOGD(acme_tag, "%s -> %s", __FUNCTION__, r);

  return r;
}

/*
 * RFC 8555 (ACME v2) says (§6.2) : encapsulate payload in a JWS (RFC7515) object,
 * using Flattened JSON Serialization.
 *
 * RFC 7518 (JWS) §3.3 : A key of size 2048 bits or larger MUST be used with these algorithms.
 *
 * Signature as specified by JWS (https://tools.ietf.org/html/rfc7515).
 * This must be JSON Web Signature (see RFC 8555, §6.1).
 *
 * Parameters are already base64-url formatted
 */
String Acme::Signature(String pr, String pl) {
  int ret;
  char buf[80];

  ESP_LOGD(acme_tag, "PR %s", pr.c_str());
  ESP_LOGD(acme_tag, "PL %s", pl.c_str());

  int len = strlen(pr.c_str()) + strlen(pl.c_str()) + 4;
  char *bb = (char *)malloc(len);
  sprintf(bb, "%s.%s", pr.c_str(), pl.c_str());
  ESP_LOGD(acme_tag, "signing input (length %d) {%s}", strlen((char *)bb), bb);

  // Generate a digital signature
  unsigned char *signature = (unsigned char *)calloc(2, mbedtls_pk_get_len(accountkey));	// hack
  if (! signature) {
    ESP_LOGE(acme_tag, "calloc failed, mbedtls_pk_get_len %d", mbedtls_pk_get_len(accountkey));
    free(bb);
    return (String)0;
  }
  int hash_size = 32;
  unsigned char *hash = (unsigned char *)calloc(1, hash_size);
  if (hash == 0) {
    ESP_LOGE(acme_tag, "calloc(32) failed");
    free(signature);
    free(bb);
    return (String)0;
  }

  const mbedtls_md_info_t *mdi = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  if (!mdi) {
    ESP_LOGE("Acme", "mbedtls_hash_get_len: md_info not found");
    free(signature);
    free(hash);
    return (String)0;
  }
  ret = mbedtls_md(mdi, (const unsigned char *)bb, strlen(bb), (unsigned char *)hash);
  free(bb); bb = 0;
  if (ret != 0) {
    mbedtls_strerror(ret, buf, sizeof(buf));
    ESP_LOGE(acme_tag, "mbedtls_hash_fast failed %s (0x%04x)", buf, -ret);
    free(signature);
    free(hash);
    return (String)0;
  }

  size_t signature_size = 0;
  ret = mbedtls_pk_sign(accountkey, MBEDTLS_MD_SHA256, hash, hash_size, signature, &signature_size, mbedtls_ctr_drbg_random, ctr_drbg);
  if (ret != 0) {
    mbedtls_strerror(ret, buf, sizeof(buf));
    ESP_LOGE(acme_tag, "mbedtls_pk_sign failed %s (0x%04x)", buf, -ret);
    free(signature);
    free(hash);
    return (String)0;
  }

  ESP_LOGD(acme_tag, "%s: signature size %d", __FUNCTION__, signature_size);

  /* Base64-encode and return.. it's important to use signature_size from mbedtls_pk_sign,
   * the signature can contain 0 bytes. */
  char *s = Base64((char *)signature, signature_size);
  free(signature);

  String rs = String(s);
  free(s);
  return rs;
}

/***************************************************
 * And now for real ACME ...
 *
 ***************************************************/
/*
 * Fetch the "directory" of the ACME server.
 * This gives us a set of URLs for our queries. Put this in a structure for later use.
 */
void Acme::QueryAcmeDirectory() {
  if (!connected) return;
  if (acme_server_url == 0) {
    ESP_LOGI(acme_tag, "%s: no ACME server configured", __FUNCTION__);
    return;
  }

  ESP_LOGI(acme_tag, "Querying directory at %s", acme_server_url);
  ClearDirectory();

  char *reply = PerformWebQuery(acme_server_url, 0, 0, 0);

  if (reply == 0) {
    ESP_LOGE(acme_tag, "%s: PerformWebQuery -> 0, returning", __FUNCTION__);
    return;
  }

  ESP_LOGD(acme_tag, "%s: parsing JSON %s", __FUNCTION__, reply);

  DynamicJsonBuffer jb;
  JsonObject &root = jb.parseObject(reply);
  if (! root.success()) {
    ESP_LOGE(acme_tag, "Could not parse JSON");
    free(reply);
    return;
  }
  directory = (Directory *)malloc(sizeof(Directory));
  memset(directory, 0, sizeof(Directory));

#define SD(x,sx) 						\
	{							\
	  const char *s;					\
	  s = root[sx];						\
	  if (s) {						\
	    x = strdup(s);					\
	    ESP_LOGD(acme_tag, "New %s URL : %s", sx, x);	\
	  } else						\
	    x = 0;						\
	}

  SD(directory->newAccount, "newAccount");
  SD(directory->newNonce, "newNonce");
  SD(directory->newOrder, "newOrder");

  free(reply);

  if (directory->newAccount == 0 || directory->newNonce == 0 || directory->newOrder == 0)
    ESP_LOGE(acme_tag, "%s: incomplete results : newAccount %p newNonce %p newOrder %p", __FUNCTION__,
      directory->newAccount, directory->newNonce, directory->newOrder);
  else
    ESP_LOGI(acme_tag, "%s: ok", __FUNCTION__);
}

/*
 * Deallocate the structure with the server URLs, and its content.
 */
void Acme::ClearDirectory() {
  if (directory) {
    if (directory->newAccount) free(directory->newAccount);
    if (directory->newNonce) free(directory->newNonce);
    if (directory->newOrder) free(directory->newOrder);
    free(directory);
    directory = 0;
  }
}

/*
 * Nonce : this is an ACME v1 vs v2 difference : make sure the server only gets queries in a sequence.
 * Each ACME query will include the "nonce" that its predecessor received from the server.
 *
 * We send a HEAD query to the URL in the directory, and fetch the header "Replay-Nonce" in the reply.
 * This requires a 3 function implementation because the esp_http_client API doesn't expose reply headers except in an event handler.
 * The reply data is available though, go figure :-(
 */
boolean Acme::RequestNewNonce() {
  esp_err_t			err;
  esp_http_client_config_t	httpc;
  esp_http_client_handle_t	client;

  if (directory == 0) {
    ESP_LOGE(acme_tag, "%s: no ACME directory", __FUNCTION__);
    return false;
  }

  if (nonce) {
    free(nonce);
    nonce = 0;
  }

  if (directory->newNonce == 0) {
    ESP_LOGE(acme_tag, "%s: we have no newNonce URL", __FUNCTION__);
    return false;
  }

  ESP_LOGD(acme_tag, "%s(%s)", __FUNCTION__, directory->newNonce);

  memset(&httpc, 0, sizeof(httpc));
  httpc.url = directory->newNonce;
  httpc.event_handler = NonceHttpEvent;

  client = esp_http_client_init(&httpc);

  SetAcmeUserAgentHeader(client);

  if ((err = esp_http_client_set_method(client, HTTP_METHOD_HEAD)) != ESP_OK) {
    ESP_LOGE(acme_tag, "%s: client_set_method error %d %s", __FUNCTION__, err, esp_err_to_name(err));
    esp_http_client_cleanup(client);
    return false;
  }
  ESP_LOGD(acme_tag, "%s set_method(HEAD) ok", __FUNCTION__);

  if ((err = esp_http_client_perform(client)) != ESP_OK) {
    ESP_LOGE(acme_tag, "%s: client_perform error %d %s", __FUNCTION__, err, esp_err_to_name(err));
    esp_http_client_cleanup(client);
    return false;
  }
  ESP_LOGD(acme_tag, "%s client_perform ok", __FUNCTION__);

  esp_http_client_close(client);
  esp_http_client_cleanup(client);

  // It should already be there, so report back
  return (nonce != 0);
}

esp_err_t Acme::NonceHttpEvent(esp_http_client_event_t *event) {
  if (event->event_id == HTTP_EVENT_ON_HEADER) {
    ESP_LOGD("Acme", "%s: header %s value %s", __FUNCTION__, event->header_key, event->header_value);
    if (strcmp(event->header_key, acme_nonce_header) == 0)
      acme->setNonce(event->header_value);
  }
  return ESP_OK;
}

/*
 * These are handlers called by HttpEvent() so we can pick up stuff from HTTP headers in replies from the ACME server.
 */
void Acme::setNonce(char *s) {
  if (nonce)
    free(nonce);
  nonce = strdup(s);

  ESP_LOGD(acme_tag, "%s(%s)", __FUNCTION__, nonce);
}

// This is needed because the location field is passed back in an HTTP header
void Acme::setLocation(const char *s) {
  if (account_location)
    free(account_location);
  account_location = strdup(s);
}

/*
 * Manage private key
 */
mbedtls_pk_context *Acme::GeneratePrivateKey() {
  mbedtls_pk_context	*key;
  int			ret;
  char			buf[80];

  ESP_LOGI(acme_tag, "Generating private key ...");

  key = (mbedtls_pk_context *)calloc(1, sizeof(mbedtls_pk_context));
  mbedtls_pk_init(key);
  mbedtls_pk_setup(key, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));

  if ((ret = mbedtls_rsa_gen_key(mbedtls_pk_rsa(*key), mbedtls_ctr_drbg_random, ctr_drbg, /* key size */ 2048, /* exponent */ 0x10001)) != 0) {
    mbedtls_strerror(ret, buf, sizeof(buf));
    ESP_LOGE(acme_tag, "%s: mbedtls_rsa_gen_key failed %s (0x%04x)", __FUNCTION__, buf, -ret);
    free((void *)key);
    return 0;
  }
  return key;
}

/*
 * Read a private key from a file, caller can specify file name.
 * Prepends our path prefix prior to use.
 */
mbedtls_pk_context *Acme::ReadPrivateKey(const char *ifn) {
  mbedtls_pk_context *pk;

  int fnlen = strlen(filename_prefix) + strlen(ifn) + 3;
  char *fn = (char *)malloc(fnlen);
  sprintf(fn, "%s/%s", filename_prefix, ifn);

  int ret;
  char buf[80];

  pk = (mbedtls_pk_context *)calloc(1, sizeof(mbedtls_pk_context));
  mbedtls_pk_init(pk);
  if ((ret = mbedtls_pk_parse_keyfile(pk, fn, 0)) != 0) {
    mbedtls_strerror(ret, buf, sizeof(buf));
    ESP_LOGE(acme_tag, "%s: mbedtls_pk_parse_keyfile(%s) failed %s (0x%04x)", __FUNCTION__, fn, buf, -ret);
    free(fn);
    free((void *)pk);
    return 0;
  }

  ESP_LOGI(acme_tag, "%s: read key file (%s) ok", __FUNCTION__, fn);
  free(fn);
  return pk;
}

/*
 * Check (and create) directories in the path
 * This becomes sensible on a real filesystem like LittleFS (not on SPIFFS).
 */
void Acme::CreateDirectories(const char *path) {
  char *dir = strdup(path);

  ESP_LOGI(acme_tag, "%s(%s)", __FUNCTION__, dir);

  // Walk from the beginning to the end of the path

  int len = strlen(dir);
  for (int i=1; i<len; i++)
    if (dir[i] == '/') {
      // Temporarily terminate path here
      dir[i] = 0;

      // If this directory doesn't exist, create it
      DIR *dp = opendir(dir);
      if (dp == 0) {
        int err = mkdir(dir, 0777);
        if (err == ESP_OK) {
	  ESP_LOGI(acme_tag, "%s: created directory %s", __FUNCTION__, dir);
        } else {
	  ESP_LOGE(acme_tag, "%s: failed to create directory %s, %d %s", __FUNCTION__, dir,
	    err, esp_err_to_name(err));
	  return;
        }
      } else {
        ESP_LOGI(acme_tag, "%s : %s exists", __FUNCTION__, dir);
	closedir(dp);
      }

      // Restore path
      dir[i] = '/';
    }
  free(dir);
}

/*
 * Write a private key to a file, caller can specify file name.
 * Prepends our path prefix prior to use.
 */
void Acme::WritePrivateKey(mbedtls_pk_context *pk, const char *ifn) {
  int fnlen = strlen(filename_prefix) + strlen(ifn) + 3;
  char *fn = (char *)malloc(fnlen);
  sprintf(fn, "%s/%s", filename_prefix, ifn);

  CreateDirectories(fn);
  FILE *f = fopen(fn, "w");
  if (f == 0) {
    ESP_LOGE(acme_tag, "%s: could not write private key to file %s", __FUNCTION__, fn);
    free(fn);
    return;
  }

  int ret, len;
  char buf[80];
  unsigned char keystring[2048];

  if ((ret = mbedtls_pk_write_key_pem(pk, keystring, sizeof(keystring))) != 0) {
    mbedtls_strerror(ret, buf, sizeof(buf));
    ESP_LOGE(acme_tag, "%s: mbedtls_pk_write_key_pem failed %s (0x%04x)", __FUNCTION__, buf, -ret);
    free(fn);
    return;
  }

  len = strlen((char *)keystring);
  ESP_LOGD(acme_tag, "%s: private key len %d", __FUNCTION__, len);
  ESP_LOGD(acme_tag, "Key : %s", keystring);

  if (fwrite(keystring, 1, len, f) != len) {
    ESP_LOGE(acme_tag, "%s: write private key to %s failed, %d %s", __FUNCTION__, fn, errno, strerror(errno));
    fclose(f);
    free(fn);
    return;
  }
  if (fclose(f) != 0) {
    ESP_LOGE(acme_tag, "%s: write private key to %s failed, %d %s", __FUNCTION__, fn, errno, strerror(errno));
    free(fn);
    return;
  }

  ESP_LOGI(acme_tag, "%s: wrote private key to %s", __FUNCTION__, fn);
  free(fn);
}

/*
 * Write a private key to the file name from Config.
 */
void Acme::WritePrivateKey() {
  int ret, len;
  char buf[80];
  unsigned char keystring[2048];

  if ((ret = mbedtls_pk_write_key_pem(accountkey, keystring, sizeof(keystring))) != 0) {
    mbedtls_strerror(ret, buf, sizeof(buf));
    ESP_LOGE(acme_tag, "%s: mbedtls_pk_write_key_pem failed %s (0x%04x)", __FUNCTION__, buf, -ret);
    return;
  }

  len = strlen((char *)keystring);
  ESP_LOGI(acme_tag, "%s: private key len %d", __FUNCTION__, len);
  ESP_LOGI(acme_tag, "Key : %s", keystring);

  int fnlen = strlen(account_key_fn) + strlen(filename_prefix) + 3;
  char *fn = (char *)malloc(fnlen);
  sprintf(fn, "%s/%s", filename_prefix, account_key_fn);

  CreateDirectories(fn);
  FILE *f = fopen(fn, "w");
  if (f) {
    fwrite(keystring, 1, len, f);
    fclose(f);
  } else {
    ESP_LOGE(acme_tag, "%s: could not write private key to file %s", __FUNCTION__, fn);
  }
  free(fn);
}

/*
 * Account handling
 * The "onlyExisting" parameter is used to check whether an account pre-exists. Don't use error logging then.
 */
boolean Acme::RequestNewAccount(const char *contact, boolean onlyExisting) {
  char *msg, *jwk, *payload;

  if (directory == 0) {
    ESP_LOGE(acme_tag, "%s fail, no directory", __FUNCTION__);
    return false;
  }

  if (rsa == 0) {
    ReadAccountKey();
    if (rsa == 0) {
      ESP_LOGE(acme_tag, "%s(%s) fail, rsa null", __FUNCTION__, contact);
      return false;
    }
  }

  if (contact) {	// email address is included
    // Check whether it starts with "mailto:"
    boolean add_mailto = (strncasecmp(contact, acme_mailto, strlen(acme_mailto)) != 0);

    // Allocate just enough. The 10 is for small stuff + the onlyExisting boolean.
    int len = strlen(new_account_template) + strlen(contact) + 10;
    if (add_mailto)
      len += strlen(acme_mailto);
    payload = (char *)malloc(len);

    // Create message
    sprintf(payload, new_account_template,
      add_mailto ? acme_mailto : "", contact,
      onlyExisting ? "true" : "false");
    ESP_LOGD(acme_tag, "%s(%s) msg %s", __FUNCTION__, contact, payload);
  } else {
    payload = strdup(new_account_template_no_email);
    ESP_LOGD(acme_tag, "%s(NULL) msg %s", __FUNCTION__, payload);
  }

  jwk = MakeJWK();
  if (jwk) {
    msg = MakeMessageJWK(directory->newAccount, payload, jwk);
    free(jwk);
  } else
    msg = MakeMessageJWK(directory->newAccount, payload, (char *)"");

  if (! msg) {
    ESP_LOGE(acme_tag, "%s: null message", __FUNCTION__);
    return false;
  }
  ESP_LOGD(acme_tag, "%s : msg %s", __FUNCTION__, msg);

  char *reply = PerformWebQuery(directory->newAccount, msg, acme_jose_json, 0);
  free(msg);
  if (reply == 0) {
    ESP_LOGE(acme_tag, "%s PerformWebQuery -> null", __FUNCTION__);
    return false;
  }

  // Decode JSON reply
  ESP_LOGD(acme_tag, "%s: parsing JSON %s", __FUNCTION__, reply);

  DynamicJsonBuffer jb;
  JsonObject &root = jb.parseObject(reply);
  if (! root.success()) {
    ESP_LOGE(acme_tag, "%s : could not parse JSON", __FUNCTION__);
    free(reply);
    return false;
  }
  ESP_LOGD(acme_tag, "%s : JSON opened", __FUNCTION__);

  const char *reply_status = root[acme_json_status];
  if (reply_status && strcmp(reply_status, acme_status_valid) != 0) {
    const char *reply_type = root[acme_json_type];
    const char *reply_detail = root[acme_json_detail];

    if (!onlyExisting)
      ESP_LOGE(acme_tag, "%s: failure %s %s %s", __FUNCTION__, reply_status, reply_type, reply_detail);

    free(reply);
    return false;
  } else if (reply_status == 0) {
    // ESP_LOGE(acme_tag, "%s: null reply_status", __FUNCTION__);
    ESP_LOGE(acme_tag, "%s: null reply_status (reply %s)", __FUNCTION__, reply);
  } else {
    ESP_LOGI(acme_tag, "%s: reply_status '%s'", __FUNCTION__, reply_status);
  }

  ReadAccount(root);

  free(reply);
  return true;
}

// FIXME protect against missing fields, will now call strdup(0)
void Acme::ReadAccount(JsonObject &json) {
  account = (Account *)malloc(sizeof(Account));
  memset((void *)account, 0, sizeof(Account));

/*
 * Replace a single statement such as
 *   account->key_type = strdup(json["key"]["kty"]);
 * by a macro invocation to protect against calling strdup(0) if an element is not in the JSON.
 * C/C++ syntax hint : #x turns the macro argument x into a string.
 */
#define	BZZ(x)									\
  {										\
    const char *x = json[#x];							\
    if (x) {									\
      ESP_LOGD(acme_tag, "%s : read %s as %s", __FUNCTION__, #x, x);		\
      account->x = strdup(x);							\
    } else {									\
      ESP_LOGD(acme_tag, "%s : no %s read", __FUNCTION__, #x);			\
      account->x = 0;								\
    }										\
  }

#define	BZZ2(x,y)								\
  {										\
    const char *x = json["key"][#y];						\
    ESP_LOGD(acme_tag, "%s: read %s as %s", __FUNCTION__, #y, x);		\
    if (x)									\
      account->x = strdup(x);							\
    else									\
      account->x = 0;								\
  }

  BZZ2(key_type, kty);
  BZZ2(key_id, n);
  BZZ2(key_e, e);

  BZZ(initialIp);
  BZZ(createdAt);
  BZZ(status);

  JsonArray &jca = json["contact"];
  ESP_LOGD(acme_tag, "%s : %d contacts", __FUNCTION__, jca.size());
  account->contact = (char **)calloc(jca.size()+1, sizeof(char *));
  account->contact[jca.size()] = 0;
  for (int i=0; i<jca.size(); i++) {
    const char *cc = jca[i];
    account->contact[i] = strdup(cc);
  }

  // Exception for the location field : when reading a ACME reply, this is in an HTTP header.
  // When reading from our saved file, this is in the JSON.
  // So only update the field if we read the JSON parameter, otherwise don't do a thing.
  const char *l = json["location"];
  // if (l)
    // location = strdup(l);

  if (account->location)
    free(account->location);
  if (account_location) {
    account->location = account_location;
    account_location = 0;
  } else if (l)
    account->location = strdup(l);

#undef BZZ
#undef BZZ2
}

void Acme::ClearAccount() {
  if (account) {
    if (account->key_type) free(account->key_type);
    if (account->key_id) free(account->key_id);
    if (account->key_e) free(account->key_e);
    if (account->initialIp) free(account->initialIp);
    if (account->createdAt) free(account->createdAt);
    if (account->location) free(account->location);
    free(account);
    account = 0;
  }

  // if (location) free(location);
  // location = 0;
}

void Acme::ClearOrderContent() {
  if (order->status) free(order->status);
  if (order->expires) free(order->expires);
  if (order->finalize) free(order->finalize);
  if (order->certificate) free(order->certificate);
  if (order->identifiers) {
    for (int i=0; order->identifiers[i]._type; i++) {
      free(order->identifiers[i]._type);
      free(order->identifiers[i].value);
    }
    free(order->identifiers);
  }
  if (order->authorizations) {
    for (int i=0; order->authorizations[i]; i++)
      free(order->authorizations[i]);
    free(order->authorizations);
  }

  memset(order, 0, sizeof(Order));
}

void Acme::ClearOrder() {
  if (order) {
    ClearOrderContent();

    free(order);
    order = 0;
  }
}

void Acme::ClearChallenge() {
  if (challenge) {
    if (challenge->status) free(challenge->status);
    if (challenge->expires) free(challenge->expires);
    if (challenge->identifiers) {
      for (int i=0; challenge->identifiers[i]._type; i++) {
        free(challenge->identifiers[i]._type);
        free(challenge->identifiers[i].value);
      }
      free(challenge->identifiers);
    }
    if (challenge->challenges) {
      for (int i=0; challenge->challenges[i]._type; i++) {
        free(challenge->challenges[i]._type);
        free(challenge->challenges[i].status);
        free(challenge->challenges[i].url);
        free(challenge->challenges[i].token);
      }
      free(challenge->challenges);
    }
    free(challenge);
    challenge = 0;
  }
}

/*
 * Read from file
 */
boolean Acme::ReadAccountInfo() {
  if (account_fn == 0 || filename_prefix == 0) {
    ESP_LOGE(acme_tag, "%s: ACME files not configured", __FUNCTION__);
    return false;
  }
  char *fn = (char *)malloc(strlen(account_fn) + 5 + strlen(filename_prefix));
  sprintf(fn, "%s/%s", filename_prefix, account_fn);

  FILE *f = fopen(fn, "r");
  if (f == NULL) {
    ESP_LOGE(acme_tag, "Could not read account info from %s, %s", fn, strerror(errno));
    free(fn);
    return false;
  }

// Choose wisely
#define	NREAD_INC	250

  // ESP-IDF VFS over SPIFFS doesn't allow use of fseek to determine file length, so read in chunks in that case
  // Potential over-allocation is limited to NREAD_INC bytes
  long len = fseek(f, 0L, SEEK_END);
  if (len == 0) {
    len = NREAD_INC;
    ESP_LOGI(acme_tag, "Reading Account info from %s (in chunks of %d)", fn, NREAD_INC);
  } else
    ESP_LOGI(acme_tag, "Reading Account info from %s (%ld bytes)", fn, len);
  free(fn);

  fseek(f, 0L, SEEK_SET);
  char *buffer = (char *)malloc(len+1);
  size_t total = fread((void *)buffer, 1, len, f);
  buffer[total] = 0;
  int inc = total;
  while (inc == NREAD_INC) {
    len += NREAD_INC;
    buffer = (char *)realloc((void *)buffer, len + 1);
    inc = fread((void *)(buffer + total), 1, NREAD_INC, f);
    total += inc;
    buffer[total] = 0;
    ESP_LOGD(acme_tag, "Reading -> %d bytes, total %d ", inc, total);
  }
  fclose(f);
  ESP_LOGI(acme_tag, "%s: %s", __FUNCTION__, buffer);

  DynamicJsonBuffer jb;
  JsonObject &root = jb.parseObject(buffer);
  if (! root.success()) {
    ESP_LOGE(acme_tag, "%s : could not parse JSON", __FUNCTION__);
    free(buffer);
    return false;
  }
  ESP_LOGD(acme_tag, "%s : JSON opened", __FUNCTION__);
  ReadAccount(root);

  free(buffer);
  return true;
}

void Acme::WriteAccountInfo() {
  if (account == NULL) {
    ESP_LOGE(acme_tag, "%s: NULL account", __FUNCTION__);
    return;
  }

  char *fn = (char *)malloc(strlen(account_fn) + 5 + strlen(filename_prefix));
  sprintf(fn, "%s/%s", filename_prefix, account_fn);
  CreateDirectories(fn);
  FILE *f = fopen(fn, "w");
  if (f == NULL) {
    ESP_LOGE(acme_tag, "Could not write account info into %s, %s", fn, strerror(errno));
    free(fn);
    return;
  }

  ESP_LOGI(acme_tag, "Writing account info into %s", fn);
  free(fn);

  DynamicJsonBuffer jb;
  JsonObject &jo = jb.createObject();
  jo[acme_json_status] = account->status;
  jo[acme_json_location] = account->location;

  // contact array must be NULL terminated
  JsonArray &jca = jo.createNestedArray(acme_json_contact);
  for (int i=0; account->contact[i]; i++)
    jca.add(account->contact[i]);

  JsonObject &jk = jo.createNestedObject(acme_json_key);
  jk[acme_json_kty] = account->key_type;
  jk[acme_json_n] = account->key_id;
  jk[acme_json_e] = account->key_e;

  char *output = (char *)malloc(1536);	// FIX ME
  jo.printTo(output, 1536);		// FIX ME

  fprintf(f, "%s", output);
  fclose(f);
  ESP_LOGI(acme_tag, "Wrote %d bytes of JSON account info", strlen(output));
  ESP_LOGI(acme_tag, "Account info : %s", output);
  free(output);
}

/*
 *
 */
void Acme::RequestNewOrder(const char *url) {
  ClearOrderContent();
  ClearChallenge();
  ESP_LOGI(acme_tag, "%s (%s)", __FUNCTION__, url);
  /*
   * prot :
   *  {"alg": "RS256", "nonce": "webIkLvTEpwjbA9rZSTv8", "kid": "https://acme-staging-v02.api.letsencrypt.org/acme/acct/0123", "url": "https://acme-staging-v02.api.letsencrypt.org/acme/new-order"}
   * pl :
   *  {\n  "identifiers": [\n    {\n      "value": "to.org",\n      "type": "dns"\n    }\n  ]\n}
   * 
   * Sending POST request to https://acme-staging-v02.api.letsencrypt.org/acme/new-order:
   * {
   *   "signature": "CSrJ8AspnxgA4lq6mx43Aiwi-GJxyXw",
   *   "protected": "ovL2FjbWUtc3RhZ2luZy12MDIuYXBpLmxldHNlbmNyeXB0Lm9yZy9hY21lL25ldy1vcmRlciJ9",
   *   "payload": "ewiZG5zIgogICAgfQogIF0KfQ"
   * }
   * 2019-07-31 04:01:52,543:DEBUG:requests.packages.urllib3.connectionpool:https://acme-staging-v02.api.letsencrypt.org:443 "POST /acme/new-order HTTP/1.1" 201 36
   */
  if (directory == 0 || rsa == 0)
    return;

  char *msg;
  char *request = (char *)malloc(strlen(new_order_template) + strlen(url) + 4);
  sprintf(request, new_order_template, url);
  ESP_LOGI(acme_tag, "%s msg %s", __FUNCTION__, request);

  msg = MakeMessageKID(directory->newOrder, request);

  if (! msg) {
    ESP_LOGE(acme_tag, "%s: null message", __FUNCTION__);
    return;
  }
  ESP_LOGD(acme_tag, "%s -> %s", __FUNCTION__, msg);

  char *reply = PerformWebQuery(directory->newOrder, msg, acme_jose_json, 0);
  // free(msg);
  if (reply) {
    ESP_LOGD(acme_tag, "PerformWebQuery -> %s", reply);
  } else {
    ESP_LOGE(acme_tag, "PerformWebQuery -> null");
  }

  // Decode JSON reply
  DynamicJsonBuffer jb;
  JsonObject &root = jb.parseObject(reply);
  if (! root.success()) {
    ESP_LOGE(acme_tag, "%s : could not parse JSON", __FUNCTION__);
    free(reply);
    return;
  }
  ESP_LOGD(acme_tag, "%s : JSON opened", __FUNCTION__);

  const char *reply_status = root[acme_json_status];
  if (reply_status && reply_status[0] == '4') {
    const char *reply_type = root[acme_json_type];
    const char *reply_detail = root[acme_json_detail];

    ESP_LOGE(acme_tag, "%s: failure %s %s %s", __FUNCTION__, reply_status, reply_type, reply_detail);

    free(reply);
    return;
  } else if (reply_status == 0) {
    // ESP_LOGE(acme_tag, "%s: null reply_status", __FUNCTION__);
    ESP_LOGE(acme_tag, "%s: null reply_status (reply %s)", __FUNCTION__, reply);
  } else {
    ESP_LOGE(acme_tag, "%s: reply_status %s", __FUNCTION__, reply_status);
  }

  ReadOrder(root);

  free(reply);
  return;
}

/*
 * Read from file
 */
boolean Acme::ReadOrderInfo() {
  char *fn = (char *)malloc(strlen(order_fn) + 5 + strlen(filename_prefix));
  sprintf(fn, "%s/%s", filename_prefix, order_fn);

  FILE *f = fopen(fn, "r");
  if (f == NULL) {
    if (errno != ENOENT)	// Don't bother telling the file simply isn't there
      ESP_LOGE(acme_tag, "Could not read order info from %s, %s", fn, strerror(errno));
    free(fn);
    return false;
  }

// Choose wisely
#define	NREAD_INC	250

  // ESP-IDF VFS over SPIFFS doesn't allow use of fseek to determine file length, so read in chunks in that case
  // Potential over-allocation is limited to NREAD_INC bytes
  long len = fseek(f, 0L, SEEK_END);
  if (len == 0) {
    len = NREAD_INC;
    ESP_LOGI(acme_tag, "Reading order info from %s (in chunks of %d)", fn, NREAD_INC);
  } else
    ESP_LOGI(acme_tag, "Reading order info from %s (%ld bytes)", fn, len);
  fseek(f, 0L, SEEK_SET);
  free(fn);

  char *buffer = (char *)malloc(len+1);
  size_t total = fread((void *)buffer, 1, len, f);
  int inc = total;
  while (inc == NREAD_INC) {
    len += NREAD_INC;
    buffer = (char *)realloc((void *)buffer, len + 1);
    inc = fread((void *)(buffer + total), 1, NREAD_INC, f);
    total += inc;
    ESP_LOGD(acme_tag, "Reading -> %d bytes, total %d ", inc, total);
  }
  fclose(f);
  buffer[total] = 0;
  ESP_LOGI(acme_tag, "%s: %s", __FUNCTION__, buffer);

  DynamicJsonBuffer jb;
  JsonObject &root = jb.parseObject(buffer);
  if (! root.success()) {
    ESP_LOGE(acme_tag, "%s : could not parse JSON", __FUNCTION__);
    free(buffer);
    return false;
  }

  ESP_LOGD(acme_tag, "%s : JSON opened", __FUNCTION__);
  ReadOrder(root);

  free(buffer);

  // ESP_LOGI(acme_tag, "%s : success", __FUNCTION__);
  if (order->status)
    ESP_LOGI(acme_tag, "%s : success, order status %s", __FUNCTION__, order->status);

  return true;
}

void Acme::WriteOrderInfo() {
  if (order == NULL) {
    ESP_LOGE(acme_tag, "%s: NULL order", __FUNCTION__);
    return;
  }

  char *fn = (char *)malloc(strlen(order_fn) + 5 + strlen(filename_prefix));
  sprintf(fn, "%s/%s", filename_prefix, order_fn);
  CreateDirectories(fn);
  FILE *f = fopen(fn, "w");
  if (f == NULL) {
    ESP_LOGE(acme_tag, "Could write order info into %s, %s", fn, strerror(errno));
    free(fn);
    return;
  }

  ESP_LOGI(acme_tag, "Writing order info into %s", fn);
  free(fn);

  DynamicJsonBuffer jb;
  JsonObject &jo = jb.createObject();
  if (order->status) jo[acme_json_status] = order->status;
  if (order->status) jo[acme_json_expires] = order->expires;
  if (order->finalize) jo[acme_json_finalize] = order->finalize;
  if (order->certificate) jo[acme_json_certificate] = order->certificate;

  if (order->identifiers) {
    // identifiers array must be NULL terminated
    JsonArray &jia = jo.createNestedArray(acme_json_identifiers);
    for (int i=0; order->identifiers[i]._type != 0 || order->identifiers[i].value != 0; i++) {
      JsonObject &jie = jia.createNestedObject();
      jie[acme_json_type] = order->identifiers[i]._type;
      jie[acme_json_value] = order->identifiers[i].value;
    }
  }

  if (order->authorizations) {
    // authorizations array must be NULL terminated
    JsonArray &jaa = jo.createNestedArray(acme_json_authorizations);
    for (int i=0; order->authorizations[i]; i++)
      jaa.add(order->authorizations[i]);
  }

  char *output = (char *)malloc(1536);	// FIX ME
  jo.printTo(output, 1536);		// FIX ME

  fprintf(f, "%s", output);
  fclose(f);
  ESP_LOGI(acme_tag, "Wrote %d bytes of JSON order info", strlen(output));
  ESP_LOGI(acme_tag, "Order info : %s", output);
  free(output);
}

/*
 */
void Acme::ReadOrder(JsonObject &json) {
  // Treat the case separately where we have an empty order structure : it's brand new so no need to free/reallocate
  if (order && order->status != 0)
    ClearOrder();
  if (order == 0) {
    order = (Order *)malloc(sizeof(Order));
    memset((void *)order, 0, sizeof(Order));
  }

/*
 * Replace a single statement such as
 *   account->key_type = strdup(json["key"]["kty"]);
 * by a macro invocation to protect against calling strdup(0) if an element is not in the JSON.
 * C/C++ syntax hint : #x turns the macro argument x into a string.
 */
#define	BZZ(x)									\
  {										\
    const char *x = json[#x];							\
    if (x) {									\
      ESP_LOGD(acme_tag, "%s : read %s as %s", __FUNCTION__, #x, x);		\
      order->x = strdup(x);							\
    } else {									\
      order->x = 0;								\
    }										\
  }

  BZZ(status);
  BZZ(expires);
  BZZ(finalize);
  BZZ(certificate);

  if (order->expires)
    order->t_expires = timestamp(order->expires);

#undef BZZ

  JsonArray &jia = json["identifiers"];
  ESP_LOGD(acme_tag, "%s : %d identifiers", __FUNCTION__, jia.size());
  order->identifiers = (Identifier *)calloc(jia.size()+1, sizeof(Identifier));
  order->identifiers[jia.size()]._type = 0;
  order->identifiers[jia.size()].value = 0;
  for (int i=0; i<jia.size(); i++) {
    const char *it = jia[i]["type"];
    const char *iv = jia[i]["value"];
    order->identifiers[i]._type = strdup(it);
    order->identifiers[i].value = strdup(iv);
  }

  JsonArray &jaa = json["authorizations"];
  ESP_LOGD(acme_tag, "%s : %d authorizations", __FUNCTION__, jaa.size());
  order->authorizations = (char **)calloc(jia.size()+1, sizeof(char *));
  order->authorizations[jaa.size()] = 0;
  for (int i=0; i<jaa.size(); i++) {
    const char *a = jaa[i];
    order->authorizations[i] = strdup(a);
  }
}

// Store a file on an FTP server
boolean Acme::ValidateOrder() {
  ESP_LOGI(acme_tag, "%s", __FUNCTION__);
  char *localfn = 0, *remotefn = 0;

  DownloadAuthorizationResource();

  const char *token = 0;
  http01_ix = -1;
  for (int i=0; challenge && challenge->challenges && challenge->challenges[i].status; i++) {
    if (strcmp(challenge->challenges[i]._type, acme_http_01) == 0) {
      token = challenge->challenges[i].token;
      http01_ix = i;
    }
  }
  if (token == 0) {
    ESP_LOGE(acme_tag, "%s: no %s token found, aborting authorization", __FUNCTION__, acme_http_01);
    return false;
  }
  ESP_LOGD(acme_tag, "%s: token %s", __FUNCTION__, token);

  if (webserver == 0) {
    if (! (ftp_user && ftp_path && ftp_server && ftp_pass)) {
      ESP_LOGI(acme_tag, "%s: failed, incomplete FTP setup", __FUNCTION__);
      return false;
    }

    /*
     * This case uses services from a "site" web server.
     * We use FTP to store and remove files on it.
     *
     * Store the token in a file.
     * Notes : take a single file for two reasons : can't remove it (see below), and the file system
     * doesn't always support file names in the format returned by an ACME server.
     */
    localfn = (char *)malloc(strlen(filename_prefix) + 15);
    sprintf(localfn, "%s/token", filename_prefix);

    if (! CreateValidationFile(localfn, token)) {
      ESP_LOGE(acme_tag, "%s: could not create local validation file %s", __FUNCTION__, localfn);
      free(localfn);
      return false;
    }

    // FTP the file
    remotefn = (char *)malloc(strlen(ftp_path) + strlen(well_known) + strlen(token) + 5);
    sprintf(remotefn, "%s%s%s", ftp_path, well_known, token);

    StoreFileOnWebserver(localfn, remotefn);
  } else {
    /*
     * The IoT device has a local web server.
     * Either this device is "in the wild" or firewall/router/webserver tweaks have been
     * made so it is accessible from the Internet.
     */
    ValidationString = CreateValidationString(token);
    
    // The file name that should be queried is a short form of the above remotefn
    ValidationFile = (char *)malloc(strlen(well_known) + strlen(token) + 2);
    sprintf(ValidationFile, "%s%s", well_known, token);

    EnableLocalWebServer();
  }

  // Alert the server
  boolean r = ValidateAlertServer();

  // Remove the file
  if (webserver != 0) {
    if (r) {
      if (ValidationString) {
        free(ValidationString);
        ValidationString = 0;
      }
      if (ValidationFile) {
        free(ValidationFile);
        ValidationFile = 0;
      }

      if (ws_registered)
        DisableLocalWebServer();
    }
  } else {
    /*
     * FIXME Can't find a API call (except when accessing SPIFFS) to remove a file
     * in the ESP-IDF VFS layer
     *
     * Sometimes this is too soon.
     * Leaving the challenges here makes sure we can pick this up in AcmeProcess() in case
     * of failures, only clean up on success.
     */
    if (r) {
      // Remove the file from FTP server
      RemoveFileFromWebserver(remotefn);

      // Remove our in-memory record
      ClearChallenge();
    }

    free(remotefn);
    free(localfn);
  }
  return r;
}

/*
 * Send a request to the server to read our token
 * We're only implementing the http-01 protocol here...
 */
boolean Acme::ValidateAlertServer() {
  ESP_LOGI(acme_tag, "%s", __FUNCTION__);
  if (http01_ix < 0) {
    ESP_LOGE(acme_tag, "%s: no %s found", __FUNCTION__, acme_http_01);
    return false;
  }

  char *msg = MakeMessageKID(challenge->challenges[http01_ix].url, "{}");

  ESP_LOGD(acme_tag, "%s: query %s message %s", __FUNCTION__, challenge->challenges[http01_ix].url, msg);

  // FIXME only one authorization is picked up
  char *reply = PerformWebQuery(challenge->challenges[http01_ix].url, msg, acme_jose_json, 0);

  free(msg);
  if (reply) {
    ESP_LOGI(acme_tag, "PerformWebQuery -> %s", reply);
  } else {
    ESP_LOGE(acme_tag, "%s: PerformWebQuery -> null", __FUNCTION__);
  }

  // Decode JSON reply
  DynamicJsonBuffer jb;
  JsonObject &root = jb.parseObject(reply);
  if (! root.success()) {
    ESP_LOGE(acme_tag, "%s : could not parse JSON", __FUNCTION__);
    free(reply);
    return false;
  }
  ESP_LOGD(acme_tag, "%s : JSON opened", __FUNCTION__);

  const char *reply_status = root[acme_json_status];
  if (reply_status && reply_status[0] == '4') {
    const char *reply_type = root[acme_json_type];
    const char *reply_detail = root[acme_json_detail];

    ESP_LOGE(acme_tag, "%s: failure %s %s %s", __FUNCTION__, reply_status, reply_type, reply_detail);

    free(reply);
    return false;
  } else if (reply_status == 0) {
    // ESP_LOGE(acme_tag, "%s: null reply_status", __FUNCTION__);
    ESP_LOGE(acme_tag, "%s: null reply_status (reply %s)", __FUNCTION__, reply);
  } else {
    ESP_LOGI(acme_tag, "%s: reply_status %s", __FUNCTION__, reply_status);
  }

  free(reply);

  if (ReadAuthorizationReply(root)) {
    return true;
  } else {
    ESP_LOGE(acme_tag, "%s: failing", __FUNCTION__);
    return false;
  }
}

void Acme::DownloadCertificate() {
  ESP_LOGI(acme_tag, "%s(%s)", __FUNCTION__, order->certificate);

  char *msg = MakeMessageKID(order->certificate, "");

  ESP_LOGI(acme_tag, "%s: PerformWebQuery(%s,%s,%s,%s)", __FUNCTION__, order->certificate, msg, acme_jose_json, acme_accept_pem_chain);

  char *reply = PerformWebQuery(order->certificate, msg, acme_jose_json, acme_accept_pem_chain);

  free(msg);
  if (reply) {
    ESP_LOGI(acme_tag, "PerformWebQuery -> %s", reply);
  } else {
    ESP_LOGE(acme_tag, "%s: PerformWebQuery -> null", __FUNCTION__);
  }

  int fnl = strlen(filename_prefix) + strlen(cert_fn) + 3;
  char *fn = (char *)malloc(fnl);
  sprintf(fn, "%s/%s", filename_prefix, cert_fn);
  FILE *f = fopen(fn, "w");
  if (f) {
    size_t len = strlen(reply);
    size_t fl = fwrite(reply, 1, len, f);
    if (fl != len) {
      ESP_LOGE(acme_tag, "Failed to write certificate to %s, %d of %d written", fn, fl, len);
    } else {
      ESP_LOGI(acme_tag, "Wrote certificate to %s", fn);
    }
    fclose(f);
  } else {
    ESP_LOGE(acme_tag, "Could not open %s to write certificate, error %d (%s)", fn, errno, strerror(errno));
  }
  free(reply);

  if (ws_registered)
    DisableLocalWebServer();

  ReadCertificate();
}

/*
 * Fetch the result of an Authorization. If valid, then we can move ahead with certificate download.
 *
 * We're not storing this info into a structure similar to the message content. Rather, we're
 * using this info to match with our existing Order structure, and update it.
 *
 * {
 *   "type": "http-01",
 *   "status": "valid",
 *   "url": "https://acme-staging-v02.api.letsencrypt.org/acme/chall-v3/28523991/ZQYjMg",
 *   "token": "XNmOzvEOv57hbpXC7kbZMEAjy1HiLT6g_opkKG7XUaY",
 *   "validationRecord": [
 *     {
 *       "url": "http://dannybackx.hopto.org/.well-known/acme-challenge/XNmOzvEOv57hbpXC7kbZMEAjy1HiLT6g_opkKG7XUaY",
 *       "hostname": "dannybackx.hopto.org",
 *       "port": "80",
 *       "addressesResolved": [
 *         "94.224.125.18"
 *       ],
 *       "addressUsed": "94.224.125.18"
 *     }
 *   ]
 * }
 */
boolean Acme::ReadAuthorizationReply(JsonObject &json) {
  const char *status = json[acme_json_status];

  if (strcmp(status, acme_status_valid) != 0) {
    return false;
  }

  free(order->status);
  order->status = strdup(acme_status_ready);	// Important note : advancing our local order to "ready"
  WriteOrderInfo();
  return true;
}

/*
 * Download Authorization Resource
 * See RFC 8555 §7.5
 *
 * This is the file that we'll need to make a available on a WWW server to authenticate our connection to the domain.
 *
 *  POST /acme/authz/PAniVnsZcis HTTP/1.1
 *    Host: example.com
 *    Content-Type: application/jose+json
 * 
 *    {
 *      "protected": base64url({
 *        "alg": "ES256",
 *        "kid": "https://example.com/acme/acct/evOfKhNU60wg",
 *        "nonce": "uQpSjlRb4vQVCjVYAyyUWg",
 *        "url": "https://example.com/acme/authz/PAniVnsZcis"
 *      }),
 *      "payload": "",
 *      "signature": "nuSDISbWG8mMgE7H...QyVUL68yzf3Zawps"
 *    }
 */
void Acme::DownloadAuthorizationResource() {
  ESP_LOGI(acme_tag, "%s", __FUNCTION__);
  if (order == 0 || order->authorizations == 0 || order->authorizations[0] == 0) {
    ESP_LOGE(acme_tag, "%s: null", __FUNCTION__);
    return;
  }

  char *msg = MakeMessageKID(order->authorizations[0], "");

  ESP_LOGD(acme_tag, "%s: query %s message %s", __FUNCTION__, order->authorizations[0], msg);

  // FIXME only one authorization is picked up
  char *reply = PerformWebQuery(order->authorizations[0], msg, acme_jose_json, 0);

  free(msg);
  if (reply) {
    ESP_LOGI(acme_tag, "PerformWebQuery -> %s", reply);
  } else {
    ESP_LOGE(acme_tag, "%s: PerformWebQuery -> null", __FUNCTION__);
  }

  // Decode JSON reply
  DynamicJsonBuffer jb;
  JsonObject &root = jb.parseObject(reply);
  if (! root.success()) {
    ESP_LOGE(acme_tag, "%s : could not parse JSON", __FUNCTION__);
    free(reply);
    return;
  }
  ESP_LOGD(acme_tag, "%s : JSON opened", __FUNCTION__);

  const char *reply_status = root[acme_json_status];
  if (reply_status && reply_status[0] == '4') {
    const char *reply_type = root[acme_json_type];
    const char *reply_detail = root[acme_json_detail];

    ESP_LOGE(acme_tag, "%s: failure %s %s %s", __FUNCTION__, reply_status, reply_type, reply_detail);

    free(reply);
    return;
  } else if (reply_status == 0) {
    // ESP_LOGE(acme_tag, "%s: null reply_status", __FUNCTION__);
    ESP_LOGE(acme_tag, "%s: null reply_status (reply %s)", __FUNCTION__, reply);
  } else {
    ESP_LOGD(acme_tag, "%s: reply_status %s", __FUNCTION__, reply_status);
  }

  ReadChallenge(root);
  free(reply);
}

/*
 * RFC 7638 describes the JSON Web Key (JWK) Thumbprint
 */
char *Acme::JWSThumbprint() {
  int err;

  int ne = 4;						// E will be at the rear end of this array
  unsigned char	E[4];
  int nl = mbedtls_rsa_get_len(rsa);
  unsigned char *N = (unsigned char *)malloc(nl);	// Allocate exactly long enough, don't add one more for trailing 0.

  if ((err = mbedtls_rsa_export_raw(rsa, N, nl, /* P */ 0, 0, /* Q */ 0, 0, /* D */ 0, 0, E, ne)) != 0) {
    char buf[80];
    mbedtls_strerror(err, buf, sizeof(buf));
    ESP_LOGE(acme_tag, "%s: failed rsa_export_raw %d %s", __FUNCTION__, err, buf);
    return 0;
  }

  // E is at the rear end of this array, point q to it
  char *q = (char *)E;
  for (; *q == 0; q++,ne--);			// Skip initial zeroes

  // ESP_LOGI(acme_tag, "RSA key N : %s", N);
  char *n64 = Base64((char *)N, nl);
  char *e64 = Base64((char *)q, ne);
  ESP_LOGI(acme_tag, "RSA key E(64) : %s, N(64) : %s", e64, n64);

  // White-space-less JWK format, as described.
  // Don't change this even a little bit
  const char *format = "{\"e\":\"%s\",\"kty\":\"RSA\",\"n\":\"%s\"}";

  char *t = (char *)malloc(strlen(format) + 2 * nl + ne + 4);		// hack : 2*, otherwise crash due to alloc(280), but use 370
  sprintf(t, format, e64, n64);
  free(N);
  free(n64);
  free(e64);

  int hash_size = 32;
  unsigned char *hash = (unsigned char *)calloc(1, hash_size);
  if (hash == 0) {
    ESP_LOGE(acme_tag, "calloc(32) failed");
    free(t);
    return 0;
  }

  const mbedtls_md_info_t *mdi = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  if (!mdi) {
    ESP_LOGE("Acme", "mbedtls_md_info_from_type: md_info not found");
    free(hash);
    free(t);
    return 0;
  }

  int ret = mbedtls_md(mdi, (const unsigned char *)t, strlen(t), (unsigned char *)hash);
  free(t); t = 0;
  if (ret != 0) {
    char buf[80];
    mbedtls_strerror(ret, buf, sizeof(buf));
    ESP_LOGE(acme_tag, "mbedtls_md failed %s (0x%04x)", buf, -ret);
    free(hash);
    return 0;
  }

  char *r = Base64((char *)hash, hash_size);
  free(hash);
  return r;
}

// Create it locally
bool Acme::CreateValidationFile(const char *localfn, const char *token) {
  FILE *tf = fopen(localfn, "w");
  if (! tf) {
    ESP_LOGE(acme_tag, "%s: could not create %s, %s", __FUNCTION__, localfn, strerror(errno));
    return false;
  }

  char *tp = JWSThumbprint();
  fprintf(tf, "%s.%s\n", token, tp);
  free(tp);

  fclose(tf);
  return true;
}

// For use by the local web server
char *Acme::CreateValidationString(const char *token) {
  char *tp = JWSThumbprint();
  int len = strlen(token) + strlen(tp) + 4;
  char *r = (char *)malloc(len);
  sprintf(r, "%s.%s\n", token, tp);
  return r;					// Caller must free
}

void Acme::ReadChallenge(JsonObject &json) {
  challenge = (Challenge *)malloc(sizeof(Challenge));
  memset((void *)challenge, 0, sizeof(Challenge));

/*
 * Replace a single statement such as
 *   account->key_type = strdup(json["key"]["kty"]);
 * by a macro invocation to protect against calling strdup(0) if an element is not in the JSON.
 * C/C++ syntax hint : #x turns the macro argument x into a string.
 */
#define	BZZ(x)									\
  {										\
    const char *x = json[#x];							\
    if (x) {									\
      ESP_LOGI(acme_tag, "%s : read %s as %s", __FUNCTION__, #x, x);		\
      challenge->x = strdup(x);							\
    } else {									\
      challenge->x = 0;								\
    }										\
  }

  BZZ(status);
  BZZ(expires);

  challenge->t_expires = timestamp(challenge->expires);

#undef BZZ

  // we're not reading the identifier, as we're not using it

  JsonArray &jca = json["challenges"];
  ESP_LOGD(acme_tag, "%s : %d challenges", __FUNCTION__, jca.size());
  challenge->challenges = (ChallengeItem *)calloc(jca.size()+1, sizeof(ChallengeItem));
  // Null-terminate
  challenge->challenges[jca.size()]._type = 0;
  challenge->challenges[jca.size()].status = 0;
  challenge->challenges[jca.size()].url = 0;
  challenge->challenges[jca.size()].token = 0;
  for (int i=0; i<jca.size(); i++) {
    const char *ct = jca[i][acme_json_type];
    const char *cs = jca[i][acme_json_status];
    const char *cu = jca[i][acme_json_url];
    const char *ck = jca[i][acme_json_token];

    challenge->challenges[i]._type = strdup(ct);
    challenge->challenges[i].status = strdup(cs);
    challenge->challenges[i].url = strdup(cu);
    challenge->challenges[i].token = strdup(ck);
  }
}

/*
 * Make an ACME message, this version makes the ones that include a "kid" field.
 *
 * Some of the relevant parts of RFC 8555 (§6.2) :
 *   It must have the fields "alg", "nonce", "url", and either "jwk" or "kid".
 *   newAccount and revokeCert messages must use jwk, this field must contain the public key
 *   corresponding to the private key used to sign the JWS.
 *   All other requests are signed using an existing account, and there must be a kid field
 *   which contains the account URL received by POSTing to newAcount.
 *
 * So this must be used in calls to RequestNewOrder, ... .
 * but especially not in calls to newAccount or revokeCert.
 *
 * {"url": "https://acme-staging-v02.api.letsencrypt.org/acme/new-acct", "jwk": {"kty": "RSA",
 *  "n": "...", "e": "AQAB"}, "alg": "RS256", "nonce": "U8b_2ZGRATuySa9yPOF3JDN4JXTyEdAfrL--WTzqYKQ"}
 */
char *Acme::MakeMessageKID(const char *url, const char *payload) {
  ESP_LOGI(acme_tag, "%s(%s,%s)", __FUNCTION__, url, payload);

  char *prot = MakeProtectedKID(url);
  if (prot == 0)
    return 0;

  ESP_LOGD(acme_tag, "PR %s", prot);
  String pr = Base64(prot);
  String pl = Base64(payload);
  String sig = Signature(pr, pl);

  String js = String("{\n  \"protected\": \"") + pr + "\",\n  \"payload\": \"" + pl + "\",\n  \"signature\": \"" + sig + "\"\n}";
  free(prot);

  return strdup(js.c_str());
}

void Acme::SetAcmeUserAgentHeader(esp_http_client_handle_t client) {
  int err;

  char *acme_agent_value = (char *)malloc(strlen(acme_agent_template) + strlen(esp_get_idf_version()) + 10);
  sprintf(acme_agent_value, acme_agent_template, esp_get_idf_version());
  if ((err = esp_http_client_set_header(client, acme_agent_header, acme_agent_value)) != ESP_OK) {
    ESP_LOGE(acme_tag, "%s: client_set_header(%s=%s) error %d %s", __FUNCTION__, acme_agent_header, acme_agent_value, err, esp_err_to_name(err));
    // Don't fail on this.
  } else {
    ESP_LOGD(acme_tag, "%s: client_set_header(%s=%s)", __FUNCTION__, acme_agent_header, acme_agent_value);
  }
  free(acme_agent_value);
}

/*
 * This will be the protected field in the JSON
 *
 * {"alg": "RS256", "nonce": "webISTv8", "kid": "https://acme-staging-v02.api.letsencrypt.org/acme/acct/012", "url": "https://acme-staging-v02.api.letsencrypt.org/acme/new-order"}
 */
char *Acme::MakeProtectedKID(const char *query) {
  if (account->location == 0 || nonce == 0)
    return 0;

  const char *acme_protected_template = "{\"alg\": \"RS256\", \"nonce\": \"%s\", \"url\": \"%s\", \"kid\": \"%s\"}";
  char *request = (char *)malloc(strlen(acme_protected_template) + strlen(query) + strlen(nonce) + strlen(account->location) + 4);
  sprintf(request, acme_protected_template, nonce, query, account->location);

  return request;
}

/*
 * Perform a query
 *
 * Post the topost data.
 */
char *Acme::PerformWebQuery(const char *query, const char *topost, const char *apptype, const char *accept_message) {
  esp_err_t			err;
  esp_http_client_config_t	httpc;
  esp_http_client_handle_t	client;
  char				*buf;
  int				pos, total, rlen, content_length;

  ESP_LOGD(acme_tag, "%s(%s, POST %s, type %s)", __FUNCTION__, query,
    topost ? topost : "null",
    apptype ? apptype : "null");

  memset(&httpc, 0, sizeof(httpc));
  httpc.url = query;
  httpc.event_handler = HttpEvent;
  client = esp_http_client_init(&httpc);

  if (reply_buffer)
    free(reply_buffer);
  reply_buffer = 0;
  reply_buffer_len = 0;

  if (topost) {
    err = esp_http_client_set_post_field(client, topost, strlen(topost));
    if (err != ESP_OK) {
      ESP_LOGE(acme_tag, "%s: set_post_field error %d %s", __FUNCTION__, err, esp_err_to_name(err));
      esp_http_client_cleanup(client);
      return 0;
    } else
      ESP_LOGD(acme_tag, "%s: set_post_field length %d", __FUNCTION__, strlen(topost));

    // Do a POST query if we're posting data.
    if ((err = esp_http_client_set_method(client, HTTP_METHOD_POST)) != ESP_OK) {
      ESP_LOGE(acme_tag, "%s: client_set_method error %d %s", __FUNCTION__, err, esp_err_to_name(err));
      esp_http_client_cleanup(client);
      return 0;
    }
  }

  SetAcmeUserAgentHeader(client);

  const char *at = apptype ? apptype : "application/json";
  if ((err = esp_http_client_set_header(client, acme_content_type, at)) != ESP_OK) {
    ESP_LOGE(acme_tag, "%s: client_set_header(%s=%s) error %d %s", __FUNCTION__, acme_content_type, at, err, esp_err_to_name(err));
    // Don't fail on this.
  } else {
    ESP_LOGD(acme_tag, "Client_set_header(%s=%s)", acme_content_type, at);
  }

  // When this parameter is supplied, the "Accept:" is implied
  if (accept_message) {
    if ((err = esp_http_client_set_header(client, acme_accept_header, accept_message)) != ESP_OK) {
      ESP_LOGE(acme_tag, "%s: client_set_header(%s=%s) error %d %s", __FUNCTION__, acme_accept_header, accept_message, err, esp_err_to_name(err));
      // Don't fail on this.
    } else {
      ESP_LOGI(acme_tag, "Client_set_header(%s=%s)", acme_accept_header, accept_message);
    }
  }

  if (topost) {
    // Need to use esp_http_client_perform() because esp_http_client_open() doesn't call esp_http_client_send_post_data() and
    // that's a static function so we can't call it ourselves.
    err = esp_http_client_perform(client);

    // Ok, now the data has been captured in Acme::HttpEvent, just pass it on and finish up.
    ESP_LOGD(acme_tag, "%s -> %s", __FUNCTION__, buf);

    esp_http_client_close(client);
    esp_http_client_cleanup(client);

    // Buffer will get freed after this, so lose its length indication
    reply_buffer_len = 0;
    char *tmp = reply_buffer;
    reply_buffer = 0;

    return tmp;
  } else {
    err = esp_http_client_open(client, 0);

    if (err != ESP_OK) {
      ESP_LOGE(acme_tag, "%s: client_open error %d %s", __FUNCTION__, err, esp_err_to_name(err));
      esp_http_client_cleanup(client);
      return 0;
    }
    if ((content_length = esp_http_client_fetch_headers(client)) < 0) {
      ESP_LOGE(acme_tag, "%s: fetch_headers error %d %s", __FUNCTION__, err, esp_err_to_name(err));
      esp_http_client_cleanup(client);
      return 0;
    }
    buf = (char *)malloc(content_length + 1);
    if (buf == 0) {
      ESP_LOGE(acme_tag, "%s: malloc error %d %s", __FUNCTION__, err, esp_err_to_name(err));
      esp_http_client_cleanup(client);
      return 0;
    }
    pos = 0; total = 0; rlen = 0;
    while (total < content_length && err == ESP_OK) {
      rlen = esp_http_client_read(client, buf + pos, content_length - total);
      if (rlen < 0) {
        ESP_LOGE(acme_tag, "%s: read error %d %s", __FUNCTION__, err, esp_err_to_name(err));
        free(buf);
        esp_http_client_cleanup(client);
        return 0;
      }
      buf[rlen] = 0;
      pos += rlen;
      total += rlen;
    }
  }

  ESP_LOGD(acme_tag, "%s -> %s", __FUNCTION__, buf);

  esp_http_client_close(client);
  esp_http_client_cleanup(client);

  return buf;
}

/*
 * This function catches HTTP headers (two of which we trap), and data sent to us as replies.
 * We gatter the latter in the reply_buffer field, whose alloc/free is rather sensitive.
 */
esp_err_t Acme::HttpEvent(esp_http_client_event_t *event) {
  switch (event->event_id) {
  case HTTP_EVENT_ON_HEADER:
    ESP_LOGD("Acme", "%s: header %s value %s", __FUNCTION__, event->header_key, event->header_value);
    if (strcmp(event->header_key, acme_nonce_header) == 0)
      acme->setNonce(event->header_value);
    else if (strcmp(event->header_key, acme_location_header) == 0)
      acme->setLocation(event->header_value);
    break;
  case HTTP_EVENT_ON_DATA:
    ESP_LOGD("Acme", "%s HTTP_EVENT_ON_DATA (len %d)", __FUNCTION__, event->data_len);
    if (acme->reply_buffer_len == 0) {
      acme->reply_buffer_len = event->data_len;
      acme->reply_buffer = (char *)malloc(event->data_len + 1);
      strncpy(acme->reply_buffer, (const char *)event->data, event->data_len);
      acme->reply_buffer[event->data_len] = 0;
    } else {
      int oldlen = acme->reply_buffer_len;

      acme->reply_buffer_len += event->data_len;
      acme->reply_buffer = (char *)realloc(acme->reply_buffer, acme->reply_buffer_len + 1);
      strncpy(acme->reply_buffer + oldlen, (const char *)event->data, event->data_len);
      acme->reply_buffer[acme->reply_buffer_len] = 0;
    }
    // ESP_LOGD("Acme", "%s: received %s", __FUNCTION__, acme->reply_buffer);
    break;
  default:
    break;
  }
  return ESP_OK;
}

/*
 * We're using https://github.com/JohnnyB1290/ESP32-FTP-Client .
 * This is a port of FTPlib (https://nbpfaus.net/~pfau/ftplib/)
 * Docs see https://nbpfaus.net/~pfau/ftplib/ftplib.html
 *
 * Note web server settings need to allow read access to these files.
 * In some cases, adding "-u 002" to the ftpd command helps in setting its umask so this works.
 *
 * Example : such a line in /etc/inetd.conf :
 * ftp     stream  tcp6    nowait  root    /usr/sbin/ftpd  ftpd -u 002
 *
 */
void Acme::StoreFileOnWebserver(char *localfn, char *remotefn) {
  NetBuf_t	*nb = 0;

  if (! (ftp_user && ftp_path && ftp_server && ftp_pass)) {
    ESP_LOGI(acme_tag, "%s: failed, incomplete setup", __FUNCTION__);
    return;
  }
  ESP_LOGI(acme_tag, "%s(%s,%s)", __FUNCTION__, localfn, remotefn);

  FtpClient	*ftpc = getFtpClient();
  ftpc->ftpClientConnect(ftp_server, 21, &nb);
  ftpc->ftpClientLogin(ftp_user, ftp_pass, nb);
  if (remotefn[0] != '/') {
    int len = strlen(remotefn) + strlen(ftp_path) + 4;
    char *b = (char *)malloc(len);
    sprintf(b, "%s/%s", ftp_path, remotefn);
    ftpc->ftpClientPut(localfn, b, FTP_CLIENT_BINARY, nb);
    free(b);
  } else {
    ftpc->ftpClientPut(localfn, remotefn, FTP_CLIENT_BINARY, nb);
  }
  ftpc->ftpClientQuit(nb);
}

void Acme::RemoveFileFromWebserver(char *remotefn) {
  NetBuf_t	*nb = 0;

  if (! (ftp_user && ftp_path && ftp_server && ftp_pass)) {
    ESP_LOGI(acme_tag, "%s: failed, incomplete setup", __FUNCTION__);
    return;
  }
  ESP_LOGI(acme_tag, "%s(%s)", __FUNCTION__, remotefn);

  FtpClient	*ftpc = getFtpClient();
  ftpc->ftpClientConnect(ftp_server, 21, &nb);
  ftpc->ftpClientLogin(ftp_user, ftp_pass, nb);
  if (remotefn[0] != '/') {
    int len = strlen(remotefn) + strlen(ftp_path) + 4;
    char *b = (char *)malloc(len);
    sprintf(b, "%s/%s", ftp_path, remotefn);
    ftpc->ftpClientDelete(b, nb);
    free(b);
  } else {
    ftpc->ftpClientDelete(remotefn, nb);
  }
  ftpc->ftpClientQuit(nb);
}

void Acme::OrderRemove(char *dir) {
  ClearOrder();

  if (order_fn == 0)
    return;

  ESP_LOGI(acme_tag, "%s(%s,%s)", __FUNCTION__, dir, order_fn);

  int err = unlink(dir);
  if (err == ESP_OK)
    ESP_LOGI(acme_tag, "Removed %s", order_fn);
  else
    ESP_LOGE(acme_tag, "Failed to remove %s", order_fn);
}

void Acme::CertificateDownload() {
  DownloadCertificate();
}

/*
 * A Certificate Signing Request (CSR) is a required parameter to the Finalize query.
 * It can be used to add administrative data to the process, and is validated thoroughly.
 * One such additional parameter is the domain private key.
 */
char *Acme::GenerateCSR() {
  const int buflen = 4096;	// This is used in mbedtls_x509 functions internally
  int ret;

  mbedtls_x509write_csr	req;
  memset(&req, 0, sizeof(req));
  mbedtls_x509write_csr_init(&req);

  mbedtls_x509write_csr_set_md_alg(&req, MBEDTLS_MD_SHA256);
  // mbedtls_x509write_csr_set_key_usage(&req, MBEDTLS_X509_NS_CERT_TYPE_SSL_CLIENT);	// Not set by default
  mbedtls_x509write_csr_set_key(&req, certkey);

  // Specify our URL, as the "common name" field.
  int snlen = strlen(acme_url) + 4;
  char *sn = (char *)malloc(snlen);
  sprintf(sn, "CN=%s", acme_url);
  ret = mbedtls_x509write_csr_set_subject_name(&req, sn);
  if (ret != 0) {
    char buf[80];
    mbedtls_strerror(ret, buf, sizeof(buf));
    ESP_LOGE(acme_tag, "%s: mbedtls_x509write_csr_set_subject_name failed %s (0x%04x)", __FUNCTION__, buf, -ret);
    mbedtls_x509write_csr_free(&req);
    free(sn);
    return 0;
  }

  unsigned char *buffer = (unsigned char *)malloc(buflen);
  memset(buffer, 0, buflen);

  // RFC 8555 §7.4 says write in (base64url-encoded) DER format
  int len = mbedtls_x509write_csr_der(&req, buffer, buflen, mbedtls_ctr_drbg_random, ctr_drbg);
  if (len < 0) {
    char buf[80];
    mbedtls_strerror(ret, buf, sizeof(buf));
    ESP_LOGE(acme_tag, "%s: mbedtls_x509write_csr_der failed %s (0x%04x)", __FUNCTION__, buf, -ret);
    mbedtls_x509write_csr_free(&req);
    free((void *)buffer);
    free(sn);
    return 0;
  }

  // output is written at the end of the buffer, so point to it
  char *p = ((char *)buffer) + buflen - len;
  char *csr = Base64(p, len);

  free((void *)buffer);
  free(sn);
  mbedtls_x509write_csr_free(&req);

  return csr;
}

/*
 * Move the Order from "ready" to "pending" or "valid" state.
 *
 * This step requires passing the CSR, and will cause the ACME server to generate a certificate.
 * One of the results of this query is a URL for the certificate, which we can then use to download it.
 *
 * We're calling ReadFinalizeReply() at the end, but this is the same as ReadOrder().
 */
void Acme::FinalizeOrder() {
  if (order == 0 || order->finalize == 0) {
    ESP_LOGE(acme_tag, "%s: null", __FUNCTION__);
    return;
  }
  ESP_LOGI(acme_tag, "%s(%s)", __FUNCTION__, order->finalize);

  if (certkey == 0) {
    ReadCertKey();
    if (certkey == 0) {
      ESP_LOGE(acme_tag, "%s: can't proceed without certificate private key", __FUNCTION__);
      return;
    }
  }

  char *csr = GenerateCSR();
  int csrlen = strlen(csr) + strlen(csr_format) + 5;
  char *csr_param = (char *)malloc(csrlen);
  sprintf(csr_param, csr_format, csr);
  free(csr);
  char *msg = MakeMessageKID(order->finalize, csr_param);
  ESP_LOGD(acme_tag, "%s : msg %s", __FUNCTION__, msg);

  char *reply = PerformWebQuery(order->finalize, msg, acme_jose_json, 0);
  free(csr_param);

  free(msg);
  if (reply) {
    ESP_LOGI(acme_tag, "%s: PerformWebQuery -> %s", __FUNCTION__, reply);
  } else {
    ESP_LOGE(acme_tag, "%s: PerformWebQuery -> null", __FUNCTION__);
  }

  // Decode JSON reply
  DynamicJsonBuffer jb;
  JsonObject &root = jb.parseObject(reply);
  if (! root.success()) {
    ESP_LOGE(acme_tag, "%s : could not parse JSON", __FUNCTION__);
    free(reply);
    return;
  }
  ESP_LOGD(acme_tag, "%s : JSON opened", __FUNCTION__);

  const char *reply_status = root[acme_json_status];
  if (reply_status && reply_status[0] == '4') {
    const char *reply_type = root[acme_json_type];
    const char *reply_detail = root[acme_json_detail];

    ESP_LOGE(acme_tag, "%s: failure %s %s %s", __FUNCTION__, reply_status, reply_type, reply_detail);

    free(reply);
    return;
  } else if (reply_status == 0) {
    // ESP_LOGE(acme_tag, "%s: null reply_status", __FUNCTION__);
    ESP_LOGE(acme_tag, "%s: null reply_status (reply %s)", __FUNCTION__, reply);
  } else {
    ESP_LOGD(acme_tag, "%s: reply_status %s", __FUNCTION__, reply_status);
  }

  ReadFinalizeReply(root);
  free(reply);
}

void Acme::ReadFinalizeReply(JsonObject &json) {
  ReadOrder(json);
}

/*
 * Convert timestamp from ACME (e.g. 2019-11-25T16:56:52Z) into time_t.
 */
time_t Acme::timestamp(const char *ts) {
  const char *acme_timestamp = "%FT%TZ";
  struct tm tms;
  char *r = strptime(ts, acme_timestamp, &tms);
  if (r == 0 || *r != 0)
    return 0;	// Failed to scan
  return mktime(&tms);
}

/*
 * Read the certificate on local storage
 */
void Acme::ReadCertificate() {
  if (filename_prefix == 0 || cert_fn == 0) {
    ESP_LOGE(acme_tag, "%s fail, no file name", __FUNCTION__);
    return;
  }

  int fnl = strlen(filename_prefix) + strlen(cert_fn) + 3;
  char *fn = (char *)malloc(fnl);
  sprintf(fn, "%s/%s", filename_prefix, cert_fn);

  certificate = (mbedtls_x509_crt *)calloc(1, sizeof(mbedtls_x509_crt));
  mbedtls_x509_crt_init(certificate);
  int ret = mbedtls_x509_crt_parse_file(certificate, fn);
  if (ret == 0) {
    ESP_LOGI(acme_tag, "%s: we have a certificate in %s", __FUNCTION__, fn);
    ESP_LOGI(acme_tag, "Valid from %04d-%02d-%02d %02d:%02d:%02d to %04d-%02d-%02d %02d:%02d:%02d",
      certificate->valid_from.year, certificate->valid_from.mon, certificate->valid_from.day,
      certificate->valid_from.hour, certificate->valid_from.min, certificate->valid_from.sec,
      certificate->valid_to.year, certificate->valid_to.mon, certificate->valid_to.day,
      certificate->valid_to.hour, certificate->valid_to.min, certificate->valid_to.sec);
#if 1
    time_t vt = TimeMbedToTimestamp(certificate->valid_to);
    struct tm *tmp = gmtime(&vt);

    char x[40];
    strftime(x, 40, "%FT%TZ", tmp);
    ESP_LOGI(acme_tag, "Valid to (converted) : %s", x);
#endif
    return;
  }

  if (ret != MBEDTLS_ERR_PK_FILE_IO_ERROR) {	/* Only print unexpected errors, a non-existing certificate file isn't. */
    char buf[80];
    mbedtls_strerror(ret, buf, sizeof(buf));
    ESP_LOGE(acme_tag, "%s: could not read certificate from %s (error 0x%04x, %s)", __FUNCTION__, fn, -ret, buf);
  }
  mbedtls_x509_crt_free(certificate);
  free(certificate);
  certificate = 0;
}

boolean Acme::HaveValidCertificate() {
  struct timeval now;
  gettimeofday(&now, 0);

  return HaveValidCertificate(now.tv_sec);
}

boolean Acme::HaveValidCertificate(time_t now) {
  if (certificate == 0)
    return false;
  if (now < 1000)
    return true;	// No false alarms based on invalid time

  // Check date ranges
  time_t vf = TimeMbedToTimestamp(certificate->valid_from);
  if (now < vf) {
    ESP_LOGE(acme_tag, "Certificate is not valid yet");
    ESP_LOGE(acme_tag, "Certificate is not valid yet : %ld < %ld", now, vf);
    return false;
  }

  time_t vt = TimeMbedToTimestamp(certificate->valid_to);
  if (vt < now) {
    ESP_LOGE(acme_tag, "Certificate has expired");
    return false;
  }

  return true;
}

/*
 * Convert from mbedtls_x509_time to time_t
 * FIX ME not sure if the hour is right
 */
time_t Acme::TimeMbedToTimestamp(mbedtls_x509_time t) {
  struct tm tms;
  tms.tm_year = t.year - 1900;
  tms.tm_mon = t.mon - 1;
  tms.tm_mday = t.day;
  tms.tm_hour = t.hour;
  tms.tm_min = t.min;
  tms.tm_sec = t.sec;
  tms.tm_isdst = false;

  return mktime(&tms);
}

/*
 * RFC 8555 §7.4.2 :
 *  If the client wishes to obtain a renewed certificate, the client initiates a new order process to request one.
 *
 * This implies that we reuse existing code, but make sure that it can work while we have an existing certificate,
 * and replacing the old with the new only happens when the new certificate is successfully downloaded.
 */
void Acme::RenewCertificate() {
  ESP_LOGI(acme_tag, "%s", __FUNCTION__);
  CreateNewOrder();
  WriteOrderInfo();
}

mbedtls_x509_crt *Acme::getCertificate() {
  return certificate;
}

void Acme::setUrl(const char *fn) {
  acme_url = fn;
}

void Acme::setEmail(const char *fn) {
  email_address = fn;
}

void Acme::setAcmeServer(const char *fn) {
  acme_server_url = fn;
}

void Acme::setAccountFilename(const char *fn) {
  account_fn = fn;
}

void Acme::setAccountKeyFilename(const char *fn) {
  account_key_fn = fn;
  // ReadAccountKey();
}

void Acme::setOrderFilename(const char *fn) {
  order_fn = fn;
}

void Acme::setCertKeyFilename(const char *fn) {
  cert_key_fn = fn;
  // ReadCertKey();
}

void Acme::setCertificateFilename(const char *fn) {
  cert_fn = fn;
  ReadCertificate();
}

void Acme::setFilenamePrefix(const char *fn) {
  filename_prefix = fn;
}

void Acme::ReadAccountKey() {
  if (account_key_fn && (accountkey = ReadPrivateKey(account_key_fn))) {
    rsa = mbedtls_pk_rsa(*accountkey);
  }
}

void Acme::ReadCertKey() {
  if (cert_key_fn)
    certkey = ReadPrivateKey(cert_key_fn);
}

void Acme::setFtpServer(const char *s) {
  ftp_server = s;
}

void Acme::setFtpUser(const char *s) {
  ftp_user = s;
}

void Acme::setFtpPassword(const char *s) {
  ftp_pass = s;
}

void Acme::setFtpPath(const char *s) {
  ftp_path = s;
}

void Acme::setWebServer(httpd_handle_t ws) {
  webserver = ws;
}

/*
 * This is - intentionally - a simplistic HTTP GET handler.
 * It just knows how to return the data that the ACME protocol requires.
 *
 * Other HTTP requests should be serviced by possibly more intelligent handlers
 * in the application.
 */
esp_err_t Acme::acme_http_get_handler(httpd_req_t *req) {
  if (strcmp(req->uri, acme->ValidationFile) == 0) {
    ESP_LOGI(acme_tag, "%s: URI %s", __FUNCTION__, req->uri);
    httpd_resp_set_type(req, "text/plain");
    httpd_resp_send(req, acme->ValidationString, strlen(acme->ValidationString));
  } else {
    ESP_LOGE(acme_tag, "%s: URI %s -> 404", __FUNCTION__, req->uri);
    httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, acme_http_404);
  }

  return ESP_OK;
}

void Acme::EnableLocalWebServer() {
  httpd_uri_t	wsconf;
  esp_err_t	err;

  if (webserver == 0) {
    ESP_LOGE(acme_tag, "%s: internal error, webserver = 0", __FUNCTION__);
    return;
  }

  if (ws_registered && (ovf != NULL)) {
    // old ValidationFile
    httpd_unregister_uri_handler(webserver, ovf, HTTP_GET);
    free(ovf);
    ovf = NULL;
  }

  // wsconf.uri = "/.well-known/acme-challenge/*";
  wsconf.uri = ValidationFile;
  wsconf.method = HTTP_GET;
  wsconf.handler = acme_http_get_handler;

  if ((err = httpd_register_uri_handler(webserver, &wsconf)) != ESP_OK) {
    ESP_LOGE(acme_tag, "%s : failed to register URI handler for %s (%d %s)",
      __FUNCTION__, wsconf.uri, err, esp_err_to_name(err));
  } else {
    ESP_LOGI(acme_tag, "%s(%s)", __FUNCTION__, wsconf.uri);
    ws_registered = true;
    ovf = strdup(wsconf.uri);
  }
}

void Acme::DisableLocalWebServer() {
  if (webserver == 0 || ovf == 0 || !ws_registered) {
    ESP_LOGE(acme_tag, "%s: failed 0", __FUNCTION__);
    return;
  }

  // Note this only works if ValidateFile isn't changed between invocations...
  httpd_unregister_uri_handler(webserver, ovf, HTTP_GET);
  free(ovf);
  ovf = NULL;
  ws_registered = false;

  ESP_LOGI(acme_tag, "%s: disabled local web server", __FUNCTION__);
}
