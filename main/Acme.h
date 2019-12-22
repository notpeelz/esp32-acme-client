/*
 * This module implements the ACME (Automated Certicifate Management Environment) protocol.
 * A client for Let's Encrypt (https://letsencrypt.org).
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


#ifndef	_ACME_H_
#define	_ACME_H_

#include <ArduinoJson.h>

#include <sys/socket.h>
#include <esp_event_loop.h>
#include <esp_http_client.h>

#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/certs.h"
#include "mbedtls/x509.h"
#include "mbedtls/ssl.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/error.h"
#include "mbedtls/rsa.h"
#include "mbedtls/sha256.h"

class Acme {
  public:
    Acme();
    ~Acme();

    void NetworkConnected(void *ctx, system_event_t *event);
    void NetworkDisconnected(void *ctx, system_event_t *event);

    void loop(time_t now);

    void OrderRemove(char *);
    void OrderStart();
    void ChallengeStart();

    struct Certificate {
      char *fullchain;
      char *privkey;
      char *chain;
      char *cert;
    };

    Certificate *issueCertificate(char *domain);

    void setNonce(char *);
    void setLocation(const char *);

  private:
    const char *acme_tag = "Acme";

    //
    const char *acme_agent_header = "User-Agent";
    const char *acme_agent_template = "EspAlarm ACME client/0.1, built on esp-idf %s";
    const char *acme_jwk_template = "{\"kty\": \"RSA\", \"n\": \"%s\", \"e\": \"%s\"}";
    const char *acme_espalarm_http_header = "";
    const char *acme_content_type = "Content-Type";
    // const char *new_account_template = "{\n  \"termsOfServiceAgreed\": true,\n  \"contact\": [\n    \"%s\"\n  ]\n}";
    const char *new_account_template =
      "{\n  \"termsOfServiceAgreed\": true,\n  \"contact\": [\n    \"%s\"\n  ],\n  \"onlyReturnExisting\": %s\n}";
    const char *new_account_template_no_email = "{\n  \"termsOfServiceAgreed\": true,\n  \"resource\": [\n    \"new-reg\"\n  ]\n}";

    // const char *server_uri = "https://acme-staging-v02.api.letsencrypt.org/directory";	// ACME v2 staging environment, high rate limits for testing
    // const char *server_uri = "https://acme-v02.api.letsencrypt.org/directory";		// Production environment
    // const char *server_uri = "https://192.168.0.228:14000/dir";					// Pebble
    const char *server_uri = "https://192.168.0.228/dir";					// Pebble

    void	StoreFileOnWebserver(char *localfn, char *remotefn);
    char	*Base64(const char *);
    char	*Base64(const char *, int);
    char	*Unbase64(const char *s);
    char	*Signature(char *, char *);
    String	Signature(String, String);
    char	*MakeMessageJWK(char *url, char *payload, char *jwk);
    char	*MakeJWK();
    char	*MakeMessageKID(const char *url, const char *payload);
    char	*MakeProtectedKID(const char *query);
    char	*PerformWebQuery(const char *, const char *, const char *);
    static esp_err_t HttpEvent(esp_http_client_event_t *event);

    void	QueryAcmeDirectory();
    void	CleanupAcmeDirectory();
    boolean	RequestNewNonce();
    static esp_err_t NonceHttpEvent(esp_http_client_event_t *event);

    boolean	GeneratePrivateKey();
    boolean	ReadPrivateKey();
    boolean	ReadPrivateKey(const char *);
    void	WritePrivateKey();

    void	RequestNewAccount(const char *contact);
    boolean	ReadAccountInfo();
    void	WriteAccountInfo();
    void	ReadAccount(JsonObject &);
    void	ClearAccount();

    void	RequestNewOrder(const char *url);
    boolean	ReadOrderInfo();
    void	WriteOrderInfo();
    void	ReadOrder(JsonObject &);
    void	ValidateOrder();
    void	ValidateOrderFTP();
    void	ValidateOrderLocal();
    void	ValidateAlertServer();
    int		http01_ix;

    void	DownloadAuthorizationResource();
    bool	CreateValidationFile(const char *localfn, const char *token);
    char	*JWSThumbprint();
    void	ReadChallenge(JsonObject &);
    const char *well_known = "/.well-known/acme-challenge/";

    void	SetAcmeUserAgentHeader(esp_http_client_handle_t);

    /*
     *
     */
    const char *csr_template = "{\n\t\"resource\" : \"new-authz\",\n\t\"identifier\" :\n\t{\n\t\t\"type\" : \"dns\",\n\t\t\"value\" : \"%s\"\n\t}\n}";

    /*
     * ACME Protocol data definitions
     */
#if 0					// We don't need this
    struct Meta {			// See ACME RFC § 7.1.1
      char **caaIdentities;
      char *termsOfService;
      char *website;
      boolean externalAccountRequired;
    };
#endif
    struct Directory {
//      Meta *meta;
      char	*newAccount,
		*newNonce,
		*newOrder,
		*newAuthz,
		*keyChange,
		*revokeCert;
    };

    struct Account {			// See ACME RFC § 7.1.2
      char *status;
      char **contact;
      boolean termsOfServiceAgreed;
      // void externalAccountBinding;	// ?
      char *orders;
      // FIX ME huh ?
      char	*key_type, *key_id, *key_e;
      // char	*key;
      char	*initialIp,
		*createdAt;
    };

    struct Identifier {			// See ACME RFC § 7.1.3
      char *_type;
      char *value;
    };
    struct Order {
      char *status;
      char *expires;	// timestamp
      Identifier *identifiers;
      char *notBefore;
      char *notAfter;
      // void error;			// ?
      char **authorizations;
      char *finalize;
      char *certificate;
    };

    struct ChallengeItem {
      char *_type;
      char *status;
      char *url;
      char *token;
    };

    struct Challenge {
      Identifier *identifiers;
      char *status;
      char *expires;
      ChallengeItem *challenges;
    };

    /*
     * private class fields
     */
    Directory	*directory;
    Account	*account;
    Order	*order;
    Challenge	*challenge;

    char	*nonce;
    char	*location;
    char	*reply_buffer;
    int		reply_buffer_len;

    mbedtls_rsa_context		*rsa;
    mbedtls_ctr_drbg_context	*ctr_drbg;
    mbedtls_entropy_context	*entropy;
    // mbedtls_pk_context		key;
    mbedtls_pk_context		*pkey;
    mbedtls_md_context_t	mdctx;

    void TestRfc7515();
    void FakeNewAccountCall();
    void FakeNewAccountCall1();
    void FakeNewAccountCall2();
};

extern Acme *acme;
#endif	/* _ACME_H_ */
