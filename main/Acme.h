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
    void ListFiles();
    void CertificateDownload();

    struct Certificate {
      mbedtls_x509_crt	*cert;
    };

    Certificate *issueCertificate(char *domain);

    void setCertificate(const char *cert);	// FIXME debug, remove this

  private:
    const char *acme_tag = "Acme";		// For ESP_LOGx calls

    // String constants for use in the code
    const char *acme_agent_header = "User-Agent";
    const char *acme_content_type = "Content-Type";
    const char *acme_jose_json = "application/jose+json";
    const char *acme_accept_header = "Accept";
    const char *acme_accept_pem_chain = "application/pem-certificate-chain";
    const char *well_known = "/.well-known/acme-challenge/";
    const char *acme_http_01 = "http-01";

    // JSON
    const char	*acme_json_status =		"status";
    const char	*acme_json_type =		"type";
    const char	*acme_json_detail =		"detail";
    const char	*acme_json_value =		"value";
    const char	*acme_json_url =		"url";
    const char	*acme_json_token =		"token";
    const char	*acme_json_location =		"location";
    const char	*acme_json_contact =		"contact";
    const char	*acme_json_key =		"key";
    const char	*acme_json_kty =		"kty";
    const char	*acme_json_n =			"n";
    const char	*acme_json_e =			"e";
    const char	*acme_json_expires =		"expires";
    const char	*acme_json_finalize =		"finalize";
    const char	*acme_json_certificate =	"certificate";
    const char	*acme_json_identifiers =	"identifiers";
    const char	*acme_json_authorizations =	"authorizations";

    // Status
    const char	*acme_status_valid =	"valid";

    // Identify ourselves as :
    const char *acme_agent_template = "EspAlarm ACME client/0.1, built on esp-idf %s (https://esp32-acme-client.sourceforge.io)";

    // Format strings for protocol queries :
    const char *acme_jwk_template = "{\"kty\": \"RSA\", \"n\": \"%s\", \"e\": \"%s\"}";
    const char *new_account_template =
      "{\n  \"termsOfServiceAgreed\": true,\n  \"contact\": [\n    \"%s\"\n  ],\n  \"onlyReturnExisting\": %s\n}";
    const char *new_account_template_no_email =
      "{\n  \"termsOfServiceAgreed\": true,\n  \"resource\": [\n    \"new-reg\"\n  ]\n}";
    const char *new_order_template =
      "{\n  \"identifiers\": [\n    {\n      \"type\": \"dns\", \"value\": \"%s\"\n    }\n  ]\n}";
    const char *csr_template =
      "{\n\t\"resource\" : \"new-authz\",\n\t\"identifier\" :\n\t{\n\t\t\"type\" : \"dns\",\n\t\t\"value\" : \"%s\"\n\t}\n}";
    const char *csr_format = "{ \"csr\" : \"%s\" }";

    // These are needed in static member functions
    // We scan HTTP headers in replies for these :
    constexpr static const char *acme_nonce_header = "Replay-Nonce";
    constexpr static const char *acme_location_header = "Location";

    // These are the static member functions
    static esp_err_t NonceHttpEvent(esp_http_client_event_t *event);
    static esp_err_t HttpEvent(esp_http_client_event_t *event);

    // These store the info obtained in one of the static member functions
    void setNonce(char *);
    void setLocation(const char *);

    // Helper functions
    time_t	timestamp(const char *);
    time_t	TimeMbedToTimestamp(mbedtls_x509_time t);

    //
    void	StoreFileOnWebserver(char *localfn, char *remotefn);
    void	RemoveFileFromWebserver(char *remotefn);

    // Crypto stuff to build the ACME messages (see protocols such as JWS, JOSE, JWK, ..)
    char	*Base64(const char *);
    char	*Base64(const char *, int);
    char	*Unbase64(const char *s);
    String	Signature(String pr, String pl, mbedtls_pk_context *ck);
    String	Signature(String, String);
    char	*MakeMessageJWK(char *url, char *payload, char *jwk);
    char	*MakeJWK();
    char	*MakeMessageKID(const char *url, const char *payload);
    char	*MakeProtectedKID(const char *query);
    char	*JWSThumbprint();

    // Do an ACME query
    char	*PerformWebQuery(const char *, const char *, const char *, const char *accept_msg);

    void	QueryAcmeDirectory();
    void	CleanupAcmeDirectory();
    boolean	RequestNewNonce();

    mbedtls_pk_context	*GeneratePrivateKey();
    boolean	ReadPrivateKey();
    mbedtls_pk_context	*ReadPrivateKey(const char *fn);
    void	WritePrivateKey();
    void	WritePrivateKey(const char *);
    void	WritePrivateKey(mbedtls_pk_context *pk, const char *fn);

    void	RequestNewAccount(const char *contact, boolean onlyExisting);
    boolean	ReadAccountInfo();
    void	WriteAccountInfo();
    void	ReadAccount(JsonObject &);
    void	ClearAccount();

    void	RequestNewOrder(const char *url);
    void	ClearOrder();
    boolean	ReadOrderInfo();
    void	WriteOrderInfo();
    void	ReadOrder(JsonObject &);
    boolean	ValidateOrder();
    boolean	ValidateOrderFTP();
    void	ValidateOrderLocal();
    boolean	ValidateAlertServer();

    void	DownloadAuthorizationResource();
    bool	CreateValidationFile(const char *localfn, const char *token);
    void	ReadChallenge(JsonObject &);
    boolean	ReadAuthorizationReply(JsonObject &json);

    void	FinalizeOrder();
    void	DownloadCertificate();
    void	ReadFinalizeReply(JsonObject &json);
    char	*GenerateCSR();

    void	SetAcmeUserAgentHeader(esp_http_client_handle_t);

    void	ReadCertificate();		// From local file
    void	RenewCertificate();

    // Forward declarations
    struct Directory;
    struct Account;
    struct Order;
    struct Challenge;

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

    int		http01_ix;
    time_t	last_run;

    mbedtls_rsa_context		*rsa;
    mbedtls_ctr_drbg_context	*ctr_drbg;
    mbedtls_entropy_context	*entropy;
    mbedtls_pk_context		*accountkey;	// Account private key
    mbedtls_pk_context		*certkey;	// Certificate private key

    mbedtls_x509_crt		*certificate;

    /*
     * ACME Protocol data definitions
     * Note : these aren't exactly what the RFC says, they're what we need.
     */
    struct Directory {
      char	*newAccount,
		*newNonce,
		*newOrder;
    };

    struct Account {			// See ACME RFC § 7.1.2
      char	*status;
      char	**contact;
      boolean	termsOfServiceAgreed;
      char	*orders;
      char	*key_type, *key_id, *key_e;
      char	*initialIp,
		*createdAt;
      time_t	t_createdAt;
    };

    struct Identifier {			// See ACME RFC § 7.1.3
      char		*_type;
      char		*value;
    };
    struct Order {
      char		*status;
      char		*expires;	// timestamp
      time_t		t_expires;
      Identifier	*identifiers;
      char		**authorizations;
      char		*finalize;	// URL for us to call
      char		*certificate;	// URL to download the certificate
    };

    struct ChallengeItem {
      char		*_type;
      char		*status;
      char		*url;
      char		*token;
    };

    struct Challenge {
      Identifier	*identifiers;
      char		*status;
      char		*expires;
      time_t		t_expires;
      ChallengeItem	*challenges;
    };
};

extern Acme *acme;
#endif	/* _ACME_H_ */
