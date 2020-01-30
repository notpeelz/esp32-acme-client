/*
 * This module implements the ACME (Automated Certicifate Management Environment) protocol.
 * A client for Let's Encrypt (https://letsencrypt.org).
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


#ifndef	_ACME_H_
#define	_ACME_H_

#include <ArduinoJson.h>

#include <sys/socket.h>
#include <esp_event_loop.h>
#include <esp_http_client.h>
#include <FtpClient.h>
#include <esp_http_server.h>

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

    // Getters / setters
    void setUrl(const char *);
    void setEmail(const char *);
    void setAcmeServer(const char *);
    void setAccountFilename(const char *);
    void setAccountKeyFilename(const char *);
    void setOrderFilename(const char *);
    void setCertKeyFilename(const char *);
    void setFilenamePrefix(const char *);
    void setCertificateFilename(const char *);
    void setFtpServer(const char *);
    void setFtpUser(const char *);
    void setFtpPassword(const char *);
    void setFtpPath(const char *);
    void setWebServer(httpd_handle_t);

    void loop(time_t now);
    boolean HaveValidCertificate(time_t);
    boolean HaveValidCertificate();

    // Private keys
    void GenerateAccountKey();
    void GenerateCertificateKey();
    mbedtls_pk_context *getAccountKey();
    mbedtls_pk_context *getCertificateKey();
    void setAccountKey(mbedtls_pk_context *ak);
    void setCertificateKey(mbedtls_pk_context *ck);

    boolean CreateNewAccount();
    void AcmeProcess();				// Run the ACME client FSM (finite state machine)
    mbedtls_x509_crt *getCertificate();

    void CreateNewOrder();
    void OrderRemove(char *);
    void CertificateDownload();
    void RenewCertificate();

    void OrderStart();				// Debug
    void ChallengeStart();			// Debug
    void ListFiles();				// Debug

  private:
    constexpr const static char *acme_tag = "Acme";	// For ESP_LOGx calls

    const char *account_key_fn;			// Account private key filename
    const char *cert_key_fn;			// Certificate private key filename
    const char *email_address;			// Email address in the account
    const char *acme_url;			// URL for which we're getting a certificate
    const char *acme_server_url;		// ACME server
    const char *filename_prefix;		// e.g. /spiffs
    const char *account_fn;			// Account status json filename, e.g. "account.json"
    const char *order_fn;			// Order status json filename, e.g. "order.json"
    const char *cert_fn;			// Certificate filename, e.g. "certificate.pem"

    const char *ftp_server;
    const char *ftp_user;
    const char *ftp_pass;
    const char *ftp_path;

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
    const char	*acme_status_valid =		"valid";
    const char	*acme_status_ready =		"ready";
    const char	*acme_status_processing =	"processing";
    const char	*acme_status_pending =		"pending";
    const char	*acme_status_invalid =		"invalid";
    const char	*acme_status_downloaded =	"downloaded";

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

    constexpr static const char *acme_http_404 = "404 File not found";

    // These are the static member functions
    static esp_err_t NonceHttpEvent(esp_http_client_event_t *event);
    static esp_err_t HttpEvent(esp_http_client_event_t *event);
    static esp_err_t acme_http_get_handler(httpd_req_t *);

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
    String	Signature(String, String);
    char	*MakeMessageJWK(char *url, char *payload, char *jwk);
    char	*MakeJWK();
    char	*MakeMessageKID(const char *url, const char *payload);
    char	*MakeProtectedKID(const char *query);
    char	*JWSThumbprint();

    // Do an ACME query
    char	*PerformWebQuery(const char *, const char *, const char *, const char *accept_msg);

    void	QueryAcmeDirectory();
    boolean	RequestNewNonce();
    void	ClearDirectory();

    mbedtls_pk_context	*GeneratePrivateKey();
    boolean	ReadPrivateKey();
    mbedtls_pk_context	*ReadPrivateKey(const char *fn);
    void	WritePrivateKey();
    void	WritePrivateKey(const char *);
    void	WritePrivateKey(mbedtls_pk_context *pk, const char *fn);
    void	ReadAccountKey();
    void	ReadCertKey();

    boolean	RequestNewAccount(const char *contact, boolean onlyExisting);
    boolean	ReadAccountInfo();
    void	WriteAccountInfo();
    void	ReadAccount(JsonObject &);
    void	ClearAccount();

    void	RequestNewOrder(const char *url);
    void	ClearOrder();
    void	ClearOrderContent();
    boolean	ReadOrderInfo();
    void	WriteOrderInfo();
    void	ReadOrder(JsonObject &);
    boolean	ValidateOrder();
    boolean	ValidateAlertServer();
    void	EnableLocalWebServer();
    void	DisableLocalWebServer();

    void	DownloadAuthorizationResource();
    bool	CreateValidationFile(const char *localfn, const char *token);
    char	*CreateValidationString(const char *token);
    void	ReadChallenge(JsonObject &);
    boolean	ReadAuthorizationReply(JsonObject &json);
    void	ClearChallenge();

    void	FinalizeOrder();
    void	DownloadCertificate();
    void	ReadFinalizeReply(JsonObject &json);
    char	*GenerateCSR();

    void	SetAcmeUserAgentHeader(esp_http_client_handle_t);

    void	ReadCertificate();		// From local file

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
    // char	*location;	// moved to Account
    char	*account_location;
    char	*reply_buffer;
    int		reply_buffer_len;

    int		http01_ix;
    time_t	last_run;
    boolean	connected;

    mbedtls_rsa_context		*rsa;
    mbedtls_ctr_drbg_context	*ctr_drbg;
    mbedtls_entropy_context	*entropy;
    mbedtls_pk_context		*accountkey;	// Account private key
    mbedtls_pk_context		*certkey;	// Certificate private key

    mbedtls_x509_crt		*certificate;

    // FTP server, if we have one
    httpd_handle_t	webserver;
    char		*ValidationString;	// The string to reply to the ACME server
    char		*ValidationFile;	// File name that must be queried
    httpd_uri_t		*wsconf;
    boolean		ws_registered;

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
      char	*location;		// Used to be a class field
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
