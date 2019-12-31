ACME client library for ESP32

Copyright (c) 2019 by Danny Backx

ACME is a protocol (see RFC8555) for automatic certificate management.
Sites such as letsencrypt.org allow you to obtain free (no charge) certificates in an automated way
using the ACME protocol.

This library allows you to get certificates for IoT devices based on the ESP32.

Currently, I've chosen to implement this for devices behind a NAT firewall.
One of the ways in which you can allow an ACME server to validate that you're asking a certificate for
a website/device that you actually have control over, is the use of a web server.
The choice here is that you can do with one central web server on your site, if you allow the IoT devices
to put temporary files there to validate theirselves against the ACME server.

Any secured Linux box on which you provide access to its web server can easily be set up in this way.

This is unfinished software. Current status and plans :
- (done) works as a part of my app against the staging server
- (done) polish up the API so it can be a library
- (todo) run against the production server
- (todo) renew certificate (I have three months to get there)

API :
- several parameters can be set up via the separate Config class :
  const char *acmeEmailAddress();		your email address
  const char *acmeUrl();			the FQDN that we're managing a certificate for
  const char *acmeServerUrl();			e.g.  https://acme-staging-v02.api.letsencrypt.org/directory
  const char *getAccountKeyFileName();		a file name on local (esp spiffs) storage, for an account private key
  const char *getAcmeCertificateKeyFileName();	a file name on local (esp spiffs) storage, for a certificate private key
  const char *getAcmeCertificateFileName();	a file name on local (esp spiffs) storage, for the certificate PEM file

  const char *getAcmeAccountFileName();		a file name to keep state of the account, on local storage (e.g. account.json)
  const char *getAcmeOrderFileName();		a file name to keep state of the order, on local storage (e.g. order.json)

  This will be turned around shortly (Acme class APIs to set these).

  The Config class is currently meant to pick up hardcoded configuration for your IoT device
  from a source configuration file. This can easily become a JSON file as well.

- Private key management from the Acme class :
    void GenerateAccountKey();
    void GenerateCertificateKey();
    mbedtls_pk_context *getAccountKey();
    mbedtls_pk_context *getCertificateKey();
    void setAccountKey(mbedtls_pk_context *ak);
    void setCertificateKey(mbedtls_pk_context *ck);

- class Acme :
    C++ class constructor		Acme();
    Event handlers for esp32 network connect / disconnect
    					void NetworkConnected(void *ctx, system_event_t *event);
    					void NetworkDisconnected(void *ctx, system_event_t *event);
    Event loop (see Arduino) that requires a timestamp
    					void loop(time_t now);
    Underlying function to handle certificate state processing
    					void AcmeProcess();
    Query the certificate
    					mbedtls_x509_crt *getCertificate();

This class relies modules provided with ESP-IDF :
- mbedtls
- vfs (filesystem access, and underlying SPIFFS)
