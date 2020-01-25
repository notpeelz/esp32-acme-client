ACME client library for ESP32

Copyright (c) 2019, 2020 by Danny Backx

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
- (done) run against the production server
- (done, on staging) renew certificate (I have three months to get there)

Build notes :
- you may have to augment default stack sizes such as
    CONFIG_SYSTEM_EVENT_TASK_STACK_SIZE=6144
    CONFIG_MAIN_TASK_STACK_SIZE=6144
  in the ESP-IDF "make menuconfig".

- building the example requires you to copy an include file and change its contents to match your
  local requirements (e.g. your WiFi credentials) :
    % cp main/secrets.h.sample main/secrets.h
    % vi main/secrets.h
    % make

API :
- This is a C++ class, with several methods that you must call :
    Acme();				Constructor
    ~Acme();				Destructor

    void NetworkConnected(void *ctx, system_event_t *event);
    void NetworkDisconnected(void *ctx, system_event_t *event);
    					Call from network event handlers, see the example

    void loop(time_t now);
    					Similar to Arduino, call this regularly with the current timestamp.
					Certificates are valid for quite a while so calling this several time
					a second (see Arduino) is not necessary.

- Several of the other setters allow you to configure the library.
  Please note that these setters take a copy of the pointer. Ownership of the data is still with the caller.
  So the caller must not free the memory pointed to.
  The reason is to keep memory consumption low.

    void setUrl(const char *);				URL that we'll get a certificate for
    void setEmail(const char *);			Email address of the owner
    void setAcmeServer(const char *);			Which ACME server do we use
    void setAccountFilename(const char *);		File name on esp32 local storage for the account, e.g. account.json
    void setAccountKeyFilename(const char *);		File name on esp32 local storage for the account private key, e.g. account.pem
    void setOrderFilename(const char *);		File name on esp32 local storage for the order, e.g. order.json
    void setCertKeyFilename(const char *);		File name on esp32 local storage for the certificate private key, e.g. certkey.pem
    void setFilenamePrefix(const char *);		Prefix for filesystem on esp32, e.g. /spiffs
    void setCertificateFilename(const char *);		File name on esp32 local storage for the certificate, e.g. certificate.pem

    void setFtpServer(const char *);			For your local FTP server : hostname / ip address
    void setFtpUser(const char *);			Userid on your local FTP server
    void setFtpPassword(const char *);			Password of that user on your local FTP server
    void setFtpPath(const char *);			Path to the web server files on your local FTP server, e.d. /var/www/html

- Note that the path ".well-known/challenge" must already have been create on your FTP server, e.g.
    cd /var/www/html
    mkdir -p .well-known/challenge

- You can grab your certificate with
    mbedtls_x509_crt *getCertificate();

- See the example client, you will need to use one or more of the folowing calls to kickstart the process.
  Actuall processing is in the loop() function, or the underlying AcmeProcess().

    boolean CreateNewAccount();
    void CreateNewOrder();
    void RenewCertificate();

- Private key management from the Acme class :
    void GenerateAccountKey();
    void GenerateCertificateKey();
    mbedtls_pk_context *getAccountKey();
    mbedtls_pk_context *getCertificateKey();
    void setAccountKey(mbedtls_pk_context *ak);
    void setCertificateKey(mbedtls_pk_context *ck);

This class relies modules provided with ESP-IDF :
- mbedtls
- vfs (filesystem access, and underlying SPIFFS)
