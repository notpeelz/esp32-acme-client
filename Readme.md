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

If you try this at home, any secured Linux box on which you provide access to its web server can easily be
set up in this way.
