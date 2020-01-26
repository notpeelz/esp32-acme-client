# Configuration examples
This document describes some ways in which you can use the acmeclient library.

# Examples

These are high level descriptions, technology mentioned is explained further below.

### Standalone "in the wild"

A device can be reachable directly from the Internet (meaning it has its own IP address, not shielded by a NAT router).

The sample application standalone.cpp demonstrates :
- ACME can be used to get a certificate
- The ACME protocol is supported by a local web server
- The hostname of the web server can be maintained by DynDNS

### Home environment

In a typical home environment, the ISP provides for a NAT router so all internal nodes appear to have the same IP address as the router.  It is often possible to configure a small number of holes in the router so e.g. a Raspberry Pi with a number of services on it can be accessed.

Our suggestion is to use such a small server with a secured web server (reachable from the Internet) and an FTP server (only visible from inside).

The sample application simple.cpp demonstrates :
- ACME can be used to get a certificate
- The ACME protocol is supported by a local web server

You should set up the home router to run DynDNS to keep a hostname assigned. Alternatively, you can run the noip daemon on your Raspberry Pi.

### Advanced setup

Your environment can have a mixture of the above, and more. You could run forwarding web servers which point traffic for some domains to an offloaded web server, which could run on your IoT device.

The standalone.cpp application can be used for that as well :
- your web server can be configured to forward one domain to your IoT device
- the IoT device uses ACME, DynDNS, and a local web server to power all this 

# Technology overview

### ACME

### DynDNS

### NAT Firewall

### Web traffic forwarding

This basically involves the combination of two techniques :
- Multi-homed web server : most web servers allow you to create and serve several domains, and will happily run them in parallel.
- Traffic forwarding : we'll set up one of these domains to forward traffic to an IoT device. It's then up to the IoT device's web server to answer to queries.

An example with the nginx web server. You can configure it to run a secondary domain by adding a configuration file to the /etc/nginx/sites-available directory :

  #
  # Virtual Host configuration for mydomain.dyndns.me
  #
  server {
          listen 80;
          listen [::]:80;
          server_name mydomain.dyndns.me;
          proxy_set_header X-Real-IP $remote_addr;
          location / {
                  proxy_pass http://192.168.5.6:80;
          }

A symbolic link to the same file must also be created in /etc/nginx/sites-enabled .
The IP address on line 10 should be the IP address of the IoT device, and the port number (here : 80) should be where it services HTTP requests for mydomain.dyndns.me .

### Web traffic forwarding

![Image](Drawing-pictures.png "drawing")
