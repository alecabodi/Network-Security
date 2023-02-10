# ACMEv2 Project
> *Project from NetSec 2022 @ ETH Zürich*

Public Key Infrastructures (PKIs) using X.509 certificates are used for many purposes, the most significant of which is the authentication of domain names. Certificate Authorities (CAs) are trusted to verify that an applicant for a certificate legitimately represents the domain name(s) in the certificate. Traditionally, this verification is done through various ad-hoc methods.
The Automatic Certificate Management Environment (ACME) protocol aims to facilitate the automation of certificate issuance by creating a standardized and machine-friendly protocol for certificate management. 

The application implements ACMEv2 according to [RFC8555](https://www.rfc-editor.org/rfc/rfc8555.html). 
However, to make the application self-contained and in order to facilitate testing, the application needs to have more functionality than a bare ACME client.

### Components

The application consists of the following components:

* ACME client: An ACME client which can interact with a standard-conforming ACME server.
* DNS server: A DNS server which resolves the DNS queries of the ACME server.
* Challenge HTTP server: An HTTP server to respond to http-01 queries of the ACME server.
* Certificate HTTPS server: An HTTPS server which uses a certificate obtained by the ACME client.
* Shutdown HTTP server:  An HTTP server to receive a shutdown signal.

### Functionalities

The application is able to:

* use ACME to request and obtain certificates using the `dns-01` and `http-01` challenge (with fresh keys in every run),
* request and obtain certificates which contain aliases,
* request and obtain certificates with wildcard domain names, and
* revoke certificates after they have been issued by the ACME server.
