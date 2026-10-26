# Portal TLS certificate

Place the certificate and its private key in this directory before starting the
public gateway:

~~~text
tls.crt    full certificate chain in PEM format
tls.key    matching private key in PEM format
~~~

The files are intentionally ignored by Git. Use a certificate issued for the
Portal's public DNS name or IP address; do not commit private keys or production
certificates to this repository.
