# work
Important things.

Setup SQUID SSL made simple ;-)
mkdir /etc/squid/ssl
cd /etc/squid/ssl/
openssl genrsa -des3 -out squid.key 1024
openssl req -new -key squid.key -out squid.csr
cp squid.key squid.key.org
openssl rsa -in squid.key.org -out squid.key
openssl x509 -req -days 365 -in squid.csr -signkey squid.key -out squid.crt

FINALLY EDIT SQUID.CONF
http_port 3128 transparent
https_port 3129 transparent key=/etc/squid/ssl/squid.key cert=/etc/squid/ssl/squid.crt
