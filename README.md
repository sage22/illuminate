# work
Important things.

Setup SQUID SSL made simple ;-)
<br />
```mkdir /etc/squid/ssl```
<br />
'''cd /etc/squid/ssl/'''
<br />
'''openssl genrsa -des3 -out squid.key 1024'''
<br />
openssl req -new -key squid.key -out squid.csr
<br />
cp squid.key squid.key.org
<br />
openssl rsa -in squid.key.org -out squid.key
<br />
openssl x509 -req -days 365 -in squid.csr -signkey squid.key -out squid.crt

FINALLY EDIT SQUID.CONF
<br />
http_port 3128 transparent
https_port 3129 transparent key=/etc/squid/ssl/squid.key cert=/etc/squid/ssl/squid.crt
