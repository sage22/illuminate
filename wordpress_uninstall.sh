#!/bin/bash
# Written by: Sulayman Touray


sudo /bin/php /tmp/phpentermysql.sh

host=host_placeholder

/bin/rm -fr /var/www/$host
/bin/rm -fr /etc/httpd/sites-enabled/$host.conf

/bin/cli53 rrdelete sudirlaycoders.com www.$host A 52.2.96.172 --ttl 40
/bin/cli53 rrdelete sudirlaycoders.com $host A 52.2.96.172 --ttl 40

#/bin/rm -fr /tmp/*

service httpd reload

