#!/bin/bash
# Written by: Sulayman Touray


sudo /bin/php /tmp/phpremovemysql.sh

host=host_placeholder

/bin/rm -fr /var/www/$host
/bin/rm -fr /etc/httpd/sites-enabled/$host.conf

/bin/cli53 rrdelete sudirlaycoders.com www.$host
/bin/cli53 rrdelete sudirlaycoders.com $host

#/bin/rm -fr /tmp/*

service httpd reload

