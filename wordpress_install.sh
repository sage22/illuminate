#!/bin/bash
# Written by: Sulayman Touray
host=host_placeholder
sitecheck=`ls /var/www | grep -c $host`

if [ "$sitecheck" == 0 ]
then

/bin/php /tmp/phpentermysql.php



wget -c  wget https://wordpress.org/latest.tar.gz
tar -zxvf latest.tar.gz

/bin/rm latest.tar.gz

mv wordpress /var/www/$host 
sudo mv /tmp/wp-config.php /var/www/$host
chmod 777 -R /var/www/$host/wp-content/
echo "
define('FTP_USER', 'ftpuser');
define('FTP_PASS', 'ftppass');
define('FTP_HOST', 'localhost');" >> /var/www/$host/wp-config.php


echo "

<VirtualHost *:80>
        ServerName www.$host.sudirlaycoders.com
        Serveralias $host.sudirlaycoders.com
        DocumentRoot /var/www/$host/
        <Directory /var/www/$host/>
                Options FollowSymLinks
                AllowOverride All
                Order allow,deny
                Allow from all
        </Directory>
</VirtualHost>" > /etc/httpd/sites-enabled/$host.conf
/bin/cli53 rrcreate sudirlaycoders.com www.$host A 52.203.246.218 --ttl 40
/bin/cli53 rrcreate sudirlaycoders.com $host A 52.203.246.218 --ttl 40

/bin/rm -fr /tmp/*
/bin/rm -fr /var/www/$host/xmlrpc.php

service httpd restart

else

echo "ERROR - SITENAME ALREADY EXISTS, EXITING...."
exit 0

fi


