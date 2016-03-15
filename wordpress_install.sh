#!/bin/bash
# Written by: Sulayman Touray


sudo /bin/php /tmp/phpentermysql.sh

host=host_placeholder

wget -c  wget https://wordpress.org/latest.tar.gz
tar -zxvf latest.tar.gz

/bin/rm latest.tar.gz

mv wordpress /var/www/$host
sudo mv wp-config.php /var/www/$host

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
</VirtualHost>" >> /etc/httpd/sites-enabled/default.conf
/bin/cli53 rrcreate sudirlaycoders.com www.$host A 52.2.96.172 --ttl 40
/bin/cli53 rrcreate sudirlaycoders.com $host A 52.2.96.172 --ttl 40

service httpd reload

