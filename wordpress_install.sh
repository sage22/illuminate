#!/bin/bash

php phpentermysql.sh

host=host_placeholder

wget -c  wget https://wordpress.org/latest.tar.gz
tar -zxvf latest.tar.gz

/bin/rm latest.tar.gz

mv wordpress /var/www/$host

mv /var/www/$host/wp-config-sample.php /var/www/$host/wp-config.php

sed -i 's/database_name_here/'$host'/g' /var/www/$host/wp-config.php
sed -i 's/username_here/db_user/g' /var/www/$host/wp-config.php 
sed -i 's/password_here/db_pass/g' /var/www/$host/wp-config.php

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

service httpd reload

