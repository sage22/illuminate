#!/bin/bash
# Written by: Sulayman Touray
host=host_placeholder
sitecheck=`ls /var/www | grep -c $host`
theme=site_theme
if [ "$sitecheck" == 0 ]
then

/bin/php /tmp/phpentermysql.php

if [ "$theme" == Default_latest ]
then

wget -c  wget http://ftp.drupal.org/files/projects/drupal-7.43.zip
unzip drupal-7.43.zip
/bin/rm drupal-7.43.zip
mv drupal-7.43 /var/www/$host 
chown -R apache:apache /var/www/$host/
cp -fr /tmp/settings.php /var/www/$host/sites/default/
chmod 777 /var/www/$host/sites/default/settings.php 

else

wget -c  wget http://ftp.drupal.org/files/projects/"$theme".zip
unzip "$theme".zip
/bin/rm "$theme".zip
mv $theme /var/www/$host
chown -R apache:apache /var/www/$host/
cp -fr /tmp/settings.php /var/www/$host/sites/default/
chmod 777 /var/www/$host/sites/default/settings.php

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
/bin/cli53 rrcreate sudirlaycoders.com www.$host A 52.2.96.172 --ttl 40
/bin/cli53 rrcreate sudirlaycoders.com $host A 52.2.96.172 --ttl 40

/bin/rm -fr /tmp/*

service httpd restart

else

echo "ERROR - SITENAME ALREADY EXISTS, EXITING...."
exit 0

fi
fi
