#!/bin/bash
# Written by: Matthew Trotter
# This script will update all wordpress websites, plugins and core


# Detecting in a for loop rather /dir is a wordpress directory or not

for i in `ls /var/www/`
do
if [ -e /var/www/$i/index.php ]
then
echo "$i is a wordpress, updating all plugins and core" >> /var/www/update.log
cd /var/www/$i/
tool plugin update --all --allow-root >> /var/www/update.log
cd /var/www/$i/
tool core update --allow-root >> /var/www/update.log
cd /var/www/$i/
tool core update-db --allow-root >> /var/www/update.log
echo "Wordpress site $i update finish




"
else
echo $i is not a wordpress site
fi

done

# Restarting Httpd services and display log of all events
service httpd restart && cat /var/www/update.log


