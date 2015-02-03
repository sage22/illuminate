#!/bin/bash

# The purpose of this script is to add a new virtual host entry based on either user input or directory pattern match
# Written by: Matthew Trotter

#!/bin/bash

clear

echo "Enter domain name for the vhost entry without the (www)"
echo "For example: yahoo.com"
read vint

clear
    echo "Awesome, now enter the blog_id (number only) for $vint"
    read vint2


clear
echo "Vhost entry added..done"

echo "<VirtualHost *:80>
        ServerName www.$vint
        Serveralias $vint
        DocumentRoot /var/www/blogs/$vint2
        <Directory /var/www/blogs/$vint2>
                Options FollowSymLinks
                AllowOverride All
                Order allow,deny
                Allow from all
        </Directory>
</VirtualHost>" >>  /etc/apache2/sites-available/copythis.txt

# Adding some space in the vhost conf
echo "                                                   

" >> /etc/apache2/sites-available/copythis.txt

 
