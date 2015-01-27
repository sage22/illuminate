#!/bin/bash

# The purpose of this script is to add a new virtual host entry based on either user input or directory pattern match
# Written by: Matthew Trotter

clear

echo "Whatsup, please pick an option:"

case $1 in 
  1) echo "Add a new single entry for vhosts"
echo
"<VirtualHost *:80>
        ServerName dev1.dealeron.com
        DocumentRoot /var/www/blogs/937

        <Directory /var/www/blogs/937>
                Options FollowSymLinks
                AllowOverride All
                Order allow,deny
                Allow from all
        </Directory>
</VirtualHost>
"



  2) echo "scan blogs directory and add vhosts for everything"

" <VirtualHost *:80>
        ServerName dev1.dealeron.com
        DocumentRoot /var/www/blogs/937

        <Directory /var/www/blogs/937>
                Options FollowSymLinks
                AllowOverride All
                Order allow,deny
                Allow from all
        </Directory>
</VirtualHost>" 

esac 

