#!/bin/bash

# The purpose of this script is to add a new virtual host entry based on either user input or directory pattern match
# Written by: Matthew Trotter

#!/bin/bash

clear


echo "Choose an option:"
echo "(1) Add a single vhost entry"
echo "(2) Add all the blogs in the /blogs directory to vhost"
read answer

if  [ "$answer" == "1" ]
       then
clear
     echo "Enter domain name for the vhost entry beginning with (www)"
read vint

clear
    echo "Awesome, now enter the blog_id (number only) for $vint"
    read vint2

clear
    echo "Awesome, now enter the blog_id (number only) for $vint"
    read vint2
clear
echo "Vhost entry added..done"

echo "<VirtualHost *:80>
        ServerName $vint
        DocumentRoot /var/www/blogs/$vint2

        <Directory /var/www/blogs/$vint2>
                Options FollowSymLinks
                AllowOverride All
                Order allow,deny
                Allow from all
        </Directory>
</VirtualHost>" >> /root/testvhost.conf

# Adding some space in the vhost conf
echo "                                                   



" >> /root/testvhost.conf

  else

   echo "This part will be done from a csv file" 

fi
