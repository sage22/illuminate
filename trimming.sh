#!/bin/bash
# This script was written to detect new blogs created, generate accurate vhost entries and reload apache in an automated fashion
# Written by: Matthew Trotter sudirlay@icloud.com

#Begin - Blog creation called so eval on blogs1 starts with a sweep of the directory written to a temp file.. (temp is overwritten everytime a call for blog creation is made)

ls /var/www/blogs/ > /tmp/temp.txt

# Eval is performed to catch new blog id and parsed into blogid.txt - this is overwritten everytime blog-creation process called to permit 1 id per string
awk -F, 'NR==FNR {a[$0]++;next} !a[$1] {print $1}' /tmp/store.txt /tmp/temp.txt > /tmp/blogid.txt



# Generating query to help php grab url params
readarray -t array < /tmp/blogid.txt
for i in  ${array[*]}
do



# Php will grab url using this and parse into a file
echo "SELECT * from "$i"_options where option_name ='siteurl' LIMIT 1 into outfile '/tmp/domain.txt';" > /tmp/graburl.sql
sudo /usr/bin/php /tmp/siteurl.php                   >> /dev/null 2>&1
cat /tmp/domain.sql > /tmp/tempdomainname.txt
rm -fr /tmp/domain.sql

done 


# Give php some time to catch up :-) (php is always slower than bash)
sleep 3

# Back alive, taking new domain name and cleaning url to only give me the domain name.com
grep -oP '(?<=www\.)\s?[^\/]*' /tmp/tempdomainname.txt > /tmp/domain.txt

# cleanup
rm -fr /tmp/tempdomainname.txt



# Backup apache conf
/bin/cat /etc/apache2/sites-available/default > /etc/apache2/sites-available/default.bckup

# Vhost creation starting now......
readarray -t array2 < /tmp/domain.txt
for i2 in ${array2[*]}

ex - /etc/apache2/sites-available/default/<<!

li 

<VirtualHost *:80>
        ServerName www.$i2
        Serveralias $i2
        DocumentRoot /var/www/blogs/$i
        <Directory /var/www/blogs/$i>
                Options FollowSymLinks
                AllowOverride All
                Order allow,deny
                Allow from all
        </Directory>

.
x
!

done

# Reload Apache conf
/usr/bin/service apache2 reload
