#!/bin/bash


# This script was written to consolidate username password resets into a single function
# Any questions or concerns please email sudirlay@icloud.com
clear

echo "Greetings what blog ID number do you want to reset username/and password on?"
read number


clear
echo "Updating admin username to newusername for blog_id=$number"
sleep 3

echo "update "$number"_users set user_login='username' where user_nicename like '%matt' LIMIT 1;" > /usr/local/bin/setusername.sql
sudo /usr/bin/php /usr/local/bin/step1.php
clear


echo "Updating login password for blog_id=$number"
sleep 3
echo "update "$number"_users set user_pass = MD5('xxxx') where user_login = 'matt';" > /usr/local/bin/setpasswd.sql
sudo /usr/bin/php /usr/local/bin/step2.php


#rm /usr/local/bin/setpasswd.sql
#rm /usr/local/bin/setusername.sql
clear
echo "All done! exiting.."


