#!/bin/bash
# This script will edite the header for the theme and clear the cache
# script written/developed by: Matthew Trotter mtrotter@dealeron.com

clear





echo "Enter the blog id (number only)"
read id

clear
echo "Changing responsive header file"
grep -rl header /var/www/blogs/$id/wp-content/themes/dealerOnBoss-Responsive/header.php | xargs sed -i 's/dealerOnBoss-Responsive/amsitest/'
cd /var/www/blogs/$id/wp-content/themes/dealerOnBoss-Responsive/
echo "blog_$id's new header file is:" >> header.log
cat header.php >>header.log
sleep 3

clear
echo "A log of this change has been recorded in /$id/header.log"
echo "done exiting" 





