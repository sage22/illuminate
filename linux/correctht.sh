#!/bin/bash

# script written/developed by: Matthew Trotter sudirlay@icloud.com
clear

echo "Enter blog id to correct"
read id

clear
echo "Fixing blog htaccess now"
cp -fr /root/.fix /var/www/blogs/$id/.htaccess


clear
echo "done"
