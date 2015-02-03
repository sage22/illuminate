#!/bin/bash

# script written/developed by: Matthew Trotter mtrotter@dealeron.com

clear

echo "Enter blog id to correct"
read id

clear
echo "Fixing blog htaccess now"
cp -fr /root/.fix /var/www/blogs/$id/.htaccess


clear
echo "done"
