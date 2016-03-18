#!/bin/bash
# Script written to updated all wp plugins automated



sitedir=`ls /var/www`

for i in ${sitedir[*]}
do
cd /var/www/$i
echo $PWD

tool plugin update --all --allow-root

done
