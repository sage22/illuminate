#!/bin/bash

# Shell script written by: Sulayman Touray January 27, 2015
# This script is written to check if user is root or not and display date if user desires.

clear

if [ "$(whoami)" == "root" ]
   then
       echo 'You are root' 

   else

        echo 'You are not root' 



        fi
sleep 2
   clear

echo "Do you want to know today's date? yes or no"
read do

if [ "$do" == "yes" ]
    then
         clear
         echo "Todays date is:"
         echo $(date)
else

           echo "Guess your good not knowing"

fi

sleep 2

clear

echo "Do you want to know who you are? yes or no"
read answer

if [ "$answer" == "yes" ]
   then
       clear
       echo "You are:"
       echo $(whoami)
else

clear
echo "I guess your not interested in who you are :-("

fi



   
