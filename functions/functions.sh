#!/bin/bash
source /$PWD/actions
clear

echo "Greetings, this script was written to demonstrate the power of functions in bash"
sleep 4 
clear
echo "Written by Matthew L. Trotter"
sleep 4 
clear
echo "Do you want to pull headers from websites?"
read ans
clear


# Setting condition
if [ "$ans" == no ]
then
echo "Okay, moving on..."
else

echo "What websites do you wish to pull headers for?"
read answer
clear

# Passing answer to function 
pullsiteheader

fi
sleep 4
clear


echo "What service do you want to check to see if its running?"
read serv
clear

# Passing answer to function
servicecheck





