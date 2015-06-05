#!/bin/bash
clear
echo "Hi this a quick program written to test the integrity of your system"
sleep 2
clear

echo "I am a computer scientist and my name is Mr. Trotter"
echo "What is your name?"
read in
clear

echo "Okat $in, how are you?"
read ans
clear

echo "Okay good that you are $ans"
sleep 3
clear

echo "Lets test the integrity of your system"
sleep 3
clear
echo "How many shots do you want to send"
read shots
clear

echo "Okay sending $shots number of shots"
sleep 4
clear

echo "What is your target?"
read target
clear

echo "Okay hitting $target now....."

seq $shots > temp

readarray -t array < temp
for i in ${array[*]}
do
echo "Pulling header"
curl -I $target

nmap www.fbi.gov

done

echo "DONE!!!! PUNK"

