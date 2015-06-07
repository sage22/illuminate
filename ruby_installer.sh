#!/bin/bash
# Simple ruby installation script written by: Matthew Trotter
clear

echo "     Please select and option and hit enter:"
echo "
      (a) Install RVM Manage along with Ruby & Ruby Gems
      (b) Install Ruby & Ruby Gems only"

read selection

if [ "$selection" == b ]
then

echo "What version of ruby do you want to install?"
read var
clear

echo "Installing ruby version $var please wait....."
rvm install $var > /dev/null 2>&1
clear
echo "      Done
'See ruby version listed below'"

ruby --version

else


echo "Installing RVM now...."
gpg --keyserver hkp://keys.gnupg.net --recv-keys 409B6B1796C275462A1703113804BB82D39DC0E3

# Grabbing RVM manager for easy version management
\curl -sSL https://get.rvm.io | bash -s stable
source /etc/profile.d/rvm.sh
clear

echo "What version of ruby do you want to install?"
read var
clear

echo "Installing ruby version $var please wait....."
rvm install $var > /dev/null 2>&1
clear
echo "      Done
'See ruby version listed below'"

ruby --version

fi

