#!/bin/bash

yum install -y wget
sudo wget -O /etc/yum.repos.d/jenkins.repo http://pkg.jenkins-ci.org/redhat/jenkins.repo
sudo rpm --import https://jenkins-ci.org/redhat/jenkins-ci.org.key
sudo yum install jenkins

 sudo yum install java-1.7.0-openjdk

sudo /etc/init.d/jenkins restart
systemctl restart jenkins.service
