#!/bin/bash

# HINT: run me with sudo...
cd ~
apt-get update
# per http://askubuntu.com/questions/318246/complete-installation-guide-for-android-sdk-on-ubuntu
apt-get install -y libgl1-mesa-dev openjdk-7-jdk
# install couchdb locally
apt-get install -y couchdb

# get the android sdk
wget http://dl.google.com/android/android-sdk_r22.0.5-linux.tgz
tar zxvf android-sdk_r22.0.5-linux.tgz 
# link it to a generic name
ln -s android-sdk-linux android-sdk

# code goes into ~/android...
mkdir ~/android
