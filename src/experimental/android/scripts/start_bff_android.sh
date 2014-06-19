#!/bin/bash
cd ~/android/src
source include virtualenv-certfuzz/bin/activate
xterm -e bff_android --debug 0 &
