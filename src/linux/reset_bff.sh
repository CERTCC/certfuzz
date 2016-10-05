#!/bin/sh

# Sometimes you need to clean or nuke the VM in which BFF runs. 
# This script will remove the output directories and 
# local copy of the config file so that you can start
# fresh. Probably best to reboot afterwards

platform=`uname`

if [ $# -lt 1 ]
then
        echo "For your safety, this script won't run unless you provide an argument."
        echo
        echo "E.g.," $0 "<anything> [--reboot]"
        echo
        echo "With any argument other than --remove-results, this script will simply kill any"
        echo "running BFF batch.sh and remove the local fuzzing directory."
        echo
        echo "However, --remove-results will wipe out the remote results directory as well "
        echo "so only use it if you really, really mean it."
        echo
        echo "If the second arg is --reboot, the machine will be rebooted."
        exit 1
fi

# kill any running bff stuff
BFF_PID=`ps -ef | grep bff.py | grep python | awk '{print $2;}'`

if [ -n "$BFF_PID" ]; then
    kill $BFF_PID
fi

# wipe the local files
rm -rfv ~/fuzzing
rm -rfv ~/bff.cfg

if [ "$1" = "--remove-results" ]; then
	if [ "$platform" = "Linux" ]; then
	    # wipe the remote results too
	    sudo rm -rfv ~/results/*
	else
	    rm -rfv ~/results/*
	fi
fi

if [ "$2" = "--reboot" ]; then
    # reboot the vm
    echo Rebooting machine...
    sudo reboot
fi



