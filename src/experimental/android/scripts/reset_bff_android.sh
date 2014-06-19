#!/bin/bash

# Sometimes you need to clean or nuke the VM in which BFF runs. 
# This script will remove the output directories and 
# local copy of the config file so that you can start
# fresh. Probably best to reboot afterwards

ROOT=
AVD_DIR=~/.android/avd
RUN_SCRIPT=$ROOT/foo
CONFIG=$ROOT/config/android_config.yaml

function get_config_param(){
	val=`grep -v '#' $CONFIG | grep $1: | tr -d ' ' | awk -F: '{ print \$2 }'`
}


if [ $# -lt 1 ]
then
        echo "For your safety, this script won't run unless you provide an argument."
		echo
		echo "E.g.," $0 "<anything> [--reboot]"
		echo
		echo "With any argument other than --remove-results, this script will simply kill any"
		echo "running BFF batch.sh, remove the local fuzzing directory, and reset"
		echo "the local copy of memcached."
        echo
        echo "However, --remove-results will wipe out the remote results directory as well "
        echo "so only use it if you really, really mean it."
        echo
        echo "If the second arg is --reboot, the machine will be rebooted."
        exit 1
fi

# kill any running bff stuff
ps -ef| grep bff | awk '{print $2;}' | xargs kill -9
ps -ef| grep android | awk '{print $2;}' | xargs kill -9

# wipe the local files
rm -rfv $ROOT/fuzzing
rm -rfv $ROOT/log/*.log
rm -rfv $AVD_DIR/*clone*

# wipe the remote results too
if [ "$1" = "--remove-results" ]; then
	DB_HOST=$(get_config_param 'host')
	DB_PORT=$(get_config_param 'port')
	DB_USER=$(get_config_param 'username')
	DB_PASS=$(get_config_param 'password')
	DB_NAME=$(get_config_param 'dbname')
	DB_CREDS=''
	if [[ ! -z "$DB_USER" ]] && [[ ! -z "$DB_PASS" ]]; then
		DB_CREDS=$DB_USER:$DB_PASS
	fi
	
	echo Attempting to delete results at $DB_HOST:$DB_PORT/$DB_NAME
	curl -X DELETE http://$DB_CREDS@$DB_HOST:$DB_PORT/$DB_NAME
fi

# wipe the config, if necessary
if [ "$2" = "--reset-config" ]; then
	sudo rm -rf $ROOT/config
	echo Calling $RESET_CONFIG
	exec $RESET_CONFIG
fi

if [ "$3" = "--reboot" ]; then
	# reboot the vm
    echo Rebooting machine...
	sudo reboot
fi



