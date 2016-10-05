#!/bin/bash

cd ~/bff
platform=`uname -a`
if [[ "$platform" =~ "Darwin" ]]; then
    launchctl unload -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
    defaults write NSGlobalDomain NSQuitAlwaysKeepsWindows -bool false
fi

clear
echo -e "***** Welcome to the CERT BFF! *****\n\n"
echo "Working directory: $PWD"

# TODO: This logic needs to change / be fixed
if [[ -f ~/fuzzing/bff.log ]]; then
  currentcfg=~/bff.yaml
  echo -e "\n--- Resuming fuzzing campaign ...  ---"
  echo -e "--- Run ./reset_bff.sh to start a new fuzzing campaign ---\n"
else
  currentcfg=configs/bff.yaml
  echo "Using configuration file: $currentcfg"
fi

program=`egrep -m1 '^    program:' $currentcfg | sed 's/^    program://' | sed 's/\\r//'`
echo "Target commandline: " `egrep -m1 '^    cmdline' $currentcfg | sed 's/^    cmdline_template://' | sed "s|"'$PROGRAM'"|$program|"`
echo -e "Output directory: " `egrep -m1 '^    results_dir' $currentcfg | sed 's/^    results_dir://' | sed 's/\\r//'` "\n\n"

if [[ "$platform" =~ "Darwin" ]]; then
    echo -e "Run ./batch.sh to begin fuzzing.\n"
else
    echo -e "BFF should start fuzzing automatically via ~/bff/batch.sh\n"
fi
