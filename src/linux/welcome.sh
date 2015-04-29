#!/bin/bash

xterm=`which xterm`
cd ~/bff
platform=`uname -a`
if [[ "$platform" =~ "Darwin" ]]; then
    launchctl unload -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
    defaults write NSGlobalDomain NSQuitAlwaysKeepsWindows -bool false
fi

clear
echo -e "***** Welcome to the CERT BFF! *****\n\n"
echo "Working directory: $PWD"

if [[ -f ~/fuzzing/bff.log ]]; then
  currentcfg=~/bff.yaml
  echo -e "\n--- Resuming fuzzing campaign ...  ---"
  echo -e "--- Run ./reset_bff.sh to start a new fuzzing campaign ---\n"
else
  currentcfg=conf.d/bff.yaml
  echo "Using configuration file: $currentcfg"
fi

echo "Target commandline: " `egrep -m1 '^    cmdline' $currentcfg | sed 's/^    cmdline://'`
echo "Output directory: " `egrep -m1 '^    output_dir' $currentcfg | sed 's/^    output_dir://'`

"

if [[ -n "$xterm" ]]; then
    echo "Run ./batch.sh to begin fuzzing.
"
elif [[ "$platform" =~ "Darwin" ]]; then
    echo "X is not detected. Please install X before running BFF
See: https://support.apple.com/kb/HT5293
"
fi
