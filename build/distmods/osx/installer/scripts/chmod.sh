#!/bin/sh

installdir="$2"
bffdir="$installdir/bff"
packagesdir="$2/packages"

launchctl unload -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist
sed "s/^copymode=0/copymode=1/" $bffdir/conf.d/bff.cfg > $bffdir/conf.d/cfg.tmp
mv $bffdir/conf.d/cfg.tmp $bffdir/conf.d/bff.cfg
chmod -R 777 $bffdir
chmod 755 $packagesdir
chmod 755 /usr/local/lib

exit $?
