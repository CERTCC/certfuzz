#!/bin/sh

pkgdir="$1"
scipy="/Library/Frameworks/Python.framework/Versions/2.7/lib/python2.7/site-packages/scipy/version.py"
installdir=`echo $pkgdir | xargs -Ix dirname "x"`

if [[ ! -f $scipy ]]; then
  if [ -d "$installdir/pkgs/scipy-0.9.0-py2.7.mpkg" ]; then
    /usr/sbin/installer -pkg "$installdir/pkgs/scipy-0.9.0-py2.7.mpkg" -target "/"
  fi
fi

exit $?
