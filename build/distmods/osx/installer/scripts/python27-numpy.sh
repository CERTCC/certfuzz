#!/bin/sh

pkgdir="$1"
numpy="/Library/Frameworks/Python.framework/Versions/2.7/lib/python2.7/site-packages/numpy/version.py"

installdir=`echo $pkgdir | xargs -Ix dirname "x"`

if [[ ! -f $numpy ]]; then
  if [ -d "$installdir/pkgs/numpy-1.6.1-py2.7.mpkg" ]; then
    /usr/sbin/installer -pkg "$installdir/pkgs/numpy-1.6.1-py2.7.mpkg" -target "/"
  fi
fi

exit $?
