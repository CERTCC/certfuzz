#!/bin/sh

pkgdir="$1"
python27="/Library/Frameworks/Python.framework/Versions/2.7/Python"
matplotlib="/Library/Frameworks/Python.framework/Versions/2.7/lib/python2.7/site-packages/matplotlib/mpl.py"

installdir=`echo $pkgdir | xargs -Ix dirname "x"`

if [[ ! -f $matplotlib ]]; then
  if [ -d "$installdir/pkgs/matplotlib-1.0.1-python.org-32bit-py2.7-macosx10.3.mpkg" ]; then
    /usr/sbin/installer -pkg "$installdir/pkgs/matplotlib-1.0.1-python.org-32bit-py2.7-macosx10.3.mpkg" -target "/"
  fi
fi

exit $?
