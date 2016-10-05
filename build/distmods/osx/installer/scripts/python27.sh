#!/bin/sh

pkgdir="$1"
osxver=`uname -a | awk '{print $3}' | awk -F. '{print $1}'`
echo $osxver

# Now using same Python version for all platforms
if (( "$osxver" < 11 )); then
  echo "using lion python"
  pythonpkg='Python-2.7.mpkg'
else
  echo "using leopard python"
  pythonpkg='Python-2.7.mpkg'
fi

python27="/Library/Frameworks/Python.framework/Versions/2.7/Python"

installdir=`echo $pkgdir | xargs -Ix dirname "x"`

if [[ ! -f $python27 ]]; then
  if [ -d "$installdir/pkgs/$pythonpkg" ]; then
    /usr/sbin/installer -pkg "$installdir/pkgs/$pythonpkg" -target "/"
  fi
fi

exit $?
