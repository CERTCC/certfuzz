#!/bin/sh

installdir="$2"

if [ ! -e ~/convert ]; then
  ln -s $installdir/convert ~/convert
fi

exit $?
