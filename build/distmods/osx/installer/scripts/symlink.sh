#!/bin/sh

installdir="$2"
bffdir="$installdir/bff"

if [ ! -e ~/bff ]; then
  ln -s $bffdir ~/bff
fi
#if [ ! -e ~/results ]; then
#  mkdir ~/results
#fi
#if [ -d ~/bff/results ]; then
  rmdir $bffdir/results
#fi
if [ -L ~/results ]; then
  rm ~/results
#  mkdir ~/results
fi
#chmod g+w ~/results
#rmdir ~/bff/results
#ln -s ~/results ~/bff/results

exit 0
