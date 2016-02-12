#!/bin/sh

installdir="$2"
bffdir="$installdir/bff"
homedir=`cd && pwd`

if [ ! -e $homedir/bff ]; then
  ln -s $bffdir $homedir/bff
fi

rm -rf $bffdir/results

if [ -L ~/results ]; then
  rm $homedir/results
  mkdir $homedir/results
fi

if [ ! -e $homedir/results ]; then
  mkdir $homedir/results
  chmod g+w $homedir/results
fi

ln -s $homedir/results $homedir/bff/results

exit 0
