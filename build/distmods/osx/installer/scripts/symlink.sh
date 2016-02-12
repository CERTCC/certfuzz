#!/bin/sh

installdir="$2"
bffdir="$installdir/bff"
homedir=`cd && pwd`

if [ ! -e $homedir/bff ]; then
  ln -s $bffdir $homedir/bff
fi

if [ -L ~/results ]; then
  rm $homedir/results
  mkdir $homedir/results
fi

if [ ! -e $homedir/results ]; then
  mkdir $homedir/results
  chmod g+w $homedir/results
fi

rmdir $homedir/bff/results 2> /tmp/rm.err
ln -s $homedir/results $homedir/bff/results 2> /tmp/ln.err

exit 0
