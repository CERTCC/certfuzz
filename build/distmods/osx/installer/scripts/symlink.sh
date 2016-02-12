#!/bin/sh

installdir="$2"
bffdir="$installdir/bff"
homedir=`cd && pwd`

if [ ! -e $homedir/bff ]; then
  ln -s $bffdir $homedir/bff 2>> /tmp/symlink.err
fi

if [ -L ~/results ]; then
  rm $homedir/results 2>> /tmp/symlink.err
  mkdir $homedir/results 2>> /tmp/symlink.err
fi

if [ ! -e $homedir/results ]; then
  mkdir $homedir/results 2>> /tmp/symlink.err
  chmod g+w $homedir/results 2>> /tmp/symlink.err
fi

rmdir $homedir/bff/results 2>> /tmp/symlink.err
ln -s $homedir/results $homedir/bff/results 2>> symlink.err

exit 0
