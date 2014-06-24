#!/bin/sh

installdir="$2"                                                                 

export PATH=/Library/Frameworks/Python.framework/Versions/2.7/bin/:$PATH

cd $installdir
tar xzvf python-memcached-1.47.tar.gz
cd python-memcached-1.47               
python setup.py install   2>>/tmp/memcache.err


exit $?
