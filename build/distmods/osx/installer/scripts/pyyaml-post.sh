#!/bin/sh

installdir="$2"                                                                 

export PATH=/Library/Frameworks/Python.framework/Versions/2.7/bin/:$PATH

cd $installdir
tar xzvf PyYAML-3.10.tar.gz
cd PyYAML-3.10               
python setup.py install   2>>/tmp/pyyaml.err


exit $?
