#!/bin/sh

installdir="$2"                                                                 

export PATH=/Library/Frameworks/Python.framework/Versions/2.7/bin/:$PATH

cd $installdir        
tar xzvf hcluster-0.2.0.tar.gz                                           
cd hcluster-0.2.0                                                              
/Library/Frameworks/Python.framework/Versions/2.7/bin/python setup.py install 2>>/tmp/hcluster.err   

exit $?
