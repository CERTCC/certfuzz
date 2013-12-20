#!/bin/sh

installdir="$2"

export PATH=/Library/Frameworks/Python.framework/Versions/2.7/bin/:$PATH
$installdir/setuptools-0.6c11-py2.7.egg 2>>/tmp/setuptools.err

exit $?
