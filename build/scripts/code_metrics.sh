#!/bin/bash
###  
### This script is intended for use in a Jenkins job to generate various
### code metrics for the BFF project
###

# Count the lines of code
sloccount --duplicates --wide --details . | fgrep -v .svn > sloccount.sc


# Run the unit tests, and collect code coverage data
export PYTHONPATH=./src:$PYTHONPATH
/usr/local/bin/nosetests-2.7 --with-xunit --with-xcoverage \
	--cover-inclusive --cover-package=src --cover-erase \
	--cover-branches -e test_probability \
    src/certfuzz/test src/linux/test src/windows/test
    
