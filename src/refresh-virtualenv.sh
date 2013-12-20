#!/bin/bash

ENVNAME=virtualenv-certfuzz

svn update
source $ENVNAME/bin/activate
python setup.py install
