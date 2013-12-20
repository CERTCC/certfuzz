#!/bin/bash

ENVNAME=virtualenv-certfuzz

rm -rf $ENVNAME
virtualenv --system-site-packages $ENVNAME

./refresh-virtualenv.sh

deactivate

echo "Activate virtualenv using 'source $ENVNAME/bin/activate'"
