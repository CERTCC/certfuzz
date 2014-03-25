#!/bin/bash

ENV=bff.env

virtualenv --verbose --python=python2.7 \
    --system-site-packages --distribute \
    --never-download $ENV