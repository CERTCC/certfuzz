#!/bin/bash

ENV=bff.env

virtualenv --system-site-packages --distribute $ENV && source $ENV/bin/activate && pip install -r requirements.txt
