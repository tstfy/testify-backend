#!/bin/bash

export FLASK_APP=testifybackend/app.py
git pull origin master
source /home/testify/testify/bin/activate
nohup flask run &

exit 0
