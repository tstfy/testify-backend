#!/bin/bash

export FLASK_APP=run.py
git pull origin master
source /home/testify/testify/bin/activate
nohup flask run &

exit 0
