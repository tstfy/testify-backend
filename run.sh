#!/bin/bash

export FLASK_APP=run.py
git pull origin $(git branch | grep \* | cut -d ' ' -f2)
source /home/testify/testify/bin/activate
nohup flask run &

exit 0
