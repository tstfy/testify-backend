#!/bin/bash

export FLASK_APP=run.py
export FLASK_DEBUG=1
git pull origin $(git branch | grep \* | cut -d ' ' -f2)
source /home/testify/testify/bin/activate

nohup python -m flask run &

exit 0
