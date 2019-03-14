from testifybackend import create_app, db
from testifybackend.constants import (
    CHALLENGES_AUTH_FP,
    CHALLENGES_BASE_PATH,
)

import os
import htpasswd
import shutil


def reset_git_directory():
    for d in os.listdir(CHALLENGES_BASE_PATH):
        full_path = os.path.join(CHALLENGES_BASE_PATH, d)
        if os.path.isdir(full_path):
            shutil.rmtree(full_path)

    with htpasswd.Basic(CHALLENGES_AUTH_FP) as authdb:
        for user in authdb.users:
            authdb.pop(user)

db.drop_all()
db.create_all()
reset_git_directory()

app = create_app()
app.run(debug=True)