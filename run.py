from testifybackend import db, app
from testifybackend.constants import (
    CHALLENGES_AUTH_FP,
    CHALLENGES_BASE_PATH,
)
from instance.config import (
    SQLALCHEMY_DATABASE_URI,
    SECRET_KEY,
    MAIL_SETTINGS,
)
import os
import htpasswd
import shutil

app.secret_key = SECRET_KEY
app.config['SQLALCHEMY_DATABASE_URI'] = SQLALCHEMY_DATABASE_URI
app.config.update(MAIL_SETTINGS)

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
app.run(debug=True)