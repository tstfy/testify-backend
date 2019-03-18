from enum import Enum

CHALLENGES_BASE_PATH = "/var/www/git"
CHALLENGES_AUTH_FP = "/var/www/git/htpasswd"
GIT = "git"
GIT_SERVER = "tstfy.co"
APP_NAME = "testify"

class RepositoryStatus(Enum):
    CREATED = 0
    INVITED = 1
    REJECTED = 2
    ACCEPTED = 3