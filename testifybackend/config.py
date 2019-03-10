SECRET_KEY = 'super secret key'

# Statement for enabling the development environment
DEBUG = True

# Define the application directory
import os
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

# Define the database - we are working with
# SQLite for this example
# SQLALCHEMY_DATABASE_URI = 'sqlite://' + os.path.join(BASE_DIR, 'app.sqlite')
DATABASE_CONNECT_OPTIONS = {}

SQLALCHEMY_DATABASE_URI = 'mysql://root@devdb.tstfy.co/testifybackend'
SQLALCHEMY_POOL_RECYCLE = 280
SQLALCHEMY_POOL_SIZE = 20
SQLALCHEMY_TRACK_MODIFICATIONS = True