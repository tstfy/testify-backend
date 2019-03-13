SECRET_KEY = 'super secret key'

# Statement for enabling the development environment
DEBUG = True

DATABASE_CONNECT_OPTIONS = {}

SQLALCHEMY_DATABASE_URI = 'mysql://testify:YtscHDZsCt9egb@devdb.tstfy.co/testifybackend'
SQLALCHEMY_POOL_RECYCLE = 280
SQLALCHEMY_POOL_SIZE = 20
SQLALCHEMY_TRACK_MODIFICATIONS = False

MAIL_SETTINGS = {
    'MAIL_SERVER': 'mail.privateemail.com',
    'MAIL_PORT': 465,
    'MAIL_DEFAULT_SENDER': 'hello@tstfy.co',
    'MAIL_USERNAME': 'hello@tstfy.co',
    'MAIL_PASSWORD': 'HsLOD3Nx7c0EZZDG0pT4',
    'MAIL_USE_TLS': False,
    'MAIL_USE_SSL': True,
}
