from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
from flask import Flask, request, jsonify, session
from flask_cors import CORS
from flask_mail import Mail

from instance.config import (
    SQLALCHEMY_DATABASE_URI,
    SECRET_KEY,
    MAIL_SETTINGS,
)

app = Flask(__name__)

app.secret_key = SECRET_KEY
app.config['SQLALCHEMY_DATABASE_URI'] = SQLALCHEMY_DATABASE_URI
app.config.update(MAIL_SETTINGS)

db = SQLAlchemy(app)
ma = Marshmallow(app)
mail = Mail(app)
CORS(app)

from . import routes