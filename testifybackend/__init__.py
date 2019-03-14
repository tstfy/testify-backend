from flask import flask
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

db = SQLAlchemy()
ma = Marshmallow()
mail = Mail()
app = Flask(__name__)

def create_app():
    app.secret_key = SECRET_KEY
    app.config['SQLALCHEMY_DATABASE_URI'] = SQLALCHEMY_DATABASE_URI
    app.config.update(MAIL_SETTINGS)

    db.init_app(app)
    ma.init_app(app)
    mail.init_app(app)
    CORS(app)
    return app