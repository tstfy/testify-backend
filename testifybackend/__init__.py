from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
from flask import Flask, request, jsonify, session
from flask_cors import CORS
from flask_mail import Mail

app = Flask(__name__)
db = SQLAlchemy(app)
ma = Marshmallow(app)
mail = Mail(app)
CORS(app)

from . import routes