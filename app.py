from datetime import datetime, timedelta

from flask import Flask, request, jsonify, session
# from flask.ext.session import Session
# from flask_restful import Resource, Api
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
from passlib.hash import sha256_crypt
from functools import wraps
from testifybackend.config import SECRET_KEY, SQLALCHEMY_DATABASE_URI

from testifybackend.classes.Exception import (
    AuthenticationRequiredException,
    UsernameTakenException,
    IncorrectCredentialsException
)

import htpasswd

app = Flask(__name__)
app.secret_key = SECRET_KEY
app.config['SQLALCHEMY_DATABASE_URI'] = SQLALCHEMY_DATABASE_URI

db = SQLAlchemy(app)
ma = Marshmallow(app)

class Company(db.Model):
    name = db.Column(db.String(120), primary_key=True)

    def __init__(self, name):
        self.name = name

class CompanySchema(ma.Schema):
    class Meta:
        fields = ('name')

company_schema = CompanySchema()

class Candidate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True)
    f_name = db.Column(db.String(30))
    l_name = db.Column(db.String(30))
    created = db.Column(db.DateTime())
    username = db.Column(db.String(80), unique=True)
    password = db.Column(db.String(120))
    last_modified = db.Column(db.DateTime())

    def __init__(self, email, f_name, l_name):
        self.email = email
        self.f_name = f_name
        self.l_name = l_name
        self.created = datetime.utcnow()
        self.last_modified = datetime.utcnow()

class CandidateSchema(ma.Schema):
    class Meta:
        fields = ('email','f_name','l_name', 'last_modified')

candidate_schema = CandidateSchema()

class Employer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True)
    email = db.Column(db.String(120), unique=True)
    password = db.Column(db.String(120))
    f_name = db.Column(db.String(30))
    l_name = db.Column(db.String(30))
    created = db.Column(db.DateTime())
    last_modified = db.Column(db.DateTime())
    company = db.Column(db.String(120), db.ForeignKey(Company.name))

    def __init__(self, username, email, password, f_name, l_name):
        self.username = username
        self.email = email
        self.password = password
        self.f_name = f_name
        self.l_name = l_name
        self.created = datetime.utcnow()
        self.last_modified = datetime.utcnow()

class EmployerSchema(ma.Schema):
    class Meta:
        fields = ('username','email','f_name','l_name', 'last_modified')

employer_schema = EmployerSchema()

# class Setting(db.Model):
#     user_id = db.Column(db.Integer, primary_key=True)
#     setting_field_1 = db.Column(db.String(80))
#     setting_field_2 = db.Column(db.String(80))
#     last_modified = db.Column(db.DateTime())

#     def __init__(self, user_id):
#         self.user_id = user_id
#         self.last_modified = datetime.utcnow()


# class SettingSchema(ma.Schema):
#     class Meta:
#         # Fields to expose
#         fields = ('last_modified',)

# setting_schema = SettingSchema()


class Challenge(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    creator = db.Column(db.Integer, db.ForeignKey(Employer.id))
    description = db.Column(db.String(80), unique=True)
    category = db.Column(db.String(80))
    due = db.Column(db.DateTime())
    created = db.Column(db.DateTime())
    last_modified = db.Column(db.DateTime())


    def __init__(self, creator, description, category, due):
        self.category = category
        self.creator = creator
        self.description = description
        self.due = due
        self.created = datetime.utcnow()
        self.last_modified = datetime.utcnow()


class ChallengeSchema(ma.Schema):
    class Meta:
        # Fields to expose
        fields = ('creator', 'description', 'category', 'last_modified', 'due')

challenge_schema = ChallengeSchema()


class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user = db.Column(db.Integer, db.ForeignKey(Employer.id))
    message = db.Column(db.String(80))
    challenge = db.Column(db.Integer, db.ForeignKey(Challenge.id))
    created = db.Column(db.DateTime())
    last_modified = db.Column(db.DateTime())


    def __init__(self, user, message, challenge):
        self.user = user
        self.message = message
        self.challenge = challenge
        self.created = datetime.utcnow()
        self.last_modified = datetime.utcnow()


class CommentSchema(ma.Schema):
    class Meta:
        # Fields to expose
        fields = ('user', 'message', 'challenge', 'last_modified')

comment_schema = CommentSchema()

class Repository(db.Model):
    id = db.Column(db.Integer, default=1, primary_key=True)
    employer = db.Column(db.Integer, db.ForeignKey(Employer.id), primary_key=True)
    candidate = db.Column(db.Integer, db.ForeignKey(Candidate.id), primary_key=True)
    challenge = db.Column(db.Integer, db.ForeignKey(Challenge.id), primary_key=True)
    created = db.Column(db.DateTime())
    last_modified = db.Column(db.DateTime())

    def __init__(self, employer, candidate, challenge):
        self.employer = employer
        self.candidate = candidate
        self.challenge = challenge
        self.created = datetime.utcnow()
        self.last_modified = datetime.utcnow()


class RepositorySchema(ma.Schema):
    class Meta:
        # Fields to expose
        fields = ('id', 'employer', 'candidate', 'challenge', 'last_modified')

repository_schema = RepositorySchema()


def login_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        try:
            if 'logged_in' in session:
                return f(*args, **kwargs)
            else:
                raise AuthenticationRequiredException
        except Exception as e:
            return(str(e))
    return wrap

def existing_username(username):
    user_count = db.session.query(Employer).filter(Employer.username==username).count()

    if int(user_count) > 0:
        return True
    return False


@app.route("/challenges/<cid>/user/<uid>", methods=["POST"])
# check due date of challenge for validity
def assign_challenge(cid, uid):
    try:
        challenge = cid
        employer = 1
        candidate = uid

        new_repository = Repository(employer, candidate, challenge)
        db.session.add(new_repository)
        db.session.commit()

        new_repository = db.session.query(Repository).filter(Repository.employer==employer).\
                        filter(Repository.candidate==candidate).\
                        filter(Repository.challenge==challenge).first()

        return jsonify(repository_schema.dump(new_repository).data)

    except Exception as e:
        return(str(e))

# need to change the route on this to have /challenges prefix
@app.route("/comments", methods=["POST"])
def create_comment():
    try:
        user = request.json['user']
        message = request.json['message']
        challenge = request.json['challenge']
        # TODO need time of comment as well

        new_comment = Comment(user, message, challenge)
        db.session.add(new_comment)
        db.session.commit()

        new_comment = db.session.query(Comment).filter(Comment.user==user).\
                        filter(Comment.message==message).\
                        filter(Comment.challenge==challenge).first()

        return jsonify(comment_schema.dump(new_comment).data)

    except Exception as e:
        return(str(e))

@app.route("/challenges", methods=["POST"])
# @login_required; employer login required
# TODO need a way to recognize which user is making this call
def create_challenge():
    try:
        creator = 1 # TODO hardcoded for now, remove later
        description = request.json['description']
        category = request.json['category']
        # due = request.json['due']
        due = datetime.today() + timedelta(days=1) #TODO hardcoded for now, remove later

        new_challenge = Challenge(creator, description, category, due)
        db.session.add(new_challenge)
        db.session.commit()

        new_challenge = db.session.query(Challenge).filter(Challenge.description==description).first()
        return jsonify(challenge_schema.dump(new_challenge).data)

    except Exception as e:
        return(str(e))

@app.route("/users", methods=["POST"])
def register_user():
    try:
        username  = request.json['username']
        email = request.json['email']
        password = sha256_crypt.encrypt((str(request.json['password'])))
        f_name = request.json['f_name']
        l_name = request.json['l_name']
        if existing_username(username):
            raise UsernameTakenException

        else:
            # TODO consider creating a separate Candidate/Employer object based on FE logic
            new_employer = Employer(username, email, password, f_name, l_name)
            db.session.add(new_employer)
            db.session.commit()

            new_employer = db.session.query(Employer).filter(Employer.username==username).first()
            return jsonify(employer_schema.dump(new_employer).data)

    except Exception as e:
        return(str(e))


@app.route("/user/<id>", methods=["GET"])
def user_detail(id):
    user = Employer.query.get(id)
    return employer_schema.jsonify(user)


@app.route("/user/<id>", methods=["PUT"])
@login_required
def user_update(id):
    try:
        user = Employer.query.get(id)
        username = request.json['username']
        email = request.json['email']

        if existing_username(username):
            raise UsernameTakenException

        user.email = email
        user.username = username
        user.last_modified = datetime.utcnow()

        db.session.commit()
        return employer_schema.jsonify(user)

    except Exception as e:
        return(str(e))

@app.route("/user/<id>", methods=["DELETE"])
@login_required
def user_delete(id):
    user = Employer.query.get(id)
    db.session.delete(user)
    db.session.commit()

    return employer_schema.jsonify(user)


@app.route("/login", methods=["POST"])
def login_page():
    try:
        username  = request.json['username']
        input_password = request.json['password']
        print(username)
        print(input_password)
        res = db.session.query(Employer.username, Employer.password).filter(Employer.username==username)

        if res.count() != 1:
            raise IncorrectCredentialsException

        if sha256_crypt.verify(input_password, res.first().password):
            session['logged_in'] = True
            session['username'] = username
            return "LOGIN SUCCESS"
        else:
            raise IncorrectCredentialsException

    except Exception as e:
        return(str(e))

@app.route("/logout", methods=["POST"])
@login_required
def logout():
    session.clear()
    return "LOGOUT SUCCESS"


# import pdb; pdb.set_trace()
if __name__ == 'app':
    db.drop_all()
    db.create_all()
    app.run(debug=True)