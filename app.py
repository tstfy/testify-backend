from datetime import datetime, timedelta

from flask import Flask, request, jsonify, session
from flask_cors import CORS
# from flask.ext.session import Session # TODO: maybe use this for session
# from flask_restful import Resource, Api
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
from passlib.hash import sha256_crypt
from functools import wraps
from testifybackend.config import SECRET_KEY, SQLALCHEMY_DATABASE_URI, MAIL_SETTINGS
from testifybackend.constants import (
    CHALLENGES_BASE_PATH,
    CHALLENGES_AUTH_FP,
    GIT,
    GIT_SERVER,
)

from testifybackend.classes.Exception import (
    AuthenticationRequiredException,
    UsernameTakenException,
    IncorrectCredentialsException,
    ChallengeExistsException,
    ChallengeRepositoryExistsException
)

from git import Repo

import htpasswd
import os
import shutil

app = Flask(__name__)
app.secret_key = SECRET_KEY
app.config['SQLALCHEMY_DATABASE_URI'] = SQLALCHEMY_DATABASE_URI
app.config.update(MAIL_SETTINGS)
CORS(app)

db = SQLAlchemy(app)
ma = Marshmallow(app)

class Company(db.Model):
    company_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), unique=True, nullable=False)

    def __init__(self, name):
        self.name = name

class CompanySchema(ma.Schema):
    class Meta:
        fields = ('name',)

company_schema = CompanySchema()

class Candidate(db.Model):
    candidate_id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    username = db.Column(db.String(80), unique=True, nullable=False)
    f_name = db.Column(db.String(30), nullable=False)
    l_name = db.Column(db.String(30), nullable=False)
    created = db.Column(db.DateTime())
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
    employer_id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    f_name = db.Column(db.String(30), nullable=False)
    l_name = db.Column(db.String(30), nullable=False)
    created = db.Column(db.DateTime())
    last_modified = db.Column(db.DateTime())
    company = db.Column(db.String(120), db.ForeignKey(Company.name), nullable=False)

    def __init__(self, username, email, password, f_name, l_name, company):
        self.username = username
        self.email = email
        self.password = password
        self.f_name = f_name
        self.l_name = l_name
        self.created = datetime.utcnow()
        self.last_modified = datetime.utcnow()
        self.company = company

class EmployerSchema(ma.Schema):
    class Meta:
        fields = ('employer_id', 'username', 'email', 'f_name', 'l_name', 'last_modified', 'company')

employer_schema = EmployerSchema()

class Challenge(db.Model):
    challenge_id = db.Column(db.Integer, primary_key=True)
    employer_id = db.Column(db.Integer, db.ForeignKey(Employer.employer_id))
    title = db.Column(db.String(80), nullable=False)
    description = db.Column(db.String(280))
    category = db.Column(db.String(80))
    created = db.Column(db.DateTime())
    last_modified = db.Column(db.DateTime())
    repo_link = db.Column(db.String(140), nullable=False)
    deleted = db.Column(db.Boolean, default=False, unique=False)

    def __init__(self, employer, title, description, category, repo_link):
        self.employer_id = employer
        self.title = title
        self.description = description
        self.category = category
        self.created = datetime.utcnow()
        self.last_modified = datetime.utcnow()
        self.repo_link = repo_link

class ChallengeSchema(ma.Schema):
    class Meta:
        # Fields to expose
        fields = ('employer_id', 'title', 'description', 'category', 'repo_link')

challenge_schema = ChallengeSchema()


class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user = db.Column(db.Integer, db.ForeignKey(Employer.employer_id))
    message = db.Column(db.String(140))
    created = db.Column(db.DateTime())
    last_modified = db.Column(db.DateTime())

    def __init__(self, user, message, repository):
        self.user = user
        self.message = message
        self.created = datetime.utcnow()
        self.last_modified = datetime.utcnow()


class CommentSchema(ma.Schema):
    class Meta:
        # Fields to expose
        fields = ('user', 'message', 'repository', 'last_modified')

comment_schema = CommentSchema()

class Repository(db.Model):
    repository_id = db.Column(db.Integer, primary_key=True)
    employer_id = db.Column(db.Integer, db.ForeignKey(Employer.employer_id), nullable=False)
    challenge_id = db.Column(db.Integer, db.ForeignKey(Challenge.challenge_id), nullable=False)
    candidate_id = db.Column(db.Integer, db.ForeignKey(Candidate.candidate_id), nullable=False)
    created = db.Column(db.DateTime())
    last_modified = db.Column(db.DateTime())

    def __init__(self, employer, candidate, challenge):
        self.employer_id = employer
        self.candidate_id = candidate
        self.challenge_id = challenge
        self.created = datetime.utcnow()
        self.last_modified = datetime.utcnow()


class RepositorySchema(ma.Schema):
    class Meta:
        # Fields to expose
        fields = ('repository_id', 'employer_id', 'candidate_id', 'challenge_id', 'last_modified')

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
    return int(user_count) > 0

def existing_challenge(employer, title):
    c = db.session.query(Challenge).filter(Challenge.employer_id==employer).filter(Challenge.title==title).count()
    return int(c) > 0

def company_challenge_count(employer):
    return db.session.query(Challenge).filter(Challenge.employer_id==employer).count()

@app.route("/challenges/<cid>/user/<uid>", methods=["POST"])
def assign_challenge(cid, uid, eid):
    try:
        challenge = cid
        employer = eid
        candidate = uid

        new_repository = Repository(employer, candidate, challenge)
        db.session.add(new_repository)
        db.session.commit()

        new_repository = db.session.query(Repository).filter(Repository.employer_id==employer).\
                        filter(Repository.candidate_id==candidate).\
                        filter(Repository.challenge_id==challenge).first()

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

@app.route("/challenges/<eid>", methods=["GET"])
# @authorization
def get_challenges(eid):
    try:
        challenges = db.session.query(Challenge).filter(Challenge.employer_id==eid).filter(Challenge.deleted==False)

        return jsonify(challenge_schema.dump(challenges).data)

    except Exception as e:
        return str(e)


@app.route("/challenges", methods=["POST"])
# @login_required; employer login required
# TODO need a way to recognize which user is making this call
def create_challenge():
    try:
        employer = request.json['employer']
        title = request.json['title']
        description = request.json['description']
        category = request.json['category']

        if existing_challenge(employer, title):
            raise ChallengeExistsException

        emp_record = db.session.query(Employer).filter(Employer.employer_id==employer).first()
        company = emp_record.company
        username = emp_record.username

        repo_name = ("%s.%s" % (title, GIT))
        path = os.path.join(CHALLENGES_BASE_PATH, company, repo_name)
        if os.path.exists(path):
            raise ChallengeRepositoryExistsException(path)

        Repo.init(path, bare=True)
        repo_loc = ("http://%s@%s" % (username, GIT_SERVER))
        repo_link = os.path.join(repo_loc, GIT, company, repo_name)

        new_challenge = Challenge(employer, title, description, category, repo_link)
        db.session.add(new_challenge)
        db.session.commit()

        new_challenge = db.session.query(Challenge).filter(Challenge.employer_id==employer).filter(Challenge.title==title).first()
        return jsonify(challenge_schema.dump(new_challenge).data)

    except Exception as e:
        return(str(e))

@app.route("/users", methods=["POST"])
def register_user():
    try:
        username = request.json['username']
        email = request.json['email']
        password = sha256_crypt.encrypt((str(request.json['password'])))
        f_name = request.json['f_name']
        l_name = request.json['l_name']
        company = request.json['company']

        if existing_username(username):
            raise UsernameTakenException

        else:
            company_exists = db.session.query(Company).filter(Company.name == company).scalar() is not None

            if not company_exists:
                new_company = Company(company)
                db.session.add(new_company)
                db.session.commit()
                path = os.path.join(CHALLENGES_BASE_PATH, company)
                if not os.path.exists(path):
                    os.makedirs(os.path.join(CHALLENGES_BASE_PATH, company))

            new_employer = Employer(username, email, password, f_name, l_name, company)
            db.session.add(new_employer)
            db.session.commit()

        with htpasswd.Basic(CHALLENGES_AUTH_FP) as authdb:
            authdb.add(username, str(request.json['password']))

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
        res = db.session.query(Employer).filter(Employer.username==username)
        if res.count() is 0:
            raise IncorrectCredentialsException

        assert res.count() is 1

        if sha256_crypt.verify(input_password, res.password):
            session['logged_in'] = True
            session['username'] = username
            return jsonify(employer_schema.dump(res.first()).data,logged_in = True)
        else:
            raise IncorrectCredentialsException

    except Exception as e:
        return(str(e))

@app.route("/logout", methods=["POST"])
@login_required
def logout():
    session.clear()
    return "LOGOUT SUCCESS"

def reset_git_directory():
    for d in os.listdir(CHALLENGES_BASE_PATH):
        full_path = os.path.join(CHALLENGES_BASE_PATH, d)
        if os.path.isdir(full_path):
            shutil.rmtree(full_path)

    with htpasswd.Basic(CHALLENGES_AUTH_FP) as authdb:
        for user in authdb.users:
            authdb.pop(user)

if __name__ == 'app':
    db.drop_all()
    db.create_all()
    reset_git_directory()
    app.run(debug=True)
