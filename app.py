from datetime import datetime, timedelta

from flask import Flask, request, jsonify, session
from flask_cors import CORS
from flask_mail import Mail, Message
# from flask.ext.session import Session # TODO: maybe use this for session
# from flask_restful import Resource, Api
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
from passlib.hash import sha256_crypt
from functools import wraps
from testifybackend.config import (
    SECRET_KEY,
    SQLALCHEMY_DATABASE_URI,
    MAIL_SETTINGS,
)

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
    ChallengeRepositoryExistsException,
    InvalidCandidateException,
    AlreadyDeletedException,
    CandidateExistsException,
    InvalidChallengeException,
    CandidateInvitedException
)

from git import Repo

import htpasswd
import os
import shutil
import uuid

app = Flask(__name__)
app.secret_key = SECRET_KEY
app.config['SQLALCHEMY_DATABASE_URI'] = SQLALCHEMY_DATABASE_URI
app.config.update(MAIL_SETTINGS)

CORS(app)
mail = Mail(app)
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
    assigned_challenge = db.Column(db.Integer, db.ForeignKey(Challenge.id), nullable=True)
    deleted = db.Column(db.Boolean, default=False, nullable=False)

    def __init__(self, email, username, password, f_name, l_name, assigned_challenge):
        self.email = email
        self.username = username
        self.password = password
        self.f_name = f_name
        self.l_name = l_name
        self.created = datetime.utcnow()
        self.last_modified = datetime.utcnow()
        self.assigned_challenge = assigned_challenge

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
    deleted = db.Column(db.Boolean, default=False)

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
    title = db.Column(db.String(80), nullable=False, unique=True)
    description = db.Column(db.String(280))
    category = db.Column(db.String(80))
    created = db.Column(db.DateTime())
    last_modified = db.Column(db.DateTime())
    repo_link = db.Column(db.String(140), nullable=False)
    deleted = db.Column(db.Boolean, default=False, nullable=False)

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
        fields = ('challenge_id', 'employer_id', 'title', 'description', 'category', 'repo_link')

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
    repo_link = db.Column(db.String(140), nullable=False, unique=True)
    invited = db.Column(db.Boolean, default=False)

    def __init__(self, employer, candidate, challenge, repo_link, invited=False):
        self.employer_id = employer
        self.candidate_id = candidate
        self.challenge_id = challenge
        self.created = datetime.utcnow()
        self.last_modified = datetime.utcnow()
        self.repo_link = repo_link
        self.invited = invited


class RepositorySchema(ma.Schema):
    class Meta:
        # Fields to expose
        fields = ('repository_id', 'employer_id', 'candidate_id', 'challenge_id', 'last_modified, repo_link')

repository_schema = RepositorySchema()


def construct_data(endpoint, id, data):
    return {
            "type": endpoint,
            "id": id,
            "attributes": data
    }


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

def create_unique_uname(email, f_name, l_name):
# check db if email w/o domain exists in candidate table; if not create entry, otherwise generate unique entry by using f_name, l_name
    try:
        username = email.split("@")[0]
        if not db.session.query(Candidate).filter(Candidate.username==username).count() is 0:
            # username exists so need to make unique one from name
            f_initial = f_name[0]
            possible_collisions = db.session.query(Candidate).filter(Candidate.l_name==l_name).filter(Candidate.f_name.like(("%s%" % (f_initial)))).count()
            if possible_collisions is 0:
                username = f_initial + l_name
            else:
                username = ("%s%d%s" % (f_initial, possible_collisions, l_name))

        return username

    except Exception as e:
        return(str(e))

def create_candidate_pass():
    return uuid.uuid4()

#TODO: login_required
@app.route("/challenges/<challenge_id>/candidates", methods=["POST"])
def add_candidates(eid, challenge_id):
    try:
        email = request.json['email']
        f_name = request.json['f_name']
        l_name = request.json['l_name']
        username = create_unique_uname(email, f_name, l_name)
        password = create_candidate_pass()
        assigned_challenge = challenge_id

        if not db.session.query(Candidate).filter(Candidate.email==email).count() is 0:
            raise CandidateExistsException

        new_candidate = Candidate(email, username, password, f_name, l_name, assigned_challenge)
        db.session.add(new_candidate)
        db.session.commit()

        candidate_record = db.session.query(Candidate).filter(Candidate.email==email).first()
        return jsonify(candidate_schema.dump(candidate_record))

    except Exception as e:
        return(str(e))

#TODO: login_required
@app.route("/challenges/<cid>/candidates", methods=["GET"])
def get_candidates(cid):
    try:
        candidates = db.session.query(Candidate).filter(Candidate.assigned_challenge==cid).filter(Candidate.deleted==False)
        return jsonify([candidate_schema.dump(candidate) for candidate in candidates])

    except Exception as e:
        return(str(e))

#TODO: login_required
@app.route("/challenges/<challenge_id>/candidates/<candidate_id>", methods=["DELETE"])
def delete_candidate(challenge_id, candidate_id):
    try:
        res = db.session.query(Candidate).get(candidate_id)
        if not res.count() is 1 :
            raise InvalidCandidateException(candidate_id)

        res = res.first()
        if res.deleted:
            raise AlreadyDeletedException(candidate_id)

        res.deleted = True
        db.session.commit()
        return jsonify(candidate_schema.dump(res))

    except Exception as e:
        return(str(e))

#TODO make /user/eid/challenges/cid/candidates/cand_id GET route to see task progression

#TODO: login_required
@app.route("/challenges/<challenge_id>/invite", methods=["POST"])
def invite_candidates(challenge_id):
    try:
        eid = request.json['employer_id']
        candidate_ids = request.json['candidate_ids']

        res = db.session.query(Employer).join(Challenge).filter(Employer.employer_id==eid).filter(Challenge.challenge_id==challenge_id)
        if not res.count() == 1:
            raise InvalidChallengeException(challenge_id)

        res = res.first()
        employer = employer_schema.dump(res)
        challenge = challenge_schema.dump(res)

        company = employer.company
        orig_repo_name = ("%s.%s" % (challenge.title, GIT))
        # orig_repo_loc = ("http://%s@%s" % (employer.username, GIT_SERVER))
        # orig_repo_link = os.path.join(orig_repo_loc, GIT, company, orig_repo_name)

        challenge_repo = Repo(os.path.join(CHALLENGES_BASE_PATH, company, orig_repo_name))
        error_candidates = []

        for candidate_id in candidate_ids:
            # check that candidate belongs to challenge
            res = db.session.query(Candidate).get(candidate_id)
            if not res.count() == 1:
                error_candidates.append(candidate_id)
                continue

            candidate = res.first()

            if not candidate.assigned_challenge == challenge_id:
                error_candidates.append(candidate_id)
                continue

            # check if repo already exists
            if not db.session.query(Repository).filter(Repository.candidate_id==candidate_id).count() == 0:
                error_candidates.append(candidate_id)
                continue

            candidate_repo_name = ("%s.%s" % (candidate.username, GIT))
            candidate_repo_loc = ("http://%s@%s" % (candidate.username, GIT_SERVER))
            candidate_repo_link = os.path.join(candidate_repo_loc, GIT, company, challenge.title, candidate_repo_name)

            # clone repo
            candidate_repo = challenge_repo.clone(os.path.join(CHALLENGES_BASE_PATH, company, challenge.title, candidate_repo_name))
            new_repo = Repository(employer.employer_id, candidate_id, challenge.challenge_id, candidate_repo_link, invited=True)
            db.session.add(new_repo)
            db.session.commit()

            # enter candidate into htpasswd

            with htpasswd.Basic(CHALLENGES_AUTH_FP) as authdb:
                authdb.add(candidate.username, candidate.password)

        # send emails to candidates
        contact_candidates = candidate_ids - error_candidates
        query = db.session.query(Candidate.f_name,
                                 Candidate.l_name,
                                 Candidate.email,
                                 Candidate.username,
                                 Candidate.password).filter(Candidate.id.in_(contact_candidates))

        candidate_rows = jsonify([candidate_schema.dump(candidate) for candidate in query.all()])
        candidate_infos = [{'FirstName': c.f_name,
                            'LastName': c.l_name,
                            'Email': c.email,
                            'Username': c.username,
                            'Password': c.password} for c in candidate_rows]

        with mail.connect() as conn:
            for candidate_info in candidate_infos:
                f_name, l_name, email = candidate_info['FirstName'], candidate_info['LastName'], candidate_info['Email']
                username, password = candidate_info['Username'], candidate_info['Password']
                message = ('TESTING\nusername: %s\npassword: %s' % (username, password))
                subject = ("Hello, %s %s" % (f_name, l_name))
                msg = Message(recipients=[email],
                                body=message,
                                subject=subject)
                conn.send(msg)

        # return all new repos created
        if error_candidates:
            raise InvalidCandidateException(*candidate_ids)

        new_repos = db.session.query(Repository).filter(Repository.challenge_id==challenge.challenge_id)
        return jsonify([repository_schema.dump(repository) for repository in new_repos])

    except Exception as e:
        return(str(e))

@app.route("/challenges", methods=["GET"])
# @authorization
def get_challenges():
    try:
        eid = request.args.get("eid")
        challenges = db.session.query(Challenge)\
                               .filter(Challenge.employer_id==eid)\
                               .filter(Challenge.deleted==False)
        data = [challenge_schema.dump(challenge).data for challenge in challenges]
        json_data = [construct_data("challenges", int(d["challenge_id"]), d) for d in data]
        return jsonify({"data": json_data})

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

# TODO: need to add login_required wrapper
@app.route("/user/<id>", methods=["GET"])
def user_detail(id):
    user = db.session.query(Employer).filter(Employer.employer_id == id).first()
    data = employer_schema.dump(user).data
    return jsonify({"data": construct_data("user", id, data)})


# @app.route("/user/<id>", methods=["PUT"])
# @login_required
# def user_update(id):
#     try:
#         user = Employer.query.get(id)
#         username = request.json['username']
#         email = request.json['email']

#         if existing_username(username):
#             raise UsernameTakenException

#         user.email = email
#         user.username = username
#         user.last_modified = datetime.utcnow()

#         db.session.commit()
#         return employer_schema.jsonify(user)

#     except Exception as e:
#         return(str(e))

# TODO: not sure if it will be supported, but consider cleanup if implemented
@app.route("/user/<id>", methods=["DELETE"])
@login_required
def user_delete(id):
    user = Employer.query.get(id)
    user.deleted = True
    db.session.commit()

    return jsonify(employer_schema.dump(user))


@app.route("/login", methods=["POST"])
def login_page():
    try:
        username  = request.json['username']
        input_password = request.json['password']
        res = db.session.query(Employer).filter(Employer.username==username)
        if res.count() == 0:
            raise IncorrectCredentialsException

        assert res.count() == 1
        res = res.first()
        if sha256_crypt.verify(input_password, res.password):
            session['logged_in'] = True
            session['username'] = username
            return jsonify(employer_schema.dump(res).data)
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
