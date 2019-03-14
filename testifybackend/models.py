from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from testifybackend.app import db

class Company(db.Model):
    company_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), unique=True, nullable=False)

    def __init__(self, name):
        self.name = name

class Candidate(db.Model):
    candidate_id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    username = db.Column(db.String(80), unique=True, nullable=False)
    f_name = db.Column(db.String(30), nullable=False)
    l_name = db.Column(db.String(30), nullable=False)
    created = db.Column(db.DateTime())
    last_modified = db.Column(db.DateTime())
    assigned_challenge = db.Column(db.Integer, db.ForeignKey(Challenge.challenge_id), nullable=True)
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