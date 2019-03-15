from flask import request, jsonify, session
from flask_mail import Message
from passlib.hash import sha256_crypt
from functools import wraps
from testifybackend.constants import (
    CHALLENGES_BASE_PATH,
    CHALLENGES_AUTH_FP,
    GIT,
    GIT_SERVER,
    CandidateStatus
)
from testifybackend.models import (
    Candidate,
    Employer,
    Challenge,
    Repository,
    Company,
)
from testifybackend.schemas import (
    CompanySchema,
    EmployerSchema,
    ChallengeSchema,
    CandidateSchema,
    RepositorySchema,
)
from testifybackend.exceptions import (
    AuthenticationRequiredException,
    UsernameTakenException,
    IncorrectCredentialsException,
    ChallengeExistsException,
    ChallengeRepositoryExistsException,
    InvalidCandidateException,
    AlreadyDeletedException,
    CandidateExistsException,
    InvalidChallengeException,
    InvalidEmployerException,
    InvalidCandidateStatusException
)
from . import db, mail, app
from git import Repo

import htpasswd
import os
import shutil
import uuid
import subprocess
import errno

company_schema = CompanySchema()
employer_schema = EmployerSchema()
challenge_schema = ChallengeSchema()
candidate_schema = CandidateSchema()
repository_schema = RepositorySchema()


def _chown(path, uid, gid):
    os.chown(path, uid, gid)
    for item in os.listdir(path):
        itempath = os.path.join(path, item)
        if os.path.isfile(itempath):
            os.chown(itempath, uid, gid)
        elif os.path.isdir(itempath):
            os.chown(itempath, uid, gid)
            _chown(itempath, uid, gid)


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
    user_count = db.session.query(Employer)\
                           .filter(Employer.username == username)\
                           .count()

    return int(user_count) > 0


def existing_challenge(employer, title):
    c = db.session.query(Challenge)\
                  .filter(Challenge.employer_id == employer)\
                  .filter(Challenge.title == title)\
                  .count()

    return int(c) > 0


def company_challenge_count(employer):
    return db.session.query(Challenge)\
                     .filter(Challenge.employer_id == employer)\
                     .count()


# check db if email w/o domain exists in candidate table; if not create entry,
# otherwise generate unique entry by using f_name, l_name
def create_unique_uname(email, f_name, l_name):
    try:
        username = email.split("@")[0]
        if not db.session.query(Candidate)\
                         .filter(Candidate.username == username)\
                         .count() == 0:
            # username exists so need to make unique one from name
            f_initial = f_name[0]
            possible_collisions = db.session\
                                    .query(Candidate)\
                                    .filter(Candidate.l_name == l_name)\
                                    .filter(Candidate.f_name.like(("%s%" % (f_initial))))\
                                    .count()
            if possible_collisions is 0:
                username = f_initial + l_name
            else:
                username = ("%s%d%s" % (f_initial, possible_collisions, l_name))

        return username

    except Exception as e:
        return(str(e))


def create_candidate_pass():
    return str(uuid.uuid4())


@app.route("/challenges/<challenge_id>/candidates/<candidate_id>", methods=["PUT"])
def update_candidate_status(challenge_id, candidate_id):
    try:
        candidate = db.session.query(Candidate).get(candidate_id)
        if not candidate.assigned_challenge == challenge_id:
            raise InvalidCandidateException(candidate_id)

        status = request.json['status'].strip().lower()
        if status == "rejected":
            candidate.status = CandidateStatus.REJECTED.value
        elif status == "accepted":
            candidate.status = CandidateStatus.ACCEPTED.value
        else:
            raise InvalidCandidateStatusException(candidate_id, status)

        db.session.commit()
        updated_candidate = db.session.query(Candidate).get(candidate_id)
        return jsonify(candidate_schema.dump(updated_candidate))

    except Exception as e:
        return(str(e))


@app.route("/challenges/<challenge_id>/candidates", methods=["POST"])
def add_candidates(challenge_id):
    try:
        email = request.json['email']
        f_name = request.json['f_name']
        l_name = request.json['l_name']

        if not db.session.query(Candidate)\
                         .filter(Candidate.email == email)\
                         .count() == 0:
            raise CandidateExistsException(email)

        username = create_unique_uname(email, f_name, l_name)
        password = create_candidate_pass()
        assigned_challenge = challenge_id


        new_candidate = Candidate(email, username, password, f_name, l_name, assigned_challenge)
        db.session.add(new_candidate)
        db.session.commit()

        candidate_record = db.session.query(Candidate)\
                                     .filter(Candidate.email == email)\
                                     .first()
        return jsonify(candidate_schema.dump(candidate_record))

    except Exception as e:
        return(str(e))


@app.route("/challenges/candidates", methods=["GET"])
def get_candidates():
    try:
        challenge_id = request.args.get("cid")
        candidates = db.session.query(Candidate)\
                               .filter(Candidate.assigned_challenge == challenge_id)\
                               .filter(Candidate.deleted == False)

        data = [candidate_schema.dump(candidate).data for candidate in candidates]
        json_data = [construct_data("candidates", int(d["candidate_id"]), d) for d in data]
        return jsonify({"data": json_data})

    except Exception as e:
        return(str(e))


@app.route("/challenges/<challenge_id>/candidates/<candidate_id>", methods=["DELETE"])
def delete_candidate(challenge_id, candidate_id):
    try:
        res = db.session.query(Candidate).get(candidate_id)
        if res is None:
            raise InvalidCandidateException(candidate_id)

        res = res.first()
        if res.deleted:
            raise AlreadyDeletedException(candidate_id)

        res.deleted = True
        db.session.commit()
        return jsonify(candidate_schema.dump(res))

    except Exception as e:
        return(str(e))

# TODO make /user/eid/challenges/cid/candidates/cand_id GET route to see task progression

def copy_repo(src, dst):
    try:
        shutil.copytree(src, dst)
    except OSError as exc: # python >2.5
        if exc.errno == errno.ENOTDIR:
            shutil.copy(src, dst)
        else:
            raise

def create_candidate_repo(employer_repo, candidate, res):
    candidate_repo_name = ("%s.%s" % (candidate.username, GIT))
    candidate_repo_loc = ("http://%s@%s" % (candidate.username, GIT_SERVER))
    candidate_repo_link = os.path.join(candidate_repo_loc, GIT, res.company, res.title, candidate_repo_name)

    # copy repo
    candidate_repo = os.path.join(CHALLENGES_BASE_PATH, res.company, res.title, candidate_repo_name)
    copy_repo(employer_repo, candidate_repo)
    # challenge_repo.clone(os.path.join(CHALLENGES_BASE_PATH, res.company, res.title, candidate_repo_name))
    new_repo = Repository(res.employer_id, candidate.candidate_id, res.challenge_id)
    db.session.add(new_repo)

    # update Candidate record
    candidate_record = db.session.query(Candidate).get(candidate.candidate_id)
    candidate_record.repo_link = candidate_repo_link

def add_to_htpasswd(candidate):
    with htpasswd.Basic(CHALLENGES_AUTH_FP) as authdb:
        authdb.add(candidate.username, candidate.password)

def send_email_to_candidate(conn, c, res):
    c.status = CandidateStatus.INVITED.value
    credentials_msg = ("Credentials to the repository with the challenge:\nusername: %s\npassword: %s\n" % (c.username, c.password))
    instructions = ("\n\nCopy and paste the following into a terminal to start:\n\n\tgit clone %s" % (c.repo_link))
    body = credentials_msg + instructions
    subject = ("Hello %s %s, new challenge %s sent from %s" % (c.f_name, c.l_name, res.title, res.company))
    msg = Message(recipients=[c.email], body=body, subject=subject)
    conn.send(msg)

@app.route("/challenges/<challenge_id>/invite", methods=["POST"])
def invite_candidates(challenge_id):
    try:
        eid = request.json['employer_id']
        candidate_ids = request.json['candidate_ids']

        res = db.session.query(Employer).join(Challenge)\
            .add_columns(Employer.employer_id, Employer.company, Challenge.challenge_id, Challenge.title)\
            .filter(Employer.employer_id == eid)\
            .filter(Challenge.challenge_id == challenge_id)
        if not res.count() == 1:
            raise InvalidChallengeException(challenge_id)

        res = res.first()
        cid = res.challenge_id
        orig_repo_name = ("%s.%s" % (res.title, GIT))

        employer_repo = os.path.join(CHALLENGES_BASE_PATH, res.company, orig_repo_name)
        error_candidates = []

        for candidate_id in set(list(candidate_ids)):
            # check that candidate belongs to challenge
            candidate = db.session.query(Candidate).get(candidate_id)
            if candidate is None:
                error_candidates.append(candidate_id)
                continue

            if not str(candidate.assigned_challenge) == challenge_id:
                error_candidates.append(candidate_id)
                continue

            # check if repo already exists
            if not db.session.query(Repository)\
                             .filter(Repository.candidate_id == candidate_id)\
                             .count() == 0:
                error_candidates.append(candidate_id)
                continue

            create_candidate_repo(employer_repo, candidate, res)

            # enter candidate into htpasswd
            add_to_htpasswd(candidate)

        db.session.commit()

        # send emails to candidates
        contact_candidates = set(candidate_ids) - set(error_candidates)
        candidates = db.session.query(Candidate)\
                        .filter(Candidate.candidate_id.in_(contact_candidates))

        with mail.connect() as conn:
            for candidate in candidates:
                if candidate.already_sent_invite():
                    continue
                send_email_to_candidate(conn, candidate, res)

        db.session.commit()

        # return all new repos created
        if error_candidates:
            raise InvalidCandidateException(*candidate_ids)

        new_repos = db.session.query(Repository).filter(Repository.challenge_id==cid)
        return jsonify([repository_schema.dump(repository) for repository in new_repos])

    except Exception as e:
        return(str(e))


@app.route("/challenges", methods=["GET"])
# @authorization
def get_challenges():
    try:
        eid = request.args.get("eid")
        user = Employer.query.get(eid)
        if user is None:
            raise InvalidEmployerException(eid)

        challenges = db.session.query(Challenge)\
                               .filter(Challenge.employer_id == eid)\
                               .filter(Challenge.deleted == False)
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

        user = Employer.query.get(employer)
        if user is None:
            raise InvalidEmployerException(employer)

        if existing_challenge(employer, title):
            raise ChallengeExistsException

        emp_record = db.session.query(Employer)\
                               .filter(Employer.employer_id == employer)\
                               .first()
        company = emp_record.company
        username = emp_record.username

        repo_name = ("%s.%s" % (title, GIT))
        path = os.path.join(CHALLENGES_BASE_PATH, company, repo_name)
        if os.path.exists(path):
            raise ChallengeRepositoryExistsException(path)

        Repo.init(path, bare=True)
        _chown(path, 1005, 33)
        subprocess.call(['sudo', 'chmod', '-R', '777', path])
        repo_loc = ("http://%s@%s" % (username, GIT_SERVER))
        repo_link = os.path.join(repo_loc, GIT, company, repo_name)

        new_challenge = Challenge(employer, title, description, category, repo_link)
        db.session.add(new_challenge)
        db.session.commit()

        new_challenge = db.session.query(Challenge)\
                                  .filter(Challenge.employer_id == employer)\
                                  .filter(Challenge.title == title)\
                                  .first()
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
            company_exists = db.session.query(Company)\
                                       .filter(Company.name == company)\
                                       .scalar() is not None

            if not company_exists:
                new_company = Company(company)
                db.session.add(new_company)
                db.session.commit()
                path = os.path.join(CHALLENGES_BASE_PATH, company)
                if not os.path.exists(path):
                    os.makedirs(os.path.join(CHALLENGES_BASE_PATH, company))
                    _chown(os.path.join(CHALLENGES_BASE_PATH, company), 1005, 33)

            new_employer = Employer(username, email, password, f_name, l_name, company)
            db.session.add(new_employer)
            db.session.commit()

        with htpasswd.Basic(CHALLENGES_AUTH_FP) as authdb:
            authdb.add(username, str(request.json['password']))

        new_employer = db.session.query(Employer)\
                                 .filter(Employer.username == username)\
                                 .first()
        return jsonify(employer_schema.dump(new_employer).data)

    except Exception as e:
        return(str(e))


@app.route("/user", methods=["GET"])
def user_detail():
    eid = request.args.get("eid")
    user = Employer.query.get(eid)
    if user is None:
        raise InvalidEmployerException(eid)

    data = employer_schema.dump(user).data
    return jsonify({"data": construct_data("user", eid, data)})


@app.route("/user/<eid>", methods=["DELETE"])
@login_required
def user_delete(eid):
    user = Employer.query.get(eid)
    if user is None:
        raise InvalidEmployerException(eid)
    user.deleted = True
    db.session.commit()

    return jsonify(employer_schema.dump(user))


@app.route("/login", methods=["POST"])
def login_page():
    try:
        username = request.json['username']
        input_password = request.json['password']
        res = db.session.query(Employer).filter(Employer.username == username)
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
