class AuthenticationRequiredException(Exception):

    def __init__(self):
        super().__init__('Login is required')

class UsernameTakenException(Exception):

    def __init__(self):
        super().__init__('Username is already taken')

class InvalidEmployerException(Exception):

    def __init__(self, eid):
        super().__init__('Employer with id(%s) does not exist' % eid)

class IncorrectCredentialsException(Exception):

    def __init__(self):
        super().__init__('Incorrect username/password')

class ChallengeExistsException(Exception):

    def __init__(self):
        super().__init__('Challenge with the given title exists for the employer')

class ChallengeRepositoryExistsException(Exception):

    def __init__(self, path):
        super().__init__('Repository %s already exists' % path)

class CandidateExistsException(Exception):
    def __init__(self, email):
        super().__init__('Candidate with provided email %s already exists' % email)

class InvalidCandidateException(Exception):

    def __init__(self, *candidate_ids):
        super().__init__('Candidate id(s) provided %s is/are invalid and invite failed for those id(s)' % candidate_ids)

# class CandidateInvitedException(Exception):

#     def __init__(self, candidate_id, challenge):
#         super().__init__('Candidate id provided (%s) is already invited to challenge (%s)' % (candidate_id, challenge))

class AlreadyDeletedException(Exception):

    def __init__(self, candidate_id):
        super().__init__('Candidate with provided candidate id (%s) is already deleted' % candidate_id)

class InvalidChallengeException(Exception):

    def __init__(self, challenge_id):
        super().__init__('Challenge id provided (%s) is invalid' % challenge_id)