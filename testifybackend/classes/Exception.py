class AuthenticationRequiredException(Exception):

    def __init__(self):
        super().__init__('Login is required')

class UsernameTakenException(Exception):

    def __init__(self):
        super().__init__('Username is already taken')

class IncorrectCredentialsException(Exception):

    def __init__(self):
        super().__init__('Incorrect username/password')

class ChallengeExistsException(Exception):

    def __init__(self):
        super().__init__('Challenge with the given title exists for the employer')

class ChallengeRepositoryExistsException(Exception):

    def __init__(self, path):
        super().__init__('Repository %s already exists', path)

class CandidateExistsException(Exception):
    def __init__(self, email):
        super().__init__('Candidate with provided email %s already exists', email)

class InvalidCandidateException(Exception):

    def __init__(self, candidate_id):
        super().__init__('Candidate id provided (%s) is invalid', candidate_id)

class AlreadyDeletedException(Exception):

    def __init__(self, candidate_id):
        super().__init__('Candidate with provided candidate id (%s) is already deleted', candidate_id)