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