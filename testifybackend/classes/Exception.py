class AuthenticationRequiredException(Exception):

    def __init__(self):
        super().__init__('Login is required')

class UsernameTakenException(Exception):

    def __init__(self):
        super().__init__('Username is already taken')

class IncorrectCredentialsException(Exception):

    def __init__(self):
        super().__init__('Incorrect username/password')