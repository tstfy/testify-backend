from . import ma


class CompanySchema(ma.Schema):
    class Meta:
        fields = ('name',)


class EmployerSchema(ma.Schema):
    class Meta:
        fields = ('employer_id', 'username', 'email', 'f_name', 'l_name', 'last_modified', 'company')


class ChallengeSchema(ma.Schema):
    class Meta:
        fields = ('challenge_id', 'employer_id', 'title', 'description', 'category', 'repo_link')


class CandidateSchema(ma.Schema):
    class Meta:
        fields = ('candidate_id', 'email', 'f_name', 'l_name', 'last_modified', 'status')


class RepositorySchema(ma.Schema):
    class Meta:
        fields = ('repository_id', 'employer_id', 'candidate_id', 'challenge_id', 'repo_link', 'last_modified')

class CandidateRepositorySchema(ma.Schema):
    class Meta:
        fields = ('candidate_id', 'employer_id', 'email', 'f_name', 'l_name', 'status', 'repo_link')