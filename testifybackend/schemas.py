from . import ma

class CompanySchema(ma.Schema):
    class Meta:
        fields = ('name',)

class CandidateSchema(ma.Schema):
    class Meta:
        fields = ('email','f_name','l_name', 'last_modified')

class EmployerSchema(ma.Schema):
    class Meta:
        fields = ('employer_id', 'username', 'email', 'f_name', 'l_name', 'last_modified', 'company')

class ChallengeSchema(ma.Schema):
    class Meta:
        fields = ('challenge_id', 'employer_id', 'title', 'description', 'category', 'repo_link')

class CandidateSchema(ma.Schema):
    class Meta:
        fields = ('email','f_name','l_name', 'last_modified')

class RepositorySchema(ma.Schema):
    class Meta:
        fields = ('repository_id', 'employer_id', 'candidate_id', 'challenge_id', 'last_modified, repo_link')