class User:
    def __init__(self, nickname, email, password):
        self.nickname = nickname
        self.email = email
        self.password = password

class Message:
    def __init__(self, email_from, email_to, content):
        self.email_from = email_from
        self.email_to = email_to
        self.content = content