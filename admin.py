class Admin:
    def __init__(self, username, password) -> None:
        self.username = username
        self.password = password

    def check_admin(self, username, password):
        return ((self.username == username) and (self.password == password))


AdminUser = Admin('AdminAmdin', 'nbyuJBY763BYin')