

class User:
    def __init__(self, client_socket, ip_address, port, username='', nickname='', password='', usertype='user'):
        self._client_socket = client_socket
        self._ip_address = ip_address
        self._port = port
        self._username = username
        self._nickname = nickname
        self._password = password
        self._usertype = usertype
        self._real_name = ''
        self._ignor_list = []
        self._away_status = ''
        self._invisible_status = False
        self.channel_invited_to = ''
        self.current_channel = ''
        self._status = "Online"

    @property
    def socket(self):
        return self._client_socket

    @property
    def ipAddress(self):
        return self._ip_address

    @property
    def port(self):
        return self._port

    @property
    def username(self):
        return self._username

    @property
    def nickname(self):
        return self._nickname

    @property
    def usertype(self):
        return self._usertype

    @property
    def password(self):
        return self._password

    @property
    def status(self):
        return self._status

    @property
    def ignore_list(self):
        return self._ignor_list

    @username.setter
    def username(self, new_username):
        self._username = new_username

    @nickname.setter
    def nickname(self, new_nickname):
        self._nickname = new_nickname

    @usertype.setter
    def usertype(self, new_usertype):
        self._usertype = new_usertype

    @password.setter
    def password(self, new_password):
        self._password = new_password

    @status.setter
    def status(self, new_status):
        self._status = new_status