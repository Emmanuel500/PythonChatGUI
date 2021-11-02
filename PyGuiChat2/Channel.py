
class Channel:
    def __init__(self, name, topic, password):
        self.users = [] # A list of the users in this channel.
        self.currentUsers = [] # A list of the users currently in this channel.
        self.channel_name = name
        self.log_file = "logs\\" + name + ".txt"
        file = open(self.log_file, "w")             #Create/clear log file for this channel
        file.close()
        self.channel_password = password
        self.channel_topic = topic
        self.secret_mode = False
        self.private_mode = False
        self.invite_only_mode = False
        self.operator_topic_mode = False
        self.no_outside_mode = False
        self.moderate_mode = False
        self.user_limits = 100

    def welcome_user(self, username):
        all_users = self.get_all_users_in_channel()
        file = open(self.log_file, "a")
        file.write('\n\n> {0} has joined the channel {1}!\n'.format(username, self.channel_name))
        file.close()
        for user in self.currentUsers:
            if user.username is username:
                user.socket.sendall('/join|\n\n> {0} have joined the channel {1}!\n|{2}\n'.format("You", self.channel_name, all_users).encode('utf8'))
            else:
                user.socket.sendall('/join|\n\n> {0} has joined the channel {1}!\n|{2}\n'.format(username, self.channel_name, all_users).encode('utf8'))

    def broadcast_message(self, chatMessage, username=''):
        file = open(self.log_file, "a")
        if (chatMessage.split("|")[0] == "/left"):
            file.write("\n>{0} has left the channel {1}\n".format(username, self.channel_name))
        else:
            file.write("{0}: {1}".format(username, chatMessage))
        file.close()
        for user in self.currentUsers:
            if user.username is username:
                user.socket.sendall("You: {0}".format(chatMessage).encode('utf8'))
            elif not username in user.ignore_list:
                user.socket.sendall("{0}: {1}".format(username, chatMessage).encode('utf8'))



    def get_all_users_in_channel(self):
        return ' '.join([user.username for user in self.users])

    def remove_user_from_channel(self, user):
        self.users.remove(user)
        if user in self.currentUsers:
            self.currentUsers.remove(user)
            user.current_channel = ''
        leave_message = "/left|\n>{0} has left the channel {1}\n|{0}".format(user.username, self.channel_name)
        self.broadcast_message(leave_message, user.username)
