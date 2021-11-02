import socket
import sys
import threading
import Channel
import User
import datetime

class Server:
    SERVER_CONFIG = {"MAX_CONNECTIONS": 15}

    HELP_MESSAGE = """\n> The list of commands available are:

/away [message]                     - If message is inputed, when user recieves a private message, the sender will recieve the away status message back, to remove simply call away command withou message.
/connect [targetServer] [port]      - Connect to a server with thet targetServer name and ports.[Notimplemented]
/change [channel]                   - !*New command implemented*!: To change current viewable changels from the list of change's user is currently in.
/die                                - Server shuts down (Admin only).
/help                               - Show the instructions.
/info                               - Provides information about server.
/invite [nickname] [channel]        - Invites a user with matching nickname to a channel with matching channel name, sender most be a member of the channel.
/ison [nickname1 nickname2 ...}     - Returns the nickname of the users who have matching nickname and are on the server. Can enter multiple at once, seperated by spaces.
/join [channel_name] [password]     - To create a new channel or try to join an existing channel with the correct password.
/kick [channel] [username]          - Removes user from channel (Channel operator only).
/kill [username]                    - Removes user from network (IRC/Admin operator only).
/knock [channel] [message]          - To send a notice and an optional message to a channel.
/quit                               - Exits the program.
/list                               - Lists all available channels.
/usermode [nickname] [flags]        - Changes the mode on the user that matches the nickname, for invisible mode or system operator mode, + to activate, - to deactivate. Multiple seperated by spaces. Flags: +i to make user invisible so they can't be seen by /who, /whois, /users, /userhost, or /ison; +o or +w or +s to make them server operator and recieve wallops messages.
/channelmode [channel][input][flags]- Changes the mode on the channel that matches the channel name, input is to specify a user or give an input depending on the flag run. Multiple seperated by spaces. Note that this means multiple lines of this command would be needed to use mode that require different input. Multiple seperated by spaces. Flags: +o make a user a channel operator; +p make channel private (no outside user can enter); +s make channel secret so it won't show in /list but can still be interacted with; +i makes channel invite-only so user can only enter through invites; +t makes only channel operatos capable of changing the channel topic; +n makes channel be in no-outside-mode so no notices from knocks will show; l [input=maximum] changes the maximum number of users in a channel, it won't kick users, but once limit is reach it won't allow more users to enter; +k [input=password] changes the password of the channel to the inputed one, or use - to remove the password.
/mychannels                         - !*New command implemented*!: To display all channel's user is currently on.
/nick [nickname]                    - Set up user's nickname (no duplicates).
/oper [username] [password]         - Turns user with the matching username and password into a sysop, except if they are admin.
/part [channel1,channel2,][message] - Exit list of channels (separated by a comma) with an optional parting message.
/ping <server1> [server2]           - Sends a ping to server1, and get a pong reply if online, pass on to server2 if specified.
/pong <server1> [server2]           - Sends a pong to server1, and get a ping reply if online, pass on to server2 if specified.
/privmsg [target_user] [message]    - Sends a private message to target user.
/restart                            - Server restarts (Admin only).
/rules                              - Displays server rules.
/setname [realname]                 - Changes user's real name.
/silence [+/-username1...]          - Add/remove users to the ignore list by simply writing +/- to add/remove and then the username, seperated by spaces
/time                               - Gives current time on server.
/topic [channel] <topic>            - If topic is empty, recieve topic from channel, other wise changes channel topic.
/userhost [nkname1 nkname2...]      - Returns information about the user who's nickname matches any of the nicknames giving (maximum of 5 nicknames separated by spaces).
/userip [nickname]                  - Display's the IP addres of the user that matches the nickname.
/users                              - Displays all user on server.
/version                            - Displays the version of server.
/wallops [message]                  - Sends a message to all operators of the server.
/who [name] <o>                     - Returns a list of server users that match name, add the word 'o' at the end to only get operators.
/whois [nickname1,nickname2,..]     - Returns information about the user who's nickname can be found withing any of the nicknames giving separated by commas.\n\n""".encode('utf8')

    BEFORE_HELP_MESSAGE = """\n> The list of current commands available are:

/quit                           - Exits the program.
/pass [password]                - Set up user's password (case sensitive).
/nick [nickname]                - Set up user's nickname (no duplicates).
/user [username] [realname]     - Set up user's username and real name.\n\n""".encode('utf8')

    WELCOME_MESSAGE = "\n> Welcome to our chat app!!!\nUse:\n/pass [password]\n/nick [nickname]\n/user [username] [real name]\nTo finish setting up connection\n".encode('utf8')

    VERSION_MESSAGE = """> The version of the server is 0.5.\n\n""".encode('utf8')

    COMPILE_TIME_MESSAGE = "> Server was compile at " + str(datetime.datetime.now()) + "\n\n"
    COMPILE_TIME_MSBYTE = COMPILE_TIME_MESSAGE.encode('utf8')

    RULE_MESSAGE = """> Rules of the server are:
    1. No cursing.
    2. No hacking.
    3. No running.
    4. No fighting.
    5. No shenanigans.\n\n""".encode('utf8')

    def __init__(self, host=socket.gethostbyname('localhost'), port=12900, allowReuseAddress=True, timeout=3):
        self.address = (host, port)
        self.channels = {} # Channel Name -> Channel
        self.users_channels_map = {} # User Name -> List of Channel Names
        self.client_thread_list = [] # A list of all threads that are either running or have finished their task.
        self.users = [] # A list of all the users who are connected to the server.
        self.exit_signal = threading.Event()
        self.restart_signal = False

        try:
            self.serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except socket.error as errorMessage:
            sys.stderr.write("Failed to initialize the server. Error - {0}".format(errorMessage))
            raise

        self.serverSocket.settimeout(timeout)

        if allowReuseAddress:
            self.serverSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            self.serverSocket.bind(self.address)
        except socket.error as errorMessage:
            sys.stderr.write('Failed to bind to address {0} on port {1}. Error - {2}'.format(self.address[0], self.address[1], errorMessage))
            raise

    def start_listening(self, defaultGreeting="\n> Welcome to our chat app!!! What is your full name?\n"):
        self.serverSocket.listen(Server.SERVER_CONFIG["MAX_CONNECTIONS"])

        try:
            while not self.exit_signal.is_set():
                try:
                    print("Waiting for a client to establish a connection\n")
                    clientSocket, clientAddress = self.serverSocket.accept()
                    print("Connection established with IP address {0} and port {1}\n".format(clientAddress[0], clientAddress[1]))
                    user = User.User(clientSocket, clientAddress[0], clientAddress[1])
                    self.users.append(user)
                    self.welcome_user(user)
                    clientThread = threading.Thread(target=self.client_thread, args=(user,))
                    clientThread.start()
                    self.client_thread_list.append(clientThread)
                except socket.timeout:
                    pass
        except KeyboardInterrupt:
            self.exit_signal.set()

        for client in self.client_thread_list:
            if client.is_alive():
                client.join()

    def welcome_user(self, user):
        banner_file_read = open("banner.txt", "r")
        user.socket.sendall(banner_file_read.read().encode('utf8'))
        banner_file_read.close()
        user.socket.sendall(Server.WELCOME_MESSAGE)

    def client_thread(self, user, size=4096):
        userExist = False
        correctPassword = False
        userIsBanned = False
        userIdentified = False

        while not userIdentified:
            chatMessage = user.socket.recv(size).decode('utf8')
            if self.exit_signal.is_set():
                break
            if not chatMessage:
                break
            if '/quit' in chatMessage.lower():
                self.quit(user)
                break
            elif '/pass' in chatMessage.lower():
                self.set_password(user, chatMessage)
            elif '/nick' in chatMessage.lower():
                self.set_nick(user, chatMessage)
            elif '/user' in chatMessage.lower():
                self.set_user(user, chatMessage)
            else:
                user.socket.sendall(Server.BEFORE_HELP_MESSAGE)

            if (not user.username == '') and (not user.nickname == '') and (not user.password == ''):
                user_file_read = open("users.txt", "r")
                for line in user_file_read:
                    if line.split()[0] == user.username:
                        userExist = True
                        if line.split()[1] == user.password:
                            correctPassword = True
                        user.usertype = line.split()[2]
                        if line.split()[3] == "true":
                            userIsBanned = True
                user_file_read.close()

                #Identify if user exist and correct password and not banned or new user
                if (userExist and correctPassword and not userIsBanned) or (not userExist):
                    userIdentified = True
                elif userExist and not correctPassword:
                    user.socket.sendall("Incorrect password.\n".encode('utf8'))
                elif userIsBanned:
                    user.socket.sendall("Banned users cannot enter chat, please /quit and try again.\n".encode('utf8'))

        if self.exit_signal.is_set():
            user.socket.sendall('/squit'.encode('utf8'))

        if userIdentified and not self.exit_signal.is_set():

            #user_file = open("users.txt", "a")
            #user_file.write(user.username + " " + user.password + " user false\n")
            #user_file.close()

            welcomeMessage = '\n> Welcome {0}, type /help for a list of helpful commands.\n\n'.format(user.username).encode('utf8')
            user.socket.sendall(welcomeMessage)
            self.users_channels_map[user.username] = []

            while True:
                chatMessage = user.socket.recv(size).decode('utf8')

                if self.exit_signal.is_set():
                    break

                if not chatMessage:
                    break

                if '/quit' in chatMessage.lower():
                    self.quit(user)
                    break
                # When user gets invited to a channel
                elif chatMessage == "yes" and not user.channel_invited_to == '' and self.channels[user.channel_invited_to].private_mode == False:
                    self.channels[user.channel_invited_to].users.append(user)
                    self.users_channels_map[user.username].append(user.channel_invited_to)
                    if not user.current_channel == '':
                        self.channels[user.current_channel].currentUsers.remove(user)
                    user.current_channel = user.channel_invited_to                  #Changing current view channel
                    self.channels[user.current_channel].currentUsers.append(user)
                    user.socket.sendall('/new'.encode('utf8'))                      #Clear the screen
                    self.channels[user.channel_invited_to].welcome_user(user.username)
                    user.channel_invited_to == ''
                elif '/list' in chatMessage.lower():
                    self.list_all_channels(user)
                elif '/help' in chatMessage.lower():
                    self.help(user)
                elif '/join' in chatMessage.lower():
                    self.join(user, chatMessage)
                elif '/away' in chatMessage.lower():
                    self.away(user, chatMessage)
                elif '/connect' in chatMessage.lower():
                    self.connect(user, chatMessage)
                elif '/change' in chatMessage.lower():
                    self.change(user, chatMessage)
                elif '/die' in chatMessage.lower():
                    self.die(user)
                elif '/info' in chatMessage.lower():
                    self.info(user)
                elif '/invite' in chatMessage.lower():
                    self.invite(user, chatMessage)
                elif '/ison' in chatMessage.lower():
                    self.ison(user, chatMessage)
                elif '/usermode' in chatMessage.lower():
                    self.mode_u(user, chatMessage)
                elif '/channelmode' in chatMessage.lower():
                    self.mode_c(user, chatMessage)
                elif '/mychannels' in chatMessage.lower():
                    self.mychannels(user)
                elif '/nick' in chatMessage.lower():
                    self.set_nick(user, chatMessage)
                elif '/notice' in chatMessage.lower():
                    self.notice(user, chatMessage)
                elif '/kick' in chatMessage.lower():
                    self.kick(user, chatMessage)
                elif '/kill' in chatMessage.lower():
                    self.kill(user, chatMessage)
                elif '/knock' in chatMessage.lower():
                    self.knock(user, chatMessage)
                elif '/oper' in chatMessage.lower():
                    self.oper(user, chatMessage)
                elif '/part' in chatMessage.lower():
                    self.part(user, chatMessage)
                elif '/ping' in chatMessage.lower():
                    self.ping(user, chatMessage)
                elif '/pong' in chatMessage.lower():
                    self.pong(user, chatMessage)
                elif '/privmsg' in chatMessage.lower():
                    self.privmsg(user, chatMessage)
                elif '/restart' in chatMessage.lower():
                    self.restart(user)
                elif '/rules' in chatMessage.lower():
                    self.rules(user)
                elif '/setname' in chatMessage.lower():
                    self.setname(user, chatMessage)
                elif '/silence' in chatMessage.lower():
                    self.silence(user, chatMessage)
                elif '/time' in chatMessage.lower():
                    self.time(user)
                elif '/topic' in chatMessage.lower():
                    self.topic(user, chatMessage)
                elif '/users' in chatMessage.lower():
                    self.show_users(user)
                elif '/userip' in chatMessage.lower():
                    self.userip(user, chatMessage)
                elif '/userhost' in chatMessage.lower():
                    self.userhost(user, chatMessage)
                elif '/version' in chatMessage.lower():
                    self.version(user)
                elif '/wallops' in chatMessage.lower():
                    self.wallops(user, chatMessage)
                elif '/whois' in chatMessage.lower():
                    self.whois(user, chatMessage)
                elif '/who' in chatMessage.lower():
                    self.who(user, chatMessage)
                else:
                    self.send_message(user, chatMessage + '\n')

            if self.exit_signal.is_set():
                user.socket.sendall('/squit'.encode('utf8'))

        user.socket.close()

    def quit(self, user):
        user.socket.sendall('/quit'.encode('utf8'))
        self.remove_user(user)

    def list_all_channels(self, user):
        if len(self.channels) == 0:
            chatMessage = "\n> No rooms available. Create your own by typing /join [channel_name]\n".encode('utf8')
            user.socket.sendall(chatMessage)
        else:
            chatMessage = '\n\n> Current channels available are: \n'
            for channel in self.channels:
                if self.channels[channel].secret_mode == False:
                    chatMessage += "    \n" + channel + ": " + str(len(self.channels[channel].users)) + " user(s)"
            chatMessage += "\n"
            user.socket.sendall(chatMessage.encode('utf8'))

    def help(self, user):
        user.socket.sendall(Server.HELP_MESSAGE)

    def join(self, user, chatMessage):
        isInSameRoom = False

        if len(chatMessage.split()) == 3 or 2:      #Assign password
            channelName = chatMessage.split()[1]
            topic = ""
            if len(chatMessage.split()) == 2:
                password = '@'
            else:
                password = chatMessage.split()[2]

            if user.username in self.users_channels_map: # Here we are switching to a new channel.
                if channelName in self.users_channels_map[user.username]:
                    user.socket.sendall("\n> You are already in channel: {0}\n".format(channelName).encode('utf8'))
                    isInSameRoom = True

            if not isInSameRoom:
                if not channelName in self.channels:
                    newChannel = Channel.Channel(channelName, topic, password)
                    self.channels[channelName] = newChannel
                    channel_file = open("channels.txt", "a")  # add channel to channel list file
                    channel_file.write(channelName + " " + topic + " " + password + "\n")
                    channel_file.close()

                correct_pass = True
                if not self.channels[channelName].channel_password == '@':      #Check for password in channel
                    if not password == self.channels[channelName].channel_password:
                        user.socket.sendall("\n>> Incorrect Password\n".encode('utf8'))
                        correct_pass = False

                # Connecting to channel if not invite-only or not private
                if correct_pass and self.channels[channelName].invite_only_mode == False and \
                        self.channels[channelName].private_mode == False and \
                        self.channels[channelName].user_limits > len(self.channels[channelName].users):
                    self.channels[channelName].users.append(user)
                    self.users_channels_map[user.username].append(channelName)
                    if not user.current_channel == '':
                        self.channels[user.current_channel].currentUsers.remove(user)
                    user.current_channel = channelName                 #Changing current view channel
                    self.channels[user.current_channel].currentUsers.append(user)
                    user.socket.sendall('/new'.encode('utf8'))          #Clear the screen
                    self.channels[channelName].welcome_user(user.username)
        else:
            self.help(user)

    def bye_message(self, user, channelName, chatMessage): #Bye message
        if user.username in self.users_channels_map:
            self.channels[channelName].broadcast_message(chatMessage, "{0}".format(user.username))

    def send_message(self, user, chatMessage): #
        if user.username in self.users_channels_map and not user.current_channel == '':
            self.channels[user.current_channel].broadcast_message(chatMessage, "{0}".format(user.username))
        else:
            chatMessage = """\n> You are currently not in any channels:

Use /list to see a list of available channels.
Use /join [channel name] to join a channel.\n\n""".encode('utf8')

            user.socket.sendall(chatMessage)

    def remove_user(self, user):
        if user.username in self.users_channels_map:
            for channelName in self.users_channels_map[user.username]:
                self.channels[channelName].remove_user_from_channel(user)
            del self.users_channels_map[user.username]
            user.current_channel = ''
        self.users.remove(user)
        print("Client: {0} has left\n".format(user.username))

    def server_shutdown(self):
        print("Shutting down chat server.\n")
        self.serverSocket.close()

    #****************************#

    def away(self, user, chatMessage):                   #Away Implemented
        if len(chatMessage.split()) >= 2:
            message = chatMessage.split(None, 1)[1]
            user._away_status = message
        elif len(chatMessage.split()) == 1:
            user._away_status = ''
        else:
            self.help(user)

    def connect(self, user, chatMessage):                #???????
        print("connect\n")

    def change(self, user, chatMessage):                #To change channel
        if len(chatMessage.split()) == 2:
            channelSwitch = chatMessage.split()[1]
            if channelSwitch in self.users_channels_map[user.username]:
                if not user.current_channel == '':
                    self.channels[user.current_channel].currentUsers.remove(user)
                user.current_channel = channelSwitch                        # Changing current view channel
                self.channels[user.current_channel].currentUsers.append(user)
                #For updating the windows to the new channel
                all_users = self.channels[user.current_channel].get_all_users_in_channel()
                user.socket.sendall('/new'.encode('utf8'))
                file = open(self.channels[user.current_channel].log_file, "r")
                previMessages = file.read()
                file.close()
                user.socket.sendall(('/change\n|' + all_users + "\n|" + previMessages + "\n").encode('utf8'))
        else:
            self.help(user)

    def die(self, user):                      #Die Implemented (Admin only)
        if (user.usertype == 'admin'):
            self.quit(user)
            self.exit_signal.set()
        else:
            user.socket.sendall("> Not an admin.\n".encode('utf8'))

    def info(self, user):               #Info Implemented
        self.version(user)
        self.rules(user)
        user.socket.sendall(Server.COMPILE_TIME_MSBYTE)

    def invite(self, user, chatMessage):                   #Invite Implemented
        if len(chatMessage.split()) == 3:
            nickname = chatMessage.split()[1]
            channelName = chatMessage.split()[2]
            for selectedUsers in self.users:
                if (nickname == selectedUsers.nickname) and (channelName == user.current_channel) and (channelName in self.channels):
                    selectedUsers.socket.sendall(("> Invited to join the channel " + channelName + ", type yes to join\n").encode('utf8'))
                    selectedUsers.channel_invited_to = channelName

        else:
            self.help(user)

    def ison(self, user, chatMessage):                   #Is on Implemented
        user.socket.sendall("Is on:\n".encode('utf8'))
        if len(chatMessage.split()) >= 2:
            nickname = chatMessage.split(None, 1)[1].split(" ")
            for selectedUsers in self.users:
                for nick in nickname:
                    if (nick == selectedUsers.nickname) and (selectedUsers._invisible_status == False):
                        user.socket.sendall((selectedUsers.nickname + "\n").encode('utf8'))
        else:
            self.help(user)

    def kick(self, user, chatMessage):                   #Kick Implemented (channel operator only)
        if (len(chatMessage.split()) == 3) and (user.usertype == "channelop"):
            username = chatMessage.split()[2]
            channelName = chatMessage.split()[1]
            for selectedUsers in self.users:
                if selectedUsers.username == username and channelName in selectedUsers.current_channel \
                        and channelName in self.channels:
                    self.part(selectedUsers, "\part " + channelName)
        else:
            self.help(user)

    def kill(self, user, chatMessage):                   #Kill Implemneted (system operator or admin only)
        if (len(chatMessage.split()) == 2) and (user.usertype == "sysop" or "admin"):
            username = chatMessage.split()[1]
            for selectedUsers in self.users:
                if selectedUsers.username == username:
                    self.quit(selectedUsers)
        else:
            self.help(user)

    def knock(self, user, chatMessage):                   #Knock Implemented
        if len(chatMessage.split()) == 2:
            channelName = chatMessage.split()[1]
            if self.channels[channelName].no_outside_mode == False:
                self.channels[channelName].broadcast_message("NOTICE\n", user.username)
        elif len(chatMessage.split()) >= 3:
            channelName = chatMessage.split()[1]
            if self.channels[channelName].no_outside_mode == False:
                message = chatMessage.split(None, 2)[2]
                self.channels[channelName].broadcast_message("NOTICE: " + message + "\n", user.username)
        else:
            self.help(user)

    def mode_u(self, user, chatMessage):                   #User Mode Implemented
        if len(chatMessage.split()) >= 2:
            nickname = chatMessage.split()[1]
            flags = chatMessage.split(None, 2)[2].split(" ")
            for selectedUser in self.users:
                if selectedUser.nickname == nickname:
                    for mode in flags:
                        if mode[0] == '+' and mode[1] == "i": #User cannot be seen: /ison /users /who /whois /userhost
                            selectedUser._invisible_status = True
                        elif mode[0] == '-' and mode[1] == "i":
                            selectedUser._invisible_status = False
                        elif mode[0] == '+' and (mode[1] == "o" or mode[1] == "w" or mode[1] == "s"):
                            selectedUser.usertype = "sysop"         #make user a system operator
                        elif mode[0] == '-' and (mode[1] == "o" or mode[1] == "w" or mode[1] == "s"):
                            selectedUser.usertype = "user"
                        else:
                            user.socket.sendall(("> Inproper flag\n").encode('utf8'))
        else:
            self.help(user)

    def mode_c(self, user, chatMessage):                    #Channel Mode
        if len(chatMessage.split()) >= 3:
            channelName = chatMessage.split()[1]
            secondaryInput = ''
            if (not chatMessage.split()[2][0] == "+") and (not chatMessage.split()[2][0] == "-") and len(chatMessage.split()) >= 4:
                secondaryInput = chatMessage.split()[2]
                flags = chatMessage.split(None, 3)[3].split(" ")
            else:
                flags = chatMessage.split(None, 2)[2].split(" ")
            for selectedChannel in self.channels:
                if selectedChannel == channelName:
                    for mode in flags:
                        if mode[0] == '+' and mode[1] == "o" and not secondaryInput == '':
                            user.usertype = "channelop"
                        elif mode[0] == '-' and mode[1] == "o" and not secondaryInput == '':
                            user.usertype = "user"
                        elif mode[0] == '+' and mode[1] == "p":    #Outside users cannot enter this channel Implemented
                            self.channels[selectedChannel].private_mode = True
                        elif mode[0] == '-' and mode[1] == "p":
                            self.channels[selectedChannel].private_mode = False
                        elif mode[0] == '+' and mode[1] == "s":     #Channel will not show in /list Implemented
                            self.channels[selectedChannel].secret_mode = True
                        elif mode[0] == '-' and mode[1] == "s":
                            self.channels[selectedChannel].secret_mode = False
                        elif mode[0] == '+' and mode[1] == "i":     #Users can only enter through invite Implemented
                            self.channels[selectedChannel].invite_only_mode = True
                        elif mode[0] == '-' and mode[1] == "i":
                            self.channels[selectedChannel].invite_only_mode = False
                        elif mode[0] == '+' and mode[1] == "t":     #Topic can only be changed by the channel operators
                            self.channels[selectedChannel].operator_topic_mode = True
                        elif mode[0] == '-' and mode[1] == "t":
                            self.channels[selectedChannel].operator_topic_mode = False
                        elif mode[0] == '+' and mode[1] == "n":  #Channel cannot recieve message from knock
                            self.channels[selectedChannel].no_outside_mode = True
                        elif mode[0] == '-' and mode[1] == "n":
                            self.channels[selectedChannel].no_outside_mode = False
                        elif mode == "l" and secondaryInput.isdigit() and not secondaryInput == '':
                            self.channels[selectedChannel].user_limits = int(secondaryInput) #Sets a limit
                        elif mode[0] == '+' and mode[1] == "k" and not secondaryInput == '':
                            self.channels[selectedChannel].channel_password = secondaryInput #Sets channel password
                        elif mode[0] == '-' and mode[1] == "k":
                            self.channels[selectedChannel].channel_password = '@'
                        else:
                            user.socket.sendall(("> Inproper flag\n").encode('utf8'))
        else:
            self.help(user)

    def mychannels(self, user):                              #To show channel's currently on
        if not self.users_channels_map[user.username] == []:
            channelList = ''
            for channel in self.users_channels_map[user.username]:
                channelList += channel + "\n"
            user.socket.sendall(("Channels currently on:\n" + channelList).encode('utf8'))
        else:
            self.help(user)

    def set_nick(self, user, chatMessage):                   #Nick Implemented
        repeatNick = False
        if len(chatMessage.split()) == 2:
            nickname = chatMessage.split()[1]
            for person in self.users:
                if person.nickname == nickname:
                    repeatNick = True
            if not repeatNick:
                user.nickname = nickname
            else:
                user.socket.sendall(("> Nicknamed already taken\n").encode('utf8'))
        else:
            user.socket.sendall(("> Incorrect, its: /nick [nickname]\n").encode('utf8'))

    def notice(self, user, chatMessage):                   #Notice Implemented
        if len(chatMessage.split()) >= 3:
            target = chatMessage.split()[1]
            message = chatMessage.split(None, 2)[2]
            for person in self.users:
                if target == person.username and not user.username in person.ignore_list:
                    person.socket.sendall(("> Notice from " + user.username + ": " + message + '\n').encode('utf8'))
        else:
            self.help(user)

    def oper(self, user, chatMessage):                   #Operator Implemented
        if len(chatMessage.split()) == 3:
            username = chatMessage.split()[1]
            password = chatMessage.split()[2]
            for selectedUsers in self.users:
                if selectedUsers.username == username and selectedUsers.password == password and not selectedUsers.usertype == "admin":
                    selectedUsers.usertype = "sysop"
        else:
            self.help(user)

    def part(self, user, chatMessage):                   #Part Implemented
        if (len(chatMessage.split()) >= 2):
            message = ''
            if len(chatMessage.split()) >= 3:
                message = chatMessage.split(None, 2)[2]
            channelLeaving = chatMessage.split()[1].split(",")
            for channelName in channelLeaving:
                self.bye_message(user, channelName, message + '\n')
                self.channels[channelName].remove_user_from_channel(user)  # remove them from the previous channel
                self.users_channels_map[user.username].remove(channelName)
                if user.current_channel == channelName:
                    user.current_channel = ''
            user.socket.sendall('/part'.encode('utf8'))
        else:
            self.help(user)

    def set_password(self, user, chatMessage):                   #Password Implemneted
        if len(chatMessage.split()) == 2:
            user.password = chatMessage.split()[1]
        else:
            user.socket.sendall(("> Incorrect, its: /pass [password]\n").encode('utf8'))

    def ping(self, user, chatMessage):                #Ping Implemented
        if len(chatMessage.split()) == 2:
            toServer = chatMessage.split()[1]
            for selectedUser in self.users:
                if selectedUser.username == toServer:
                    selectedUser.socket.sendall(("> Ping\n").encode('utf8'))
                    user.socket.sendall(("> Pong\n").encode('utf8'))
        elif len(chatMessage.split()) == 3:
            toServer = chatMessage.split()[1]
            passTo = chatMessage.split()[2]
            for selectedUser in self.users:
                if selectedUser.username == toServer:
                    selectedUser.socket.sendall(("> Ping\n").encode('utf8'))
                    user.socket.sendall(("> Pong\n").encode('utf8'))
                    for secondUser in self.users:
                        if secondUser.username == passTo:
                            user.socket.sendall(("> Pong\n").encode('utf8'))
        else:
            self.help(user)

    def pong(self, user, chatMessage):                   #Pong Implemented
        if len(chatMessage.split()) == 2:
            toServer = chatMessage.split()[1]
            for selectedUser in self.users:
                if selectedUser.username == toServer:
                    selectedUser.socket.sendall(("> Pong\n").encode('utf8'))
                    user.socket.sendall(("> Ping\n").encode('utf8'))
        elif len(chatMessage.split()) == 3:
            toServer = chatMessage.split()[1]
            passTo = chatMessage.split()[2]
            for selectedUser in self.users:
                if selectedUser.username == toServer:
                    selectedUser.socket.sendall(("> Pong\n").encode('utf8'))
                    user.socket.sendall(("> Ping\n").encode('utf8'))
                    for secondUser in self.users:
                        if secondUser.username == passTo:
                            user.socket.sendall(("> Ping\n").encode('utf8'))
        else:
            self.help(user)

    def privmsg(self, user, chatMessage):                #Private Message Implemented
        if len(chatMessage.split()) >= 3:
            target = chatMessage.split()[1]
            message = chatMessage.split(None, 2)[2]
            for person in self.users:
                if target == person.username and not user.username in person.ignore_list:
                    person.socket.sendall(("> Private message from " + user.username + ": " + message + '\n').encode('utf8'))
                    if not person._away_status == '':
                        user.socket.sendall(("> AWAY: " + person._away_status + '\n').encode('utf8'))
        else:
            self.help(user)

    def restart(self, user):                   #Restart Implemented (Admin only)
        if (user.usertype == 'admin'):
            self.restart_signal = True
            self.die(user)
        else:
            user.socket.sendall("> Not an admin.\n".encode('utf8'))

    def rules(self, user):              #Rules Implemented
        user.socket.sendall(Server.RULE_MESSAGE)

    def setname(self, user, chatMessage):                   #Set Real Name Implemented
        if len(chatMessage.split()) >= 2:
            newName = chatMessage.split(None, 1)[1]
            user._real_name = newName
            user.socket.sendall("> Name has been changed\n".encode('utf8'))
        else:
            self.help(user)

    def silence(self, user, chatMessage):                   #Silence Implemented
        if len(chatMessage.split()) == 1:
            user.socket.sendall("Ignored List:\n".encode('utf8'))
            for ignored_user in user.ignore_list:
                user.socket.sendall((ignored_user + "\n").encode('utf8'))
        elif len(chatMessage.split()) >= 2:
            ignored_names = chatMessage.split(None, 1)[1].split(" ")
            for selectedUsers in ignored_names:
                if selectedUsers[0] == '+'and not selectedUsers[1:] in user.ignore_list:
                    user._ignor_list.append(selectedUsers[1:])
                if selectedUsers[0] == '-' and selectedUsers[1:] in user.ignore_list:
                    user._ignor_list.remove(selectedUsers[1:])
        else:
            self.help(user)

    def time(self, user):               #Time Implemented
        TIME_MESSAGE = "> The current time is " + str(datetime.datetime.now()) + "\n\n"
        TIME_MSBYTE = TIME_MESSAGE.encode('utf8')
        user.socket.sendall(TIME_MSBYTE)

    def topic(self, user, chatMessage):                   #Topic Implemented
        if len(chatMessage.split()) == 2:
            channelName = chatMessage.split()[1]
            if channelName in self.channels:
                user.socket.sendall(("> Topic: " + self.channels[channelName].channel_topic + "\n").encode('utf8'))
        elif len(chatMessage.split()) == 3:
            channelName = chatMessage.split()[1]
            topic = chatMessage.split(None, 2)[2]
            if channelName in self.channels:
                if (self.channels[channelName].operator_topic_mode == False) or \
                        (self.channels[channelName].operator_topic_mode == True and user.usertype == 'channelop'):
                    self.channels[channelName].channel_topic = topic                            #Changes channel topic
                else:
                    user.socket.sendall(("> Operator-Topic-Mode is on, and you are not a channel operator: \n").encode('utf8'))
        else:
            self.help(user)

    def set_user(self, user, chatMessage):                   #User Implemented
        if len(chatMessage.split()) >= 3:
            user.username = chatMessage.split()[1]
            user._real_name = chatMessage.split(None, 2)[2]
        else:
            user.socket.sendall(("> Incorrect, its: /user [username] [realname]\n").encode('utf8'))

    def userhost(self, user, chatMessage):                   #User host Implemented
        userNames = ["Users:\n"]
        if len(chatMessage.split()) >= 2 and len(chatMessage.split()) <= 6:
            nickname = chatMessage.split(None, 1)[1].split(" ")
            for selectedUsers in self.users:
                for nick in nickname:
                    if (nick == selectedUsers.nickname) and (selectedUsers._invisible_status == False):
                        userNames.append(
                            selectedUsers.nickname + ": " + selectedUsers._real_name + ": " + selectedUsers.username + " " + selectedUsers.usertype + '\n')
            for word in userNames:
                user.socket.sendall(word.encode('utf8'))
        else:
            self.help(user)

    def userip(self, user, chatMessage):                   #User IP Address Implemented
        if len(chatMessage.split()) == 2:
            nickname = chatMessage.split()[1]
            for selectedUsers in self.users:
                if nickname in selectedUsers.nickname:
                    user.socket.sendall(("> User's ip address: " + selectedUsers.ipAddress + "\n").encode('utf8'))
        else:
            self.help(user)

    def show_users(self, user):                   #Show users Implemented
        userNames = ["Users:"]
        for selectedUsers in self.users:
            if (selectedUsers._invisible_status == False):
                userNames.append(selectedUsers.username)
        for word in userNames:
            user.socket.sendall((word + " ").encode('utf8'))
        user.socket.sendall('\n'.encode('utf8'))

    def version(self, user):            #Version Implemented
        user.socket.sendall(Server.VERSION_MESSAGE)

    def wallops(self, user, chatMessage):           #Wallops Implemented
        if len(chatMessage.split()) >= 2:
            message = chatMessage.split(None, 1)[1]
            for selectedUsers in self.users:
                if (selectedUsers.usertype == 'admin') or (selectedUsers.usertype == 'sysop'):
                    selectedUsers.socket.sendall(("> WALLOPS message: " + message + '\n').encode('utf8'))
        else:
            self.help(user)

    def who(self, user, chatMessage):                   #Who Implemented
        userNames = ["Users:"]
        if len(chatMessage.split()) == 2:
            name = chatMessage.split()[1]
            for selectedUsers in self.users:
                if (name in selectedUsers.username) and (selectedUsers._invisible_status == False):
                    userNames.append(selectedUsers.username + ": " + selectedUsers._real_name + ": " + selectedUsers.nickname + " " + selectedUsers.usertype)
            for word in userNames:
                user.socket.sendall((word + '\n').encode('utf8'))
        elif len(chatMessage.split()) == 3 and chatMessage.split()[2] == 'o':       #to return only admins and operators that match
            name = chatMessage.split()[1]
            for selectedUsers in self.users:
                if (name in selectedUsers.username) and (selectedUsers._invisible_status == False)\
                        and ((selectedUsers.usertype == 'admin') or (selectedUsers.usertype == 'sysop')):
                    userNames.append(selectedUsers.username + ": " + selectedUsers._real_name + ": " + selectedUsers.nickname + " " + selectedUsers.usertype)
            for word in userNames:
                user.socket.sendall((word + '\n').encode('utf8'))
        else:
            self.help(user)

    def whois(self, user, chatMessage):                   #Who Is Implemented
        userNames = ["Users:\n"]
        if len(chatMessage.split()) == 2:
            nickname = chatMessage.split(None, 1)[1].split(",")
            for selectedUsers in self.users:
                for nick in nickname:
                    if (nick == selectedUsers.nickname) and (selectedUsers._invisible_status == False):
                        userNames.append(selectedUsers.nickname + ": " + selectedUsers._real_name + ": " + selectedUsers.username + " " + selectedUsers.usertype + '\n')
            for word in userNames:
                user.socket.sendall(word.encode('utf8'))
        else:
            self.help(user)

def main():
    while True:  # if reset signal is set, stay in while loop
        chatServer = Server()

        channel_file = open("channels.txt", "w")   #resetting  channel list file
        channel_file.close()

        print("\nListening on port {0}".format(chatServer.address[1]))
        print("Waiting for connections...\n")

        chatServer.start_listening()
        chatServer.server_shutdown()
        if not chatServer.restart_signal:
            break

if __name__ == "__main__":
    main()
