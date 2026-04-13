from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.shortcuts import prompt, choice
from secure_chat_client import SecureChatClient

# instance of the secure chat client
client = SecureChatClient(url="http://localhost:25780/")

# keep track of the logged-in user
is_logged_in = False
current_user = None

def login():
    global is_logged_in, current_user
    username = prompt("Username: ")
    password = prompt("Password: ", is_password=True)
    print("logging in to the server...")
    client.login(username, password)
    is_logged_in = True
    current_user = username


def register():
    global is_logged_in, current_user
    username = prompt("Username: ")
    password = prompt("Password: ", is_password=True)
    client.register(username, password)
    is_logged_in = True
    current_user = username


def send():
    users = client.get_users()
    print(f"options: {users}")
    to = prompt("To: ", completer=WordCompleter(users, ignore_case=False))
    message = prompt("Message: ")

    try:
        client.send_secure_message(recipient_username=to, message=message)
    except Exception as e:
        print(f"Failed to send message to {to}: {e}")

def receive():
    messages = client.receive_secure_messages()
    if len(messages) > 0:
        messages.sort(key = lambda x: (x["sender"], x["timestamp"]), reverse=(False, True))
        for m in messages:
            print(f"{m['sender']} says: {m['message']}\t({m['timestamp']})")
    else:
        print("No messages!")

commands = {
    "login": login,
    "register": register,
    "send": send,
    "receive": receive
}

if __name__ == "__main__":
    while True:
        # don't show login or register if the user is already logged in
        before_login_options = {
            "login": login,
            "register": register,
        }
        after_login_options = {
            "send": send,
            "receive": receive
        }

        options = after_login_options if is_logged_in else before_login_options
        msg = f"Hi {current_user}" if is_logged_in else ""
        cmd_options = [(c, c.title()) for c in options.keys()]
        cmd = choice(message=msg, options=cmd_options)
        if cmd_func := commands.get(cmd):
            cmd_func()
            print("")
