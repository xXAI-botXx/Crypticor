# Simple console application
import crypticor
from crypticor import Crypticor
import sys

SET_POSITION = lambda n, m: f"\u001b[{n};{m}H" #moves cursor to row n column m
CLEAR_SCREEN = lambda n: f"\u001b[{n}J"

commands = {"show private keys":lambda c:show_private_keys(c), "show private":lambda c:show_private_keys(c),
            "private keys":lambda c:show_private_keys(c),
            "show public keys":lambda c:show_public_keys(c), "show public":lambda c:show_public_keys(c),
            "public":lambda c:show_public_keys(c),
            "show keys":lambda c:show_keys(c), "help":lambda c:help(c), #"keywords":lambda c:keywords(c),
            "generate keys":lambda:generate_keys(),# "add key":lambda:add_key(),
            "encrypt":lambda c:encrypt(c), "decrypt":lambda c:decrypt(c),
            #"activate private key":lambda c:activate_private_key(c),
            #"activate public key":lambda c:activate_public_key(c),
            #"copy private key":lambda c:copy_private_key(c),
            #"copy public key":lambda c:copy_public_key(c),
            "set password":lambda c:set_password(c), "reset":lambda c:reset(c),
            "exit":lambda c:exit(c)}

def terminal(crypt:crypticor.Crypticor):
    if crypt.is_password_login_active():
        user_password_not_correct = True
        while user_password_not_correct:
            user_password = input("Type your password or reset:")
            user_password_not_correct = crypt.unlock(user_password)
            if user_password == "reset":
                user_input = input("Are you sure?(y/n) You will loose all your data!")
                if user_input == "y":
                    crypt.reset()
                    user_password_not_correct = False

    menu = "🔥Crypticor🔥    >> Starten <<\n    >> Informationen <<\n    >> Credits <<\n    >> Exit <<"
    while True:
        terminal_out(create_content_with_menu("", ["private keys", "public keys", "set password", "encrypt", "decrypt", "generate keys"]))
        user_input = input("input:")
        if user_input not in commands.keys():
            print("There is no function. Type 'help' if you are unsure how to use me.")
            input("Press Enter to continue.")
            continue
        commands[user_input](crypt)

def terminal_out(content:str):
    print(f"{CLEAR_SCREEN(2)}{SET_POSITION(0,0)}")
    print(content)

def create_content_with_menu(content:str, keys:list):
    ui = ""
    # content to show (optional)
    # Crypticor
    ui += "\n\n🔥Crypticor🔥\n"
    # keys
    for key in keys:
        ui += f"    >> {key} <<\n"
    return ui

def show_private_keys(crypt:crypticor.Crypticor):
    private_keys = crypt.show_available_keys(only_names=False, private_key=True)
    private_keys_idx = dict()
    content = f"Number    Name    Key"
    for idx, key, value in private_keys_idx:
        content += f"\n{idx}    {key}    {value}"
        private_keys_idx[idx] = [key, value]
        max_idx = idx

    commands = ["back", "activate *number", "copy *number","add", "remove"]

    while True:
        terminal_out(create_content_with_menu(content, commands))
        user_input = input("input:")
        if user_input == "back":
            return
        elif user_input.startswith("activate"):
            try:
                number = int(user_input.split(" ")[1])
                if number <= max_idx:
                    crypt.active_private_key(private_keys_idx[number][0])
            except Exception:
                continue
        elif user_input.startswith("copy"):
            try:
                number = int(user_input.split(" ")[1])
                if number <= max_idx:
                    crypt.save_in_clipboard(private_keys_idx[number][0], private_keys_idx[number][1])
            except Exception:
                continue
        elif user_input == "add":
            while True:
                private_key_name = input("Name of the Public Key:")
                private_key = input("Public Key:")
                crypt.add_keystore_entry(private_key_name, private_key.encode(Crypticor.ENCODING), private_key=True)
        elif user_input == "remove":
            while True:
                private_key_name = input("Name of the Private Key:")
                crypt.remove_keystore_entry(private_key_name, private_key=True)

def show_public_keys(crypt:crypticor.Crypticor):
    public_keys = crypt.show_available_keys(only_names=False, private_key=False)
    public_keys_idx = dict()
    content = f"Number    Name    Key"
    for idx, key, value in public_keys_idx:
        content += f"\n{idx}    {key}    {value}"
        public_keys_idx[idx] = [key, value]
        max_idx = idx

    commands = ["back", "activate *number", "copy *number", "add", "remove"]

    while True:
        terminal_out(create_content_with_menu(content, commands))
        user_input = input("input:")
        if user_input == "back":
            return
        elif user_input.startswith("activate"):
            try:
                number = int(user_input.split(" ")[1])
                if number <= max_idx:
                    crypt.active_public_key(public_keys_idx[number][0])
            except Exception:
                continue
        elif user_input.startswith("copy"):
            try:
                number = int(user_input.split(" ")[1])
                if number <= max_idx:
                    crypt.save_in_clipboard(public_keys_idx[number][0], public_keys_idx[number][1])
            except Exception:
                continue
        elif user_input == "add":
            while True:
                public_key_name = input("Name of the Public Key:")
                public_key = input("Public Key:")
                crypt.add_keystore_entry(public_key_name, public_key.encode(Crypticor.ENCODING), private_key=False)
        elif user_input == "remove":
            while True:
                public_key_name = input("Name of the Public Key:")
                crypt.remove_keystore_entry(public_key_name, private_key=False)

def generate_keys(crypt:crypticor.Crypticor):
    name = input("Give one Name for the keys:")
    crypt.generate_private_and_public_key(name)
    print("Your Keys are generated.")
    input("Press Enter to continue.")

def encrypt(crypt:crypticor.Crypticor):
    msg = input("Your Message:")
    if msg == "exit":
        return
    key = input("Your Key(type nothing if you want to use active one):")
    if key == "exit":
        return
    encryptet_message = crypt.encrypt_message(msg, key)

    print("Your encryptet message:")
    print(encryptet_message)
    user_input = input("Copy in clipboard?(y/n)")
    if user_input == "y":
        crypt.content_to_clipboard(encryptet_message)


def decrypt(crypt:crypticor.Crypticor):
    msg = input("Your Message:")
    if msg == "exit":
        return
    key = input("Your Key(type nothing if you want to use active one):")
    if key == "exit":
        return
    decryptet_message = crypt.decrypt_message(msg, key)

    print("Your decryptet message:")
    print(decryptet_message)
    user_input = input("Copy in clipboard?(y/n)")
    if user_input == "y":
        crypt.content_to_clipboard(decryptet_message)

def set_password(crypt:crypticor.Crypticor):
    user_input = input("Type your password:")
    crypt.create_user_password(user_input)

def reset(crypt:crypticor.Crypticor):
    user_input = input("Are you sure? You will loose all data.(y/n)")
    if user_input == "y":
        crypt.reset()

def help(crypt:crypticor.Crypticor):
    pass

def exit(crypt:crypticor.Crypticor):
    print("I hope you had a good stay in the crypt. See you!")
    crypt.exit()
    sys.exit()

if __name__ == "__main__":
    crypt = Crypticor()
    terminal(crypt)