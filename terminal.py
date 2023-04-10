# Simple console application
import crypticor
from crypticor import Crypticor
import sys

SET_POSITION = lambda n, m: f"\u001b[{n};{m}H" #moves cursor to row n column m
CLEAR_SCREEN = lambda n: f"\u001b[{n}J"

commands = {#"show private keys":lambda c:show_private_keys(c), "show private":lambda c:show_private_keys(c),
            #"private keys":lambda c:show_private_keys(c), "private":lambda c:show_private_keys(c),
            #"show public keys":lambda c:show_public_keys(c), "show public":lambda c:show_public_keys(c),
            #"public keys":lambda c:show_public_keys(c), "public":lambda c:show_public_keys(c),
            "show keys":lambda c:show_keys(c), "keys":lambda c:show_keys(c),
            "help":lambda c:help(c), 
            "generate keys":lambda c:generate_keys(c), "generate":lambda c:generate_keys(c),
            "encrypt":lambda c:encrypt(c), "decrypt":lambda c:decrypt(c),
            "set password":lambda c:set_password(c), "password":lambda c:set_password(c),
            "delete password":lambda c:set_password(c),
            "reset":lambda c:reset(c),
            "exit":lambda c:exit(c)}

def terminal(crypt:crypticor.Crypticor):
    if crypt.is_password_login_active():
        user_password_not_correct = True
        while user_password_not_correct:
            user_password = input("Type your password or reset:")
            user_password_not_correct = not crypt.unlock(user_password)
            if user_password == "reset":
                user_input = input("Are you sure?(y/n) You will loose all your data!")
                if user_input == "y":
                    crypt.reset()
                    user_password_not_correct = False

    while True:
        create_content_with_menu("", ["keys", "generate keys", "encrypt", "decrypt",
                                    "help", "set password", "reset", "exit"], should_terminal_out=True)
                                # "private keys", "public keys"
        user_input = input("input:")
        if user_input not in commands.keys():
            print("There is no function. Type 'help' if you are unsure how to use me.")
            input("Press Enter to continue.")
            continue
        commands[user_input](crypt)

def terminal_out(content:str):
    print(f"{CLEAR_SCREEN(2)}{SET_POSITION(0,0)}")
    print(content)

def create_content_with_menu(content:str, keys:list, should_terminal_out=False):
    ui = content
    # content to show (optional)
    # Crypticor
    ui += "\n\n\n🔥Crypticor🔥\n"
    # keys
    for key in keys:
        ui += f"    >> {key} <<\n"

    if should_terminal_out:
        terminal_out(ui)
    return ui

def show_private_keys(crypt:crypticor.Crypticor):
    while True:
        private_keys = crypt.show_available_keys(only_names=False, private_key=True)
        private_keys_idx = dict()
        if bool(private_keys) == False:
            content = "*No private Keys added/generated yet"
        else:
            content = f"Number    Name    Key"
            idx = 0
            for key, value in private_keys:
                content += f"\n{idx}         {key}    {value}"
                private_keys_idx[idx] = [key, value]
                max_idx = idx
                idx += 1

        commands = ["activate *number", "deactivate", "copy *number", "add", "remove", "back", "exit"]

        create_content_with_menu(content, commands, should_terminal_out=True)
        user_input = input("input:")
        if user_input == "back" or user_input == "":
            return
        elif user_input.startswith("activate"):
            try:
                number = int(user_input.split(" ")[1])
                if number <= max_idx:
                    crypt.set_key_active(private_keys_idx[number][0], private_key=True)
                    print("Your key is now active and will be used automatically.")
                    input("Press Enter to continue.")
                else:
                    raise Exception("Number to big!")
            except Exception as e:
                print("Something went wrong!")
                input("Press Enter to continue.")
        elif user_input.startswith("deactivate"):
            crypt.deactivate(private_key=True, public_key=False)
            print("Your key is now deactived and not will be used anymore.")
            input("Press Enter to continue.")
        elif user_input.startswith("copy"):
            try:
                number = int(user_input.split(" ")[1])
                if number <= max_idx:
                    crypt.save_in_clipboard(private_keys_idx[number][0], private_key=True)
                    print("Your key is now on your clipbaord. Use it with paste or 'Strg'+'v'.")
                    input("Press Enter to continue.")
                else:
                    raise Exception("Number to big!")
            except Exception as e:
                raise e
                print("Something went wrong!")
                input("Press Enter to continue.")
        elif user_input == "add":
            while True:
                private_key_name = input("Name of the Public Key:")
                private_key = input("Public Key:")
                crypt.add_keystore_entry(private_key_name, private_key.encode(Crypticor.ENCODING), private_key=True)
        elif user_input == "remove":
            while True:
                private_key_name = input("Name of the Private Key:")
                crypt.remove_keystore_entry(private_key_name, private_key=True)
        elif user_input == "exit":
            exit(crypt)

def show_public_keys(crypt:crypticor.Crypticor):
    while True:
        public_keys = crypt.show_available_keys(only_names=False, private_key=False)
        public_keys_idx = dict()

        if bool(public_keys) == False:
            content = "*No public Keys added/generated yet"
        else:
            content = f"Number    Name    Key"
            idx = 0
            for key, value in public_keys:
                content += f"\n{idx}         {key}    {value}"
                public_keys_idx[idx] = [key, value]
                max_idx = idx
                idx += 1

        commands = ["activate *number", "deactivate", "copy *number", "add", "remove", "back", "exit"]

        create_content_with_menu(content, commands, should_terminal_out=True)
        user_input = input("input:")
        if user_input == "back" or user_input == "":
            return
        elif user_input.startswith("activate"):
            try:
                number = int(user_input.split(" ")[1])
                if number <= max_idx:
                    crypt.set_key_active(public_keys_idx[number][0], private_key=False)
                    print("Your key is now active and will be used automatically.")
                    input("Press Enter to continue.")
                else:
                    raise Exception("Number to big!")
            except Exception as e:
                print("Something went wrong!")
                input("Press Enter to continue.")
        elif user_input.startswith("deactivate"):
            crypt.deactivate(private_key=False, public_key=True)
            print("Your key is now deactived and not will be used anymore.")
            input("Press Enter to continue.")
        elif user_input.startswith("copy"):
            try:
                number = int(user_input.split(" ")[1])
                if number <= max_idx:
                    crypt.save_in_clipboard(private_keys_idx[number][0], private_key=False)
                    print("Your key is now on your clipbaord. Use it with paste or 'Strg'+'v'.")
                    input("Press Enter to continue.")
                else:
                    raise Exception("Number to big!")
            except Exception as e:
                print("Something went wrong!")
                input("Press Enter to continue.")
        elif user_input == "add":
            while True:
                public_key_name = input("Name of the Public Key:")
                public_key = input("Public Key:")
                crypt.add_keystore_entry(public_key_name, public_key.encode(Crypticor.ENCODING), private_key=False)
        elif user_input == "remove":
            while True:
                public_key_name = input("Name of the Public Key:")
                crypt.remove_keystore_entry(public_key_name, private_key=False)
        elif user_input == "exit":
            exit(crypt)

def show_keys(crypt:crypticor.Crypticor):
    while True:
        private_keys = crypt.show_available_keys(only_names=False, private_key=True)
        public_keys = crypt.show_available_keys(only_names=False, private_key=False)

        keys_idx = dict()

        if bool(public_keys) == False:
            content = "---> PRIVATE KEYS <---\n*No private Keys added/generated yet"
        else:
            content = f"---> PRIVATE KEYS <---\nNumber    Name    Key"
            private_idx = 0
            for key, value in private_keys:
                content += f"\n{private_idx}         {key}    {value}"
                keys_idx[private_idx] = [key, value]
                max_private_idx = private_idx
                private_idx += 1

        if bool(public_keys) == False:
            content += "\n\n\n---> PUBLIC KEYS <---\n*No public Keys added/generated yet"
        else:
            content += f"\n\n\n---> PUBLIC KEYS <---\nNumber    Name    Key"
            public_idx = 0
            for key, value in public_keys:
                content += f"\n{max_private_idx+public_idx+1}         {key}    {value}"
                keys_idx[max_private_idx+public_idx+1] = [key, value]
                max_public_idx = public_idx
                public_idx += 1

        active_private_key = crypt.active_private_key
        active_public_key = crypt.active_public_key
        content += f"\n\ncurrently active:\nprivate -> {active_private_key}\npublic -> {active_public_key}"

        commands = ["activate *number", "deactivate", "copy *number", "add", "remove", "back", "exit"]

        create_content_with_menu(content, commands, should_terminal_out=True)
        user_input = input("input:")
        if user_input == "back" or user_input == "":
            return
        elif user_input.startswith("activate"):
            try:
                number = int(user_input.split(" ")[1])
                if number <= max_private_idx+max_public_idx+1:
                    if number > max_private_idx:
                        private_key = False
                        msg = "Your public key is now active and will be used automatically."
                    else:
                        private_key = True
                        msg = "Your private key is now active and will be used automatically."
                    crypt.set_key_active(keys_idx[number][0], private_key=private_key)

                    print(msg)
                    input("Press Enter to continue.")
                else:
                    raise Exception("Number to big!")
            except Exception as e:
                print("Something went wrong!")
                input("Press Enter to continue.")
        elif user_input.startswith("deactivate"):
            user_input = input("public, private or both?:")
            if user_input == "public":
                crypt.deactivate(private_key=False, public_key=True)
                msg = "Your public key is now deactived and not will be used anymore."
            elif user_input == "private":
                crypt.deactivate(private_key=True, public_key=False)
                msg = "Your private key is now deactived and not will be used anymore."
            elif user_input == "both":
                crypt.deactivate(private_key=True, public_key=True)
                msg = "Your private and public key is now deactived and not will be used anymore."
            else:
                msg = "Nothing is deactivated. Maybe you have to try it again."
            print(msg)
            input("Press Enter to continue.")
        elif user_input.startswith("copy"):
            try:
                number = int(user_input.split(" ")[1])
                if number <= max_private_idx+max_public_idx+1:
                    if number > max_private_idx:
                        private_key = False
                        msg = "Your public key is now on your clipbaord. Use it with paste or 'Strg'+'v'."
                    else:
                        private_key = True
                        msg = "Your private key is now on your clipbaord. Use it with paste or 'Strg'+'v'."
                    crypt.save_in_clipboard(keys_idx[number][0], private_key=private_key)
                    print("Your key is now on your clipbaord. Use it with paste or 'Strg'+'v'.")
                    input("Press Enter to continue.")
                else:
                    raise Exception("Number to big!")
            except Exception as e:
                print("Something went wrong!")
                input("Press Enter to continue.")
        elif user_input == "add":
            while True:
                key_name = input("Name of the Key:")
                key = input("Key:")
                private_key = input("Is it a private key?(y/n):")
                if private_key == "y":
                    private_key = True
                else:
                    private_key = False
                # FIXME How to encode?
                crypt.add_keystore_entry(key_name, key.encode(), private_key=private_key)
        elif user_input == "remove":
            while True:
                key_name = input("Name of the Key:")
                private_key = input("Is it a private key?(y/n):")
                if private_key == "y":
                    private_key = True
                else:
                    private_key = False
                crypt.remove_keystore_entry(public_key_name, private_key=private_key)
        elif user_input == "exit":
            exit(crypt)

def generate_keys(crypt:crypticor.Crypticor):
    name = input("Give one Name for the keys:")
    crypt.generate_private_and_public_key(name)
    print("Your Keys are generated.")
    input("Press Enter to continue.")

def encrypt(crypt:crypticor.Crypticor):
    msg = input("Your Message:")
    if msg == "exit":
        return
    # key_name = input("Your Key Name(type nothing if you want to use active one):")
    # if key_name == "exit":
    #     return
    private_key = input("Using your private key?(y/n):")
    if private_key == "y":
        private_key = True
    else:
        private_key = False
    encryptet_message = crypt.encrypt_message(msg, output=Crypticor.OUTPUT_STR)

    print("Your encryptet message:")
    print(encryptet_message)
    user_input = input("Copy in clipboard?(y/n)")
    if user_input == "y":
        crypt.content_to_clipboard(encryptet_message)


def decrypt(crypt:crypticor.Crypticor):
    msg = input("Your Message:")
    if msg == "exit":
        return
    # if msg.startswith("b'") and msg.endswith("'"):
    #     msg = msg[2:-1]

    # key_name = input("Your Key(type nothing if you want to use active one):")
    # if key_name == "exit":
    #     return
    private_key = input("Using your private key?(y/n):")
    if private_key == "y":
        private_key = True
    else:
        private_key = False
    decryptet_message = crypt.decrypt_message(msg, output=Crypticor.OUTPUT_STR)

    print("Your decryptet message:")
    print(decryptet_message)
    user_input = input("Copy in clipboard?(y/n)")
    if user_input == "y":
        crypt.content_to_clipboard(decryptet_message)

def set_password(crypt:crypticor.Crypticor):
    if crypt.is_password_login_active():
        crypt.deactivate_user_password()
        print(f"Your password is now deleted.")
        input("Press Enter to continue.")
    else:
        user_input = input("Type your password:")
        crypt.create_user_password(user_input)
        print(f"Your password is now {user_input}.")
        input("Press Enter to continue.")

def reset(crypt:crypticor.Crypticor):
    user_input = input("Are you sure? You will loose all data.(y/n)")
    if user_input == "y":
        crypt.reset()
        print("Your crypt is like new now.")
        input("Press Enter to continue.")

def help(crypt:crypticor.Crypticor):
    pass

def exit(crypt:crypticor.Crypticor):
    print("I hope you had a good stay in the crypt. See you!")
    crypt.exit()
    sys.exit()

if __name__ == "__main__":
    crypt = Crypticor()
    terminal(crypt)