# for encryption and decryption
import nacl.secret
import nacl.utils
# for hashing
import nacl.encoding
import nacl.hash
# for assymetric
from nacl.public import PrivateKey, Box

from PIL import Image
from PIL.PngImagePlugin import PngInfo
from io import BytesIO
import random

import sys
import os
from itertools import cycle

import pyperclip

# keystore saves the keys encryptet by the primary key + signature (hashed or asymmitriced saves)
# decryptet by the primary key which is a combination of secret number in the source code and a (init) keywhich is saved in a text file

class Crypticor:

    ENCODING = nacl.encoding.Base64Encoder #nacl.encoding.RawEncoder #nacl.encoding.Base64Encoder    #"unicode_escape"
    KEYSTORE_REL_PATH = "./data/keystore"
    DATA_REL_PATH = "./data"

    def __init__(self, reset=False):
        self.active_private_key = None
        self.active_public_key = None

        self.logged_in = False    # all is locked until unlocking this
        self.init_key = None    
        self.secret_number = 76159     # will be changed
        self.primary_key = None    # maybe don't save primary key -> the secret box is only needed or?
        self.crypt = None    # Secret Box with primary key

        self.img_stag_key_part3 = "./img/DALL·E 2023-04-05 22.10.30 - An abstract digital art from a crypt with an ancient key in center. On either side ancient pillars were supposed to blaze with fire..png"
        self.meta_stag_key_part3 = "hidden_number"
        self.img_stag_user_pwd_state = self.img_stag_key_part3
        self.meta_stag_user_pwd_state = "user_password_state"
        self.img_stag_setup_state = self.img_stag_key_part3
        self.meta_stag_setup_state = "setup_state"

        self.hasher = nacl.hash.sha256

        if reset:
            self.reset()

        # check password login -> should be here? -> if no, unlock
        if self.is_password_login_active():
            pass    # have to use unlock() now!
        else:
            self.logged_in = True
            # start crypticor
            self.start()

    def __delete__(self):
        self.exit()

    def start(self):
        if self.check_setup():
            self.load_primary_key()
        else:
            self.create_init_key()
            self.create_steg_number(img_name=self.img_stag_key_part3, meta_data_name=self.meta_stag_key_part3, number=None)
            self.create_steg_number(img_name=self.img_stag_setup_state, meta_data_name=self.meta_stag_setup_state, number=1)
            self.load_primary_key()

    def is_password_login_active(self):
        number = self.get_steg_number(img_name=self.img_stag_user_pwd_state, meta_data_name=self.meta_stag_user_pwd_state)
        if type(number) == bool: 
            if number == False:
                return False

        if number == 1:
            return True
        else:
            return False

    def unlock(self, password:str):
        """
        If the password login is activated than block the application till the right password is setted.
        """
        if self.is_password_login_active():
            if self.user_password_correct(password):
                self.logged_in = True
                # start crypticor
                self.start()
                return True

    def check_setup(self):
        number = self.get_steg_number(img_name=self.img_stag_setup_state, meta_data_name=self.meta_stag_setup_state)
        if type(number) == bool: 
            if number == False:
                return False
        
        if number == 1:
            return True
        else:
            return False

    def load_primary_key(self):
        # step 1: load init key
        with open(f"{Crypticor.DATA_REL_PATH}/init_key.txt", "rb") as f:
            self.init_key = f.read()    #.encode(Crypticor.ENCODING)

        # step 2: xor with secret number
        secret_number_bytes = str(self.secret_number).encode()
        self.primary_key = self.bitwise_connection(bytes_a=self.init_key, bytes_b=secret_number_bytes)    #bytes([self.secret_number])
        #print(sys.getsizeof(self.primary_key))

        # step 3: xor with hidden number
        hidden_number = self.get_steg_number(img_name=self.img_stag_key_part3, meta_data_name=self.meta_stag_key_part3)
        if hidden_number == False:
            raise KeyError("Hidden number isn't set now!!!")
        steg_number = str(hidden_number).encode()
        self.primary_key = self.bitwise_connection(bytes_a=self.primary_key, bytes_b=steg_number)
        #print(sys.getsizeof(self.primary_key))

        self.crypt = nacl.secret.SecretBox(self.primary_key)

    def bitwise_connection(self, bytes_a:bytes, bytes_b:bytes, operation="xor"):
        res = None
        # make operation
        if operation == "xor":
            res = bytes( [a^b for a,b in zip(bytes_a, cycle(bytes_b))] )
        elif operation == "and":
            res = bytes( [a&b for a,b in zip(bytes_a, cycle(bytes_b))] )
        elif operation == "or":
            res = bytes( [a|b for a,b in zip(bytes_a, cycle(bytes_b))] )
        else:
            res = bytes( [a^b for a,b in zip(bytes_a, cycle(bytes_b))] )
        
        return res

    def create_init_key(self):
        """
        Creates the primary key out of a new init key and a secret number.
        """
        # create init key
        self.init_key = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
        
        with open(f"{Crypticor.DATA_REL_PATH}/init_key.txt", "wb") as f:
            f.write(self.init_key)

    def add_keystore_entry(self, name:str, key:bytes, private_key=True):
        if self.logged_in:
            # encrypt key 
            encrypted_key = self.crypt.encrypt(key)
            # assert len(encrypted_key) == len(key) + self.crypt.NONCE_SIZE + self.crypt.MACBYTES

            if private_key:
                PATH = f"{Crypticor.KEYSTORE_REL_PATH}/PRIVATE"
            else:
                PATH = f"{Crypticor.KEYSTORE_REL_PATH}/PUBLIC"

            # get true key/file name
            key_files = [f for f in os.listdir(PATH) if f.endswith(".txt")]
            new_key = f"{name}.txt"
            counter = 1
            while new_key in key_files:
                counter += 1
                new_key = f"{name} {counter}.txt"

            with open(f"{PATH}/{new_key}", "wb") as f:  #encoding=Crypticor.ENCODING
                f.write(encrypted_key)

    def remove_keystore_entry(self, name:str, private_key=True):
        if self.logged_in:
            if private_key:
                PATH = f"{Crypticor.KEYSTORE_REL_PATH}/PRIVATE"
            else:
                PATH = f"{Crypticor.KEYSTORE_REL_PATH}/PUBLIC"

            try:
                os.remove(f"{PATH}/{name}.txt")
                return True
            except Exception:
                return False

    def set_key_active(self, key_name:str, private_key=True):
        if self.logged_in:
            if private_key:
                self.active_private_key = self.get_key(key_name, private_key=True)
            else:
                self.active_public_key = self.get_key(key_name, private_key=False)

    def deactivate(self, private_key=True, public_key=True):
        if private_key:
            self.active_private_key = None
        if public_key:
            self.active_public_key = None

    def generate_private_and_public_key(self, name:str):
        private_key = PrivateKey.generate()
        public_key = private_key.public_key
        self.add_keystore_entry(name, private_key._private_key, private_key=True)
        self.add_keystore_entry(name, public_key._public_key, private_key=False)
        return name

    def content_to_clipboard(self, content:str):
        if type(content) != str:
            content = str(content)
        pyperclip.copy(content)

    def save_in_clipboard(self, key_name:str, private_key:bool):
        if self.logged_in:
            #text = self.get_key(key_name, private_key=private_key)
            text = key_name
            pyperclip.copy(text)

    def get_key(self, name, output="b", private_key=True):
        if self.logged_in:
            if private_key:
                PATH = f"{Crypticor.KEYSTORE_REL_PATH}/PRIVATE"
            else:
                PATH = f"{Crypticor.KEYSTORE_REL_PATH}/PUBLIC"

            key_files = [f for f in os.listdir(PATH) if f.endswith(".txt")]
            names = [f.replace(".txt", "") for f in key_files]

            if name not in names:
                return

            cache = ""
            with open(f"{PATH}/{name}.txt", "rb") as f:
                cache = f.read()
            
            # decrypt key
            key = self.crypt.decrypt(cache)

            if output == "str":
                # return it as str
                return key.decode("utf-8")
            else:    # b binary
                return key

    def show_available_keys(self, only_names=False, private_key=True) -> list:
        if self.logged_in:
            if private_key:
                PATH = f"{Crypticor.KEYSTORE_REL_PATH}/PRIVATE"
            else:
                PATH = f"{Crypticor.KEYSTORE_REL_PATH}/PUBLIC"

            key_files = [f for f in os.listdir(PATH) if f.endswith(".txt")]
            names = [f.replace(".txt", "") for f in key_files]

            if only_names:
                return [f.replace(".txt", "") for f in key_files]
            else:
                keys = dict.fromkeys(names, 0)
                for key_file, name in zip(key_files, names):
                    cache = ""
                    with open(f"{PATH}/{key_file}", "rb") as f:
                        cache = f.read()
                    
                    # decrypt key
                    keys[name] = self.crypt.decrypt(cache)
                return keys.items()
                # get a str
                # keys_string = ""
                # for key, value in my_dict.items():
                #     keys_string += f'{key}: {value},\n'
                # return keys_string


    def create_user_password(self, password:str):
        # hash it and safe it in a file
        hash_value_psw = self.hasher(password.encode(), encoder=Crypticor.ENCODING)
        print(hash_value_psw)
        print(type(hash_value_psw))

        # save the hashed psw
        with open(f"{Crypticor.DATA_REL_PATH}/user_psw.txt", "wb") as f:
            f.write(hash_value_psw)
        
        # set active
        self.create_steg_number(img_name=self.img_stag_user_pwd_state, meta_data_name=self.meta_stag_user_pwd_state, number=1)

    def user_password_correct(self, password:str):
        # check with saved hash file
        # get hash value of the given password
        check_password_hash = self.hasher(password.encode(), encoder=Crypticor.ENCODING)

        # load real hashed password
        with open(f"{Crypticor.DATA_REL_PATH}/user_psw.txt", "rb") as f:
            real_password_hash = f.read()

        # check both hash-values
        if sodium_memcmp(real_password_hash, check_password_hash):
            return True
        else:
            return False

    def reset(self):
        if self.logged_in:
            self.delete()
            self.create_init_key()
            self.create_steg_number(img_name=self.img_stag_setup_state, meta_data_name=self.meta_stag_setup_state, number=0)
            self.create_steg_number(img_name=self.img_stag_key_part3, meta_data_name=self.meta_stag_key_part3, number=None)
            self.create_steg_number(img_name=self.img_stag_user_pwd_state, meta_data_name=self.meta_stag_user_pwd_state, number=0)

    def delete(self):
        private_key_files = [f for f in os.listdir("./data/keystore/PRIVATE") if f.endswith(".txt")]
        for key_file in private_key_files:
            os.remove(f"./data/keystore/PRIVATE/{key_file}")

        public_key_files = [f for f in os.listdir("./data/keystore/PUBLIC") if f.endswith(".txt")]
        for key_file in private_key_files:
            os.remove(f"./data/keystore/PUBLIC/{key_file}")

    def exit(self):
        self.active_private_key = None
        self.active_public_key = None
        self.database_key = None
        self.password = None
        try:
            self.crypticor_db_cursor.close()
            self.crypticor_db.close()
        except Exception:
            pass

    def get_steg_number(self, img_name:str, meta_data_name:str):
        # Open the image file
        img = Image.open(img_name)

        # Get the metadata bytes from the image
        meta_data = img.text

        if meta_data_name in meta_data:
            return int(meta_data[meta_data_name])
        else:
            return False

    def create_steg_number(self, img_name:str, meta_data_name:str, number=None):
        if number == None:
            primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113]
            number = random.choice(primes)

        # Open the image file & get old meta data
        img = Image.open(img_name)
        meta_data = img.text

        new_meta_data = PngInfo()
        for key, value in meta_data.items():
            if key != meta_data_name:
                new_meta_data.add_text(key, value)
        new_meta_data.add_text(meta_data_name, str(number))
        img.save(img_name, pnginfo=new_meta_data)

    def encrypt_message(self, msg:str, key_name:str, use_active_key_if_active=True, private_key=False):
        if self.logged_in:
            key = self.get_key(key_name, private_key=private_key)
            if private_key:
                active_key = self.active_private_key
            else:
                active_key = self.active_public_key
            msg = msg.encode("utf-8")
            if active_key != None and use_active_key_if_active:
                box = nacl.secret.SecretBox(active_key)
                return box.encrypt(msg)    
            else:
                box = nacl.secret.SecretBox(key)
                return box.encrypt(msg)    

    def decrypt_message(self, msg:str, key_name:str, use_active_key_if_active=True, private_key=True):
        if self.logged_in:
            key = self.get_key(key_name, private_key=private_key)
            if private_key:
                active_key = self.active_private_key
            else:
                active_key = self.active_public_key
            msg = msg.encode("utf-8")
            if active_key != None and use_active_key_if_active:
                box = nacl.secret.SecretBox(active_key)
                return box.decrypt(msg)    
            else:
                box = nacl.secret.SecretBox(key)
                return box.decrypt(msg)    

if __name__ == "__main__":
    crypt = Crypticor(reset=False)
    #print(crypt.primary_key) 
    #crypt.create_user_password("Hello World")
