# for encryption and decryption
import nacl.secret
import nacl.utils
# for hashing
import nacl.encoding
import nacl.hash

from PIL import Image
from PIL.PngImagePlugin import PngInfo
from io import BytesIO
import random

import sys
import os
from itertools import cycle

# keystore saves the keys encryptet by the primary key + signature (hashed or asymmitriced saves)
# decryptet by the primary key which is a combination of secret number in the source code and a (init) keywhich is saved in a text file

class Crypticor:

    ENCODING = "unicode_escape"
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
        # FIXME

        # check setup
        if self.check_setup():
            self.load_primary_key()
        else:
            self.create_init_key()
            self.create_steg_number(img_name=self.img_stag_key_part3, meta_data_name=self.meta_stag_key_part3, number=None)
            self.create_steg_number(img_name=self.img_stag_setup_state, meta_data_name=self.meta_stag_setup_state, number=1)
            self.load_primary_key()

    def __delete__(self):
        self.exit()

    def is_password_login_active(self):
        number = get_steg_number(img_name=self.img_stag_user_pwd_state, meta_data_name=self.meta_stag_user_pwd_state)
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
            pass
            # FIXME
        else:
            return

    def check_setup(self):
        # with open(f"{Crypticor.DATA_REL_PATH}/STATE.txt", "r") as f:
        #     state = f.read()
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

    def add_keystore_entry(self, name:str, key:bytes):
        # encrypt key 
        encrypted_key = self.crypt.encrypt(key)
        # assert len(encrypted_key) == len(key) + self.crypt.NONCE_SIZE + self.crypt.MACBYTES

        # get true key/file name
        key_files = [f for f in os.listdir(Crypticor.KEYSTORE_REL_PATH) if f.endswith(".txt")]
        new_key = f"{name}.txt"
        counter = 1
        while new_key in key_files:
            counter += 1
            new_key = f"{name} {counter}.txt"

        with open(f"{Crypticor.KEYSTORE_REL_PATH}/{new_key}", "w") as f:  #encoding=Crypticor.ENCODING
            f.write(encrypted_key)

    def access_keystore_entry(self, ):
        pass

    def create_user_password(self, password:str):
        # hash it and safe it in a file
        hash_value_psw = self.hasher(password.encode(), encoder=nacl.encoding.HexEncoder)
        print(hash_value_psw)
        print(type(hash_value_psw))

        # save the hashed psw
        with open(f"{Crypticor.DATA_REL_PATH}/user_psw.txt", "w") as f:
            f.write(hash_value_psw)
        
        # set active
        self.create_steg_number(img_name=self.img_stag_user_pwd_state, meta_data_name=self.meta_stag_user_pwd_state, number=1)

    def user_password_correct(self, password:str):
        # check with saved hash file
        # get hash value of the given password
        check_password_hash = self.hasher(password.encode(), encoder=nacl.encoding.HexEncoder)

        # load real hashed password
        with open(f"{Crypticor.DATA_REL_PATH}/user_psw.txt", "r") as f:
            real_password_hash = f.read()

        # check both hash-values
        if sodium_memcmp(real_password_hash, check_password_hash):
            return True
        else:
            return False

    def reset(self):
        self.delete()
        self.create_init_key()
        self.create_steg_number(img_name=self.img_stag_setup_state, meta_data_name=self.meta_stag_setup_state, number=0)
        self.create_steg_number(img_name=self.img_stag_key_part3, meta_data_name=self.meta_stag_key_part3, number=None)
        self.create_steg_number(img_name=self.img_stag_user_pwd_state, meta_data_name=self.meta_stag_user_pwd_state, number=0)

    def delete(self):
        key_files = [f for f in os.listdir("./data/keystore") if f.endswith(".txt")]
        for key_file in key_files:
            os.remove(f"./data/keystore/{key_file}")

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

if __name__ == "__main__":
    crypt = Crypticor(reset=True)
    #print(crypt.primary_key) 
    #crypt.create_user_password("Hello World")
