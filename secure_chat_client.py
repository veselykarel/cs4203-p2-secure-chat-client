import base64

import nacl.hash
import requests
from nacl.public import PrivateKey, PublicKey, Box
from nacl.secret import SecretBox
from nacl.pwhash import argon2id, OPSLIMIT_INTERACTIVE, MEMLIMIT_INTERACTIVE
from nacl.utils import random
from nacl.encoding import Base64Encoder, RawEncoder
import os
from datetime import datetime

from nacl.signing import SigningKey, VerifyKey

class SecureChatClient:

    token = None
    private_key = None
    signing_key = None
    SERVER_URL = ""

    def __init__(self, url: str = "http://localhost:8000/"):
        self.SERVER_URL = url
        try:
            requests.get(self.SERVER_URL)
        except Exception as e:
            raise Exception(f"server unreachable: {e}")

        print("Welcome to a secure chat application!")

    """login obtains a new token from the application if user exists and decrypts any stored keys"""
    def login(self, username: str, password: str):
        resp = requests.post(self.SERVER_URL + "auth/login", json={
            "username": username,
            "password": password
        })
        if resp.status_code != 200:
            raise Exception(f"failed to login: {resp.text}")

        self.token = resp.json()['token']
        # print(self.token)

        # read encryption keys from file
        if self.signing_key is None or self.private_key is None:
            try:
                with open(f"keys/{username}_sig_key.enc", "rb") as f:
                    data = f.read()
                    decrypted = decrypt_with_password(data, password)
                    self.signing_key = SigningKey(decrypted)

                with open(f"keys/{username}_enc_key.enc", "rb") as f:
                    data = f.read()
                    decrypted = decrypt_with_password(data, password)
                    self.private_key = PrivateKey(decrypted)

            except:
                raise Exception("encryption keys not found")

        print(f"logged in successfully as {username}")

    """register generates new keys and uploads them onto the server"""
    def register(self, username, password):
        # generate new keys
        private_key = PrivateKey.generate()
        signing_key = SigningKey.generate()

        resp = requests.post(self.SERVER_URL + "auth/register", json={
            "username": username,
            "password": password,
            "public_key": base64.b64encode(bytes(private_key.public_key)).decode('utf-8'),
            "verify_key": base64.b64encode(bytes(signing_key.verify_key)).decode('utf-8')
        })
        if resp.status_code != 200:
            raise Exception("failed to register user: " + resp.text)
        else:
            print(f"registered: {username}")

        self.private_key = private_key
        self.signing_key = signing_key

        print("Saving encryption key locally (securely)...")
        os.makedirs("keys/", exist_ok=True)
        with open(f"keys/{username}_enc_key.enc", 'wb') as f:
            key_bytes = private_key.encode()
            encrypted = encrypt_with_password(key_bytes, password)
            f.write(encrypted)

        print("Saving signing key locally (securely)...")
        with open(f"keys/{username}_sig_key.enc", "wb") as f:
            key_bytes = self.signing_key.encode()
            encrypted = encrypt_with_password(key_bytes, password)
            f.write(encrypted)

        # automatically log in after registering
        self.login(username, password)

    def get_users(self):
        resp = requests.get(
            url = f"{self.SERVER_URL}identity/?keep_current_user=false",
            headers = {"Authorization": f"Bearer {self.token}"}
        )
        return resp.json()

    def send_secure_message(self, recipient_username: str, message: str):
        # generate a new public key per message
        message_encryption_key = PrivateKey.generate()

        try:
            recipient_public_key = self.get_public_key(recipient_username)
        except Exception as e:
            raise e

        # confirm the recipient public key does not conflict
        fingerprint = get_fingerprint(recipient_public_key.encode())

        # print("recipient key fingerprint: ", fingerprint)
        # input("confirm->")

        box = Box(message_encryption_key, recipient_public_key)

        # sign the message first
        signed_message = self.signing_key.sign(bytes(message, encoding="utf-8"))
        encrypted_message = box.encrypt(signed_message)
        ciphertext = base64.b64encode(encrypted_message).decode('utf-8')
        resp = requests.post(f"{self.SERVER_URL}chat/send/",
            json={
                "recipient": recipient_username,
                "timestamp": datetime.now().isoformat(),
                "ephemeral_pub": base64.b64encode(bytes(message_encryption_key.public_key)).decode('utf-8'),
                "ciphertext": ciphertext,
            },
            headers={"Authorization": f"Bearer {self.token}"}
        )
        # print(resp.status_code, resp.json())
        if resp.status_code != 200:
            raise Exception("failed to send message")
        print(f"sent message to {recipient_username} ({fingerprint})")

    def receive_secure_messages(self):

        resp = requests.get(
            url=f"{self.SERVER_URL}chat/receive/",
            headers={"Authorization": f"Bearer {self.token}"}
        )
        if resp.status_code != 200:
            raise Exception(f"failed to fetch messages: {resp.text}")

        # decrypt the messages in a separate function
        messages = resp.json()
        return self._decrypt_secure_messages(messages)

    def _decrypt_secure_messages(self, messages):
        decrypted_messages=[]
        for message in messages:
            their_verify_key = self.get_verify_key(message['sender'])
            their_public_key = self.get_public_key(message['sender'])
            fingerprint = get_fingerprint(their_public_key.encode())
            box = Box(self.private_key, PublicKey(base64.b64decode(message['ephemeral_pub'])))

            decoded_ciphertext = base64.b64decode(message['ciphertext'])
            decrypted_message_bytes = box.decrypt(decoded_ciphertext)
            verified_message = their_verify_key.verify(decrypted_message_bytes).decode('utf-8')
            decrypted_messages.append(
                {
                    "timestamp": message["timestamp"],
                    "sender": message["sender"],
                    "sender_fingerprint": fingerprint,
                    "message": verified_message
                }
            )
        return decrypted_messages


    def get_public_key(self, username) -> PublicKey:
        resp = requests.get(
            url=f"{self.SERVER_URL}identity/public/?username={username}",
            headers={"Authorization": f"Bearer {self.token}"}
        )
        if resp.status_code == 200:
            return PublicKey(base64.b64decode(resp.text))
        else:
            raise Exception("failed to fetch public key")

    def get_verify_key(self, username) -> VerifyKey:
        resp = requests.get(
            url=f"{self.SERVER_URL}identity/verify/?username={username}",
            headers={"Authorization": f"Bearer {self.token}"}
        )
        if resp.status_code == 200:
            return VerifyKey(base64.b64decode(resp.text))
        else:
            raise Exception("failed to fetch verify key")

# helper function to encrypt the keys with a password before saving
def encrypt_with_password(data: bytes, password: str):
    # save the keys to a file, derive a key based on the password
    salt = random(argon2id.SALTBYTES)
    key = argon2id.kdf(
        size = SecretBox.KEY_SIZE,
        password = password.encode('utf-8'),
        salt = salt,
        opslimit=OPSLIMIT_INTERACTIVE,
        memlimit=MEMLIMIT_INTERACTIVE,
    )
    box = SecretBox(key)
    encrypted = box.encrypt(data)
    return salt + encrypted

# helper function to encrypt the keys with a password before saving
def decrypt_with_password(data: bytes, password: str):
    salt = data[:argon2id.SALTBYTES]
    ciphertext = data[argon2id.SALTBYTES:]
    key = argon2id.kdf(
        size=SecretBox.KEY_SIZE,
        password=password.encode('utf-8'),
        salt=salt,
        opslimit=OPSLIMIT_INTERACTIVE,
        memlimit=MEMLIMIT_INTERACTIVE,
    )
    box = SecretBox(key)
    return box.decrypt(ciphertext)

def get_fingerprint(key_bytes: bytes):
    hash_bytes = nacl.hash.sha256(key_bytes, RawEncoder)[:16]
    hash_b64 = Base64Encoder.encode(hash_bytes)
    return hash_b64.decode('utf-8').rstrip("=")