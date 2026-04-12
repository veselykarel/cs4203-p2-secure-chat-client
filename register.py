import base64
import requests
from nacl import encoding
from nacl.public import PrivateKey, PublicKey, Box
from datetime import datetime

from nacl.signing import SigningKey, VerifyKey


class SecureChatClient:
    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.private_key = PrivateKey.generate()
        self.signing_key = SigningKey.generate()
        self.token = ""
        self._register()
        self.login(username, password)

    def login(self, username, password):
        resp = requests.post("http://localhost:8000/auth/login", json={
            "username": username,
            "password": password
        })
        if resp.status_code != 200:
            raise Exception(f"failed to login: {resp.text}")
        self.token = resp.json()['token']

    def _register(self):
        resp = requests.post("http://localhost:8000/auth/register", json={
            "username": self.username,
            "password": self.password,
            "public_key": base64.b64encode(bytes(self.private_key.public_key)).decode('utf-8'),
            "verify_key": base64.b64encode(bytes(self.signing_key.verify_key)).decode('utf-8')
        })
        if resp.status_code != 200:
            raise Exception("failed to register user")
        else:
            print(f"registered: {self.username}")

    def send_secure_message(self, recipient_username: str, message: str):
        # generate a new public key per message
        message_encryption_key = PrivateKey.generate()
        recipient_public_key = self.get_public_key(recipient_username)

        box = Box(message_encryption_key, recipient_public_key)

        # sign the message first
        signed_message = self.signing_key.sign(bytes(message, encoding="utf-8"))
        encrypted_message = box.encrypt(signed_message)
        ciphertext = base64.b64encode(encrypted_message).decode('utf-8')
        print(ciphertext)
        resp = requests.post(f"http://localhost:8000/chat/send/",
            json={
                "recipient": recipient_username,
                "timestamp": datetime.now().isoformat(),
                "ephemeral_pub": base64.b64encode(bytes(message_encryption_key.public_key)).decode('utf-8'),
                "ciphertext": ciphertext,
            },
            headers={"Authorization": f"Bearer {self.token}"}
        )
        print(resp.status_code, resp.json())
        if resp.status_code != 200:
            raise Exception("failed to send message")

    def receive_secure_messages(self):

        resp = requests.get(
            url=f"http://localhost:8000/chat/receive/",
            headers={"Authorization": f"Bearer {self.token}"}
        )
        print(resp)
        if resp.status_code != 200:
            raise Exception(f"failed to fetch messages: {resp.text}")

        # decrypt the messages in a separate function
        self._decrypt_secure_messages(resp.json())

    def _decrypt_secure_messages(self, messages):
        for message in messages:
            their_verify_key = self.get_verify_key(message['sender'])

            box = Box(self.private_key, PublicKey(base64.b64decode(message['ephemeral_pub'])))

            decoded_ciphertext = base64.b64decode(message['ciphertext'])
            decrypted_message_bytes = box.decrypt(decoded_ciphertext)
            verified_message = their_verify_key.verify(decrypted_message_bytes).decode('utf-8')
            print(f"{message['timestamp']}\t{message['sender']} says: {verified_message}")


    def get_public_key(self, username) -> PublicKey:
        resp = requests.get(
            url=f"http://localhost:8000/identity/public/?username={username}",
            headers={"Authorization": f"Bearer {self.token}"}
        )
        if resp.status_code == 200:
            return PublicKey(base64.b64decode(resp.text))
        else:
            raise Exception("failed to fetch public key")

    def get_verify_key(self, username) -> VerifyKey:
        resp = requests.get(
            url=f"http://localhost:8000/identity/verify/?username={username}",
            headers={"Authorization": f"Bearer {self.token}"}
        )
        if resp.status_code == 200:
            return VerifyKey(base64.b64decode(resp.text))
        else:
            raise Exception("failed to fetch verify key")