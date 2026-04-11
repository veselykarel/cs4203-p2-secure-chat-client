
from register import SecureChatClient

# assume users register independently
alice_chat_client = SecureChatClient("Alice", "AliceSecretPassword")
bob_chat_client = SecureChatClient("Bob", "BobSecretPassword")

# Alice wants to send a secret message to Bob
alice_chat_client.send_secure_message("Bob", "Hi Bob, super secret chat message from Alice")
bob_chat_client.send_secure_message("Alice", "Hi Alice, super secret message from Bob")
alice_chat_client.send_secure_message("Bob", "Hi Bob, Thank you for the secret message")
bob_chat_client.send_secure_message("Alice", "Hi Alice, You're welcome!")

# receive secure messages from Bob
alice_chat_client.receive_secure_messages()
bob_chat_client.receive_secure_messages()

