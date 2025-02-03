import socket
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# AES encryption key (Must be 16, 24, or 32 bytes)
SECRET_KEY = b"thisisasecretkey"  # 16-byte key

# Function to encrypt a message using AES
def encrypt_message(message):
    cipher = AES.new(SECRET_KEY, AES.MODE_CBC, iv=SECRET_KEY[:16])
    encrypted_bytes = cipher.encrypt(pad(message.encode(), AES.block_size))
    return base64.b64encode(encrypted_bytes).decode()  # Convert to base64 string

# Function to decrypt a message using AES
def decrypt_message(encrypted_message):
    encrypted_bytes = base64.b64decode(encrypted_message)
    cipher = AES.new(SECRET_KEY, AES.MODE_CBC, iv=SECRET_KEY[:16])
    return unpad(cipher.decrypt(encrypted_bytes), AES.block_size).decode()

# Client setup
HOST = "10.1.79.59"  # Change this to the server's IP address
PORT = 5050

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((HOST, PORT))

# Get user input
message = input("Enter a message to send: ")

# Encrypt the message before sending
encrypted_message = encrypt_message(message)
print(f"Encrypted message sent: {encrypted_message}")
client_socket.sendall(encrypted_message.encode())

# Receive and decrypt response
encrypted_response = client_socket.recv(1024).decode()
decrypted_response = decrypt_message(encrypted_response)
print(f"Server response (decrypted): {decrypted_response}")

client_socket.close()
