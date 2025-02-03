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

# Server setup
HOST = "10.1.79.59"  # Change this to your WiFi IP address
PORT = 5050

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((HOST, PORT))
server_socket.listen(1)

print(f"Server listening on {HOST}:{PORT}")

conn, addr = server_socket.accept()
print(f"Connected by {addr}")

while True:
    encrypted_data = conn.recv(1024).decode()
    if not encrypted_data:
        break
    
    print(f"Encrypted message from client: {encrypted_data}")

    # Decrypt the received message
    decrypted_message = decrypt_message(encrypted_data)
    print(f"Decrypted message: {decrypted_message}")

    # Prepare response
    response = f"Received: {decrypted_message}"
    
    # Encrypt the response
    encrypted_response = encrypt_message(response)
    
    # Send the encrypted response back to the client
    conn.sendall(encrypted_response.encode())

conn.close()
server_socket.close()
