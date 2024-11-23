import requests
import socketio
from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad
import base64
from Crypto.Random import get_random_bytes

# Encryption Setup
raw_key = b'secure_key_must_be_24_by'
SECRET_KEY = DES3.adjust_key_parity(raw_key)

def encrypt_message(message):
    iv = get_random_bytes(8)  # Generate random IV
    cipher = DES3.new(SECRET_KEY, DES3.MODE_CBC, iv)
    padded_message = pad(message.encode(), DES3.block_size)
    encrypted = cipher.encrypt(padded_message)
    return base64.b64encode(iv + encrypted).decode()

def decrypt_message(encrypted_message):
    raw_data = base64.b64decode(encrypted_message)
    iv = raw_data[:8]
    cipher = DES3.new(SECRET_KEY, DES3.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(raw_data[8:]), DES3.block_size)
    return decrypted.decode()

# Server URL
SERVER_URL = "http://localhost:5000"

class ChatClient:
    def __init__(self):
        self.username = None
        self.sio = socketio.Client()

    def connect_to_server(self):
        try:
            self.sio.connect(SERVER_URL)
            print("Connected to server.")
        except socketio.exceptions.ConnectionError:
            print("Error: Unable to connect to server.")
            exit()

    def register(self):
        username = input("Enter a username: ")
        password = input("Enter a password: ")
        response = requests.post(f"{SERVER_URL}/register", json={'username': username, 'password': password})
        message = response.json().get('message')
        print(message)

    def login(self):
        username = input("Enter your username: ")
        password = input("Enter your password: ")
        response = requests.post(f"{SERVER_URL}/login", json={'username': username, 'password': password})
        result = response.json()

        if result.get('success'):
            self.username = username
            print("Login successful! Connecting to the chat...")
            self.sio.emit('login', {'username': self.username})
        else:
            print(result.get('message'))

    def send_message(self):
        while True:
            msg = input("Enter message (type 'quit' to exit): ")
            if msg.lower() == 'quit':
                print("Exiting chat...")
                self.sio.disconnect()
                break
            encrypted_msg = encrypt_message(msg)
            self.sio.emit('message', {'username': self.username, 'message': encrypted_msg})

    def receive_message(self, data):
        try:
            decrypted_msg = decrypt_message(data)
            print(decrypted_msg)
        except Exception as e:
            print("Error decrypting message:", e)

    def start_chat(self):
        self.sio.on('message', self.receive_message)
        self.send_message()

    def run(self):
        self.connect_to_server()
        while True:
            print("\n1. Register\n2. Login\n3. Exit")
            choice = input("Choose an option: ")
            if choice == '1':
                self.register()
            elif choice == '2':
                self.login()
                if self.username:
                    self.start_chat()
            elif choice == '3':
                print("Exiting...")
                break
            else:
                print("Invalid choice. Please try again.")

if __name__ == "__main__":
    client = ChatClient()
    client.run()
