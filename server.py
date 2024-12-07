from flask import Flask, request, jsonify
from flask_socketio import SocketIO, emit
from flask_cors import CORS
from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64
import os
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from Crypto.Random import get_random_bytes

# Initialize Flask App and SocketIO
app = Flask(__name__)
CORS(app)
app.config['SECRET_KEY'] = 'your_secret_key'
socketio = SocketIO(app, cors_allowed_origins="*")

# Encryption Setup
raw_key = b'secure_key_must_be_24_by'
SECRET_KEY = DES3.adjust_key_parity(raw_key)

# RSA Key Generation (only need to run once)
def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    with open('private.pem', 'wb') as f:
        f.write(private_key)
    with open('public.pem', 'wb') as f:
        f.write(public_key)

# Uncomment this line to generate keys once
# generate_rsa_keys()

# Load the RSA keys for encryption/decryption
def load_rsa_keys():
    with open('private.pem', 'rb') as f:
        private_key = RSA.import_key(f.read())
    with open('public.pem', 'rb') as f:
        public_key = RSA.import_key(f.read())
    return private_key, public_key

private_key, public_key = load_rsa_keys()

# RSA Encryption and Decryption
def rsa_encrypt(data, public_key):
    cipher = PKCS1_OAEP.new(public_key)
    return cipher.encrypt(data)

def rsa_decrypt(encrypted_data, private_key):
    cipher = PKCS1_OAEP.new(private_key)
    return cipher.decrypt(encrypted_data)

def encrypt_message(message):
    iv = get_random_bytes(8)  # Generate random IV
    cipher = DES3.new(SECRET_KEY, DES3.MODE_CBC, iv)
    padded_message = pad(message.encode(), DES3.block_size)  # Pad the message
    encrypted = cipher.encrypt(padded_message)
    return base64.b64encode(iv + encrypted).decode()  # Combine IV and encrypted message, then base64 encode

def decrypt_message(encrypted_message):
    try:
        raw_data = base64.b64decode(encrypted_message)  # Decode the base64 encoded string
        iv = raw_data[:8]  # Extract the IV (first 8 bytes)
        encrypted_data = raw_data[8:]  # Extract the actual encrypted data

        cipher = DES3.new(SECRET_KEY, DES3.MODE_CBC, iv)
        decrypted = unpad(cipher.decrypt(encrypted_data), DES3.block_size)  # Decrypt and remove padding
        return decrypted.decode()  # Return the decrypted message as a string
    except Exception as e:
        print(f"Error during decryption: {e}")
        raise

# File for storing user data
USER_FILE = "users.txt"
DEBUG_FILE = "debug_messages.txt"  # Debug file for encrypted messages

# Initialize the text file if it doesn't exist
if not os.path.exists(USER_FILE):
    with open(USER_FILE, "w") as f:
        f.write("")

# Initialize Argon2 password hasher
ph = PasswordHasher()

# User Registration Route
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'success': False, 'message': 'Username and password are required'}), 400

    with open(USER_FILE, "r") as f:
        users = [line.strip() for line in f.readlines()]
        if any(user.split(":")[0] == username for user in users):
            return jsonify({'success': False, 'message': 'Username already exists'}), 409

    # Hash the password with Argon2
    hashed_password = ph.hash(password)

    with open(USER_FILE, "a") as f:
        f.write(f"{username}:{hashed_password}\n")

    return jsonify({'success': True, 'message': 'User registered successfully'})

# User Login Route
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    with open(USER_FILE, "r") as f:
        users = [line.strip() for line in f.readlines()]
        for user in users:
            stored_username, stored_hash = user.split(":", 1)
            if stored_username == username:
                try:
                    # Verify the provided password against the stored hash
                    ph.verify(stored_hash, password)
                    return jsonify({'success': True, 'message': 'Login successful'})
                except VerifyMismatchError:
                    return jsonify({'success': False, 'message': 'Invalid credentials'}), 401

    return jsonify({'success': False, 'message': 'Invalid credentials'}), 401

# WebSocket Handlers
connected_users = {}

@socketio.on('connect')
def handle_connect():
    print("A user connected.")
    with open('public.pem', 'rb') as f:
        public_key = base64.b64encode(f.read()).decode()
    emit('public_key', {'public_key': public_key})

@socketio.on('login')
def handle_login(data):
    username = data.get('username')
    if username in connected_users:
        emit('login_error', {'message': 'User already logged in'}, to=request.sid)
    else:
        connected_users[username] = request.sid
        emit('login_success', {'message': f'Welcome {username}!'}, to=request.sid)
        emit('message', encrypt_message(f"{username} has joined the chat"), broadcast=True)
        print(f"User {username} connected.")

@socketio.on('message')
def handle_message(data):
    username = data.get('username')
    encrypted_message = data.get('message')
    try:
        # Log encrypted message to the debug file
        with open(DEBUG_FILE, "a") as debug_file:
            debug_file.write(f"Encrypted message from {username}: {encrypted_message}\n")

        # Decrypt the message and log to console
        message = decrypt_message(encrypted_message)
        print(f"Message from {username}: {message}")

        # Broadcast encrypted message for privacy
        emit('message', encrypt_message(f"{username}: {message}"), broadcast=True)
    except Exception as e:
        print(f"Error decrypting message: {e}")

@socketio.on('disconnect')
def handle_disconnect():
    username = None
    for user, sid in connected_users.items():
        if sid == request.sid:
            username = user
            break
    if username:
        del connected_users[username]
        emit('message', encrypt_message(f"{username} has left the chat"), broadcast=True)
    print("A user disconnected.")

# Run the server
if __name__ == '__main__':
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)
