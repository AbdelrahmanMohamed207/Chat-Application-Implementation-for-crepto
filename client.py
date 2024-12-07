import tkinter as tk
from tkinter import scrolledtext, messagebox
import threading
import socketio
from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad
import base64
from Crypto.Random import get_random_bytes
import requests

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
    try:
        raw_data = base64.b64decode(encrypted_message)
        iv = raw_data[:8]  # Extract IV
        encrypted_data = raw_data[8:]
        cipher = DES3.new(SECRET_KEY, DES3.MODE_CBC, iv)
        decrypted = unpad(cipher.decrypt(encrypted_data), DES3.block_size)
        return decrypted.decode()
    except Exception as e:
        print(f"Error during decryption: {e}")
        return "Error: Could not decrypt message"

# Server URL
SERVER_URL = "http://localhost:5000"

class ChatClient:
    def __init__(self):
        self.sio = socketio.Client()
        self.username = None

    def connect_to_server(self):
        try:
            self.sio.connect(SERVER_URL)
            print("Connected to server.")
        except socketio.exceptions.ConnectionError:
            print("Error: Unable to connect to server.")
            exit()

    def register(self, username, password):
        response = requests.post(f"{SERVER_URL}/register", json={'username': username, 'password': password})
        return response.json()

    def login(self, username, password):
        response = requests.post(f"{SERVER_URL}/login", json={'username': username, 'password': password})
        result = response.json()
        if result.get('success'):
            self.username = username
            print("Login successful!")
            return True
        else:
            print(result.get('message'))
            return False

    def send_message(self, message):
        encrypted_msg = encrypt_message(message)
        self.sio.emit('message', {'username': self.username, 'message': encrypted_msg})

    def listen_for_messages(self, on_message_callback):
        self.sio.on('message', on_message_callback)

    def disconnect(self):
        self.sio.disconnect()

class ChatClientGUI:
    def __init__(self):
        self.client = ChatClient()
        self.root = tk.Tk()
        self.root.title("Chat Application")
        self.username = None

        # Login/Registration Screen
        self.login_frame = tk.Frame(self.root)
        self.chat_frame = None
        self.create_login_screen()

    def create_login_screen(self):
        tk.Label(self.login_frame, text="Username:").grid(row=0, column=0, padx=10, pady=10)
        tk.Label(self.login_frame, text="Password:").grid(row=1, column=0, padx=10, pady=10)

        self.username_entry = tk.Entry(self.login_frame)
        self.password_entry = tk.Entry(self.login_frame, show="*")
        self.username_entry.grid(row=0, column=1, padx=10, pady=10)
        self.password_entry.grid(row=1, column=1, padx=10, pady=10)

        tk.Button(self.login_frame, text="Login", command=self.login).grid(row=2, column=0, padx=10, pady=10)
        tk.Button(self.login_frame, text="Register", command=self.register).grid(row=2, column=1, padx=10, pady=10)

        self.login_frame.pack()

    def create_chat_screen(self):
        self.login_frame.pack_forget()

        self.chat_frame = tk.Frame(self.root)

        self.message_display = scrolledtext.ScrolledText(self.chat_frame, state='disabled', width=50, height=20)
        self.message_display.grid(row=0, column=0, columnspan=2, padx=10, pady=10)

        self.message_entry = tk.Entry(self.chat_frame, width=40)
        self.message_entry.grid(row=1, column=0, padx=10, pady=10)

        send_button = tk.Button(self.chat_frame, text="Send", command=self.send_message)
        send_button.grid(row=1, column=1, padx=10, pady=10)

        self.chat_frame.pack()

        # Start listening for messages
        threading.Thread(target=self.listen_for_messages, daemon=True).start()

    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()

        if not username or not password:
            messagebox.showerror("Error", "Please enter both username and password.")
            return

        if self.client.login(username, password):
            self.username = username
            self.create_chat_screen()
        else:
            messagebox.showerror("Error", "Login failed.")

    def register(self):
        username = self.username_entry.get()
        password = self.password_entry.get()

        if not username or not password:
            messagebox.showerror("Error", "Please enter both username and password.")
            return

        response = self.client.register(username, password)
        if response.get('success'):
            messagebox.showinfo("Success", "Registration successful.")
        else:
            messagebox.showerror("Error", response.get('message'))

    def send_message(self):
        message = self.message_entry.get()
        if message:
            self.client.send_message(message)
            self.message_entry.delete(0, tk.END)

    def listen_for_messages(self):
        def on_message(data):
            try:
                decrypted_message = decrypt_message(data)
                self.update_chat(decrypted_message)
            except Exception as e:
                print(f"Error decrypting message: {e}")

        self.client.listen_for_messages(on_message)

    def update_chat(self, message):
        self.message_display.config(state='normal')
        self.message_display.insert(tk.END, f"{message}\n")
        self.message_display.config(state='disabled')

    def run(self):
        self.client.connect_to_server()
        self.root.mainloop()

if __name__ == "__main__":
    ChatClientGUI().run()
