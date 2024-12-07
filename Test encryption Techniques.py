import unittest
from unittest.mock import patch, MagicMock
from base64 import b64encode, b64decode
from Crypto.Cipher import DES3, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

class TestEncryptionTechniques(unittest.TestCase):

    def setUp(self):
        # Setup DES3 key
        raw_key = b'secure_key_must_be_24_by'
        self.SECRET_KEY = DES3.adjust_key_parity(raw_key)

        # Setup RSA keys
        key = RSA.generate(2048)
        self.private_key = key.export_key()
        self.public_key = key.publickey().export_key()
        self.rsa_private_cipher = PKCS1_OAEP.new(RSA.import_key(self.private_key))
        self.rsa_public_cipher = PKCS1_OAEP.new(RSA.import_key(self.public_key))

    def encrypt_message_server(self, message):
        iv = get_random_bytes(8)
        cipher = DES3.new(self.SECRET_KEY, DES3.MODE_CBC, iv)
        padded_message = pad(message.encode(), DES3.block_size)
        encrypted = cipher.encrypt(padded_message)
        return b64encode(iv + encrypted).decode()

    def decrypt_message_server(self, encrypted_message):
        raw_data = b64decode(encrypted_message)
        iv = raw_data[:8]
        encrypted_data = raw_data[8:]
        cipher = DES3.new(self.SECRET_KEY, DES3.MODE_CBC, iv)
        decrypted = unpad(cipher.decrypt(encrypted_data), DES3.block_size)
        return decrypted.decode()

    def rsa_encrypt(self, data):
        return self.rsa_public_cipher.encrypt(data)

    def rsa_decrypt(self, encrypted_data):
        return self.rsa_private_cipher.decrypt(encrypted_data)

    def test_encrypt_decrypt_message_server(self):
        message = "Hello, this is a test message."
        encrypted_message = self.encrypt_message_server(message)
        print(f"Encrypted Message (Server): {encrypted_message}")
        decrypted_message = self.decrypt_message_server(encrypted_message)
        print(f"Decrypted Message (Server): {decrypted_message}")
        self.assertEqual(message, decrypted_message)

    def test_rsa_encrypt_decrypt(self):
        message = b"This is a test RSA message."
        encrypted_message = self.rsa_encrypt(message)
        print(f"Encrypted Message (RSA): {b64encode(encrypted_message).decode()}")
        decrypted_message = self.rsa_decrypt(encrypted_message)
        print(f"Decrypted Message (RSA): {decrypted_message.decode()}")
        self.assertEqual(message, decrypted_message)

    def test_encrypt_message_invalid_key(self):
        invalid_key = b"invalid_key_24_bytes!!"
        with self.assertRaises(ValueError):
            iv = get_random_bytes(8)
            cipher = DES3.new(invalid_key, DES3.MODE_CBC, iv)
            cipher.encrypt(pad(b"Test", DES3.block_size))

    def test_decrypt_message_invalid_data(self):
        invalid_data = "InvalidEncryptedMessage"
        with self.assertRaises(Exception):
            self.decrypt_message_server(invalid_data)

    def test_client_server_integration(self):
        # Encrypt with server method, decrypt with client
        message = "Integration test between client and server."
        encrypted_message = self.encrypt_message_server(message)
        print(f"Encrypted Message (Integration - Server to Client): {encrypted_message}")
        decrypted_message = self.decrypt_message_server(encrypted_message)
        print(f"Decrypted Message (Integration - Server to Client): {decrypted_message}")
        self.assertEqual(message, decrypted_message)

        # Encrypt with client method, decrypt with server
        iv = get_random_bytes(8)
        cipher = DES3.new(self.SECRET_KEY, DES3.MODE_CBC, iv)
        padded_message = pad(message.encode(), DES3.block_size)
        encrypted_message = b64encode(iv + cipher.encrypt(padded_message)).decode()
        print(f"Encrypted Message (Integration - Client to Server): {encrypted_message}")
        decrypted_message = self.decrypt_message_server(encrypted_message)
        print(f"Decrypted Message (Integration - Client to Server): {decrypted_message}")
        self.assertEqual(message, decrypted_message)

if __name__ == '__main__':
    unittest.main()
