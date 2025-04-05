import socket
from cryptography.fernet import Fernet
import threading
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MASTER_KEY_FILE = os.path.join(BASE_DIR, "master.key")

def display_welcome_message():
    print("\n" + "=" * 40)
    print("         WELCOME TO SAFESPACE         ")
    print("=" * 40)
    print("A Secure Chat Platform\n")

def load_master_key():
    """Loads the master key from file."""
    try:
        with open(MASTER_KEY_FILE, "rb") as f:
            return f.read().decode()
    except FileNotFoundError:
        print("[ERROR] Master key not found. Make sure 'master.key' is in this folder.")
        exit(1)

def listen_for_messages(client, cipher):
    """Listens for incoming messages and prints them."""
    while True:
        try:
            encrypted_response = client.recv(1024)
            if encrypted_response:
                decrypted_response = cipher.decrypt(encrypted_response).decode()
                print(decrypted_response)
            else:
                break
        except:
            break

def start_client():
    display_welcome_message()
    host = input("Enter server IP address: ")
    port = int(input("Enter server port number: "))
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client.connect((host, port))

        # Receive and decrypt the session key
        encrypted_session_key = client.recv(1024)
        master_key = load_master_key()
        session_key = Fernet(master_key).decrypt(encrypted_session_key)
        session_cipher = Fernet(session_key)

        # Send username
        username = input("Enter your username: ")
        client.send(session_cipher.encrypt(username.encode()))

        # Start listener thread
        listener = threading.Thread(target=listen_for_messages, args=(client, session_cipher))
        listener.daemon = True
        listener.start()

        print("Enter message to send (type 'exit' to quit):")
        while True:
            message = input()
            if message.lower() == 'exit':
                break
            full_message = f"{username}: {message}"
            encrypted_message = session_cipher.encrypt(full_message.encode())
            client.send(encrypted_message)

    except Exception as e:
        print(f"[ERROR] Connection failed: {e}")
    finally:
        client.close()

if __name__ == "__main__":
    start_client()
