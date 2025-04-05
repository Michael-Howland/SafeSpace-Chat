import socket
import threading
from cryptography.fernet import Fernet
import uuid
import os

# Configuration
HOST = '127.0.0.1'
PORT = 5555
MASTER_KEY_FILE = "master.key"

clients = {}  # Stores client info by session ID

def load_or_create_master_key():
    """Loads the master key from file or creates a new one if it doesn't exist."""
    if not os.path.exists(MASTER_KEY_FILE):
        key = Fernet.generate_key()
        with open(MASTER_KEY_FILE, "wb") as f:
            f.write(key)
    with open(MASTER_KEY_FILE, "rb") as f:
        return f.read().decode()

def list_usernames():
    """Returns a list of all connected usernames."""
    return [data['username'] for data in clients.values()]

def handle_client(client_socket, addr):
    """Handles communication with a single connected client."""
    session_id = str(uuid.uuid4())
    session_key = Fernet.generate_key()

    # Encrypt session key with master key and send to client
    encrypted_session_key = Fernet(master_key).encrypt(session_key)
    client_socket.send(encrypted_session_key)

    client_cipher = Fernet(session_key)

    # Receive and store client's username
    username = client_cipher.decrypt(client_socket.recv(1024)).decode()
    clients[session_id] = {
        'username': username,
        'socket': client_socket,
        'session_key': session_key
    }

    # Notify others of new user
    if len(clients) > 1:
        join_message = f"{username} has joined the chat. Members: {', '.join(list_usernames())}"
    else:
        join_message = "You are currently the only user in the chat."
    broadcast_message(session_id, join_message, broadcast_to_all=True)

    try:
        while True:
            encrypted_message = client_socket.recv(1024)
            if not encrypted_message:
                break

            message = client_cipher.decrypt(encrypted_message).decode()
            broadcast_message(session_id, message)

    except Exception:
        pass
    finally:
        broadcast_message(session_id, f"{clients[session_id]['username']} has left the chat.")
        del clients[session_id]
        client_socket.close()

def broadcast_message(sender_id, message, broadcast_to_all=False):
    """Encrypts and sends a message to all clients except the sender (unless broadcast_to_all is True)."""
    for session_id, client_data in clients.items():
        if session_id != sender_id or broadcast_to_all:
            try:
                encrypted_message = Fernet(client_data['session_key']).encrypt(message.encode())
                client_data['socket'].send(encrypted_message)
            except Exception:
                continue

def start_server():
    """Starts the server and listens for incoming connections."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen(5)
    while True:
        client_socket, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(client_socket, addr))
        thread.start()

if __name__ == "__main__":
    master_key = load_or_create_master_key()
    start_server()
