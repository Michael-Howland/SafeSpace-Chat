import socket
import threading
from cryptography.fernet import Fernet
import uuid
import os
import json
from datetime import datetime

with open('config.json') as f:
    config = json.load(f)

HOST = config["server"]["host"]
PORT = config["server"]["port"]
TIMEOUT = config["server"]["timeout"]
ENABLE_TIMESTAMPS = config["server"]["message_timestamp"]
MASTER_KEY_FILE = "master.key"

clients = {}

def load_or_create_master_key():
    if not os.path.exists(MASTER_KEY_FILE):
        key = Fernet.generate_key()
        with open(MASTER_KEY_FILE, "wb") as f:
            f.write(key)
    with open(MASTER_KEY_FILE, "rb") as f:
        return f.read().decode()

def send_full(conn, data: bytes):
    length = len(data).to_bytes(4, 'big')
    conn.sendall(length + data)

def recv_full(conn) -> bytes:
    length_bytes = conn.recv(4)
    if not length_bytes:
        return None
    length = int.from_bytes(length_bytes, 'big')
    data = b''
    while len(data) < length:
        packet = conn.recv(length - len(data))
        if not packet:
            return None
        data += packet
    return data

def list_usernames():
    return [data['username'] for data in clients.values()]

def handle_client(client_socket, addr):
    session_id = str(uuid.uuid4())
    session_key = Fernet.generate_key()
    client_cipher = Fernet(session_key)

    send_full(client_socket, Fernet(master_key).encrypt(session_key))
    send_full(client_socket, client_cipher.encrypt(json.dumps(config["client"]).encode()))

    try:
        username = client_cipher.decrypt(recv_full(client_socket)).decode()
    except Exception:
        client_socket.close()
        return

    clients[session_id] = {
        'username': username,
        'socket': client_socket,
        'session_key': session_key
    }

    if len(clients) > 1:
        join_message = f"[ALERT]{username} has joined the chat. Members: {', '.join(list_usernames())}"
    else:
        join_message = "[ALERT]You are currently the only user in the chat."
    broadcast_message(session_id, join_message, broadcast_to_all=True)

    try:
        while True:
            try:
                encrypted_message = recv_full(client_socket)
                if not encrypted_message:
                    break
                message = client_cipher.decrypt(encrypted_message).decode()
                broadcast_message(session_id, message)
            except socket.timeout:
                print(f"[TIMEOUT] {username} has been inactive. Closing connection.")
                break
            except Exception as e:
                print(f"[ERROR] {username} caused an error: {e}")
                break
    finally:
        broadcast_message(session_id, f"{clients[session_id]['username']} has left the chat.")
        del clients[session_id]
        client_socket.close()

def broadcast_message(sender_id, message, broadcast_to_all=False):
    if ENABLE_TIMESTAMPS:
        timestamp = datetime.now().strftime("%H:%M")
        message = f"[{timestamp}] {message}"
    for session_id, client_data in list(clients.items()):
        if session_id != sender_id or broadcast_to_all:
            try:
                encrypted_message = Fernet(client_data['session_key']).encrypt(message.encode())
                send_full(client_data['socket'], encrypted_message)
            except Exception:
                continue

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen(5)
    while True:
        client_socket, addr = server.accept()
        client_socket.settimeout(TIMEOUT)
        thread = threading.Thread(target=handle_client, args=(client_socket, addr))
        thread.start()

if __name__ == "__main__":
    master_key = load_or_create_master_key()
    start_server()
