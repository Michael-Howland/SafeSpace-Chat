import socket
from cryptography.fernet import Fernet
import threading
import os
from prompt_toolkit import PromptSession
from prompt_toolkit.patch_stdout import patch_stdout
import sys
import platform
import time
import json

if getattr(sys, 'frozen', False):
    BASE_DIR = os.path.dirname(sys.executable)
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

MASTER_KEY_FILE = os.path.join(BASE_DIR, "master.key")

message_buffer = []
buffer_lock = threading.Lock()

def display_welcome_message():
    print("\n" + "=" * 40)
    print("         WELCOME TO SAFESPACE         ")
    print("=" * 40)
    print("A Secure Chat Platform\n")

def load_master_key():
    try:
        with open(MASTER_KEY_FILE, "rb") as f:
            return f.read().decode()
    except FileNotFoundError:
        print("[ERROR] Master key not found. Make sure 'master.key' is in this folder.")
        exit(1)

def clear_terminal():
    if platform.system() == "Windows":
        os.system("cls")
    else:
        os.system("clear")

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

def render_messages(client_config):
    clear_terminal()
    display_welcome_message()
    with buffer_lock:
        now = time.time()
        for msg, timestamp in message_buffer:
            if now - timestamp < client_config["message_lifetime"]:
                print(msg)

def buffer_cleanup_loop(client_config):
    while True:
        time.sleep(client_config["refresh_interval"])
        with buffer_lock:
            message_buffer[:] = [
                (msg, ts) for msg, ts in message_buffer
                if time.time() - ts < client_config["message_lifetime"]
            ]
        render_messages(client_config)

def listen_for_messages(client, cipher, client_config):
    while True:
        try:
            encrypted_response = recv_full(client)
            if encrypted_response:
                decrypted_response = cipher.decrypt(encrypted_response).decode()
                with buffer_lock:
                    message_buffer.append((decrypted_response, time.time()))
                render_messages(client_config)
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

        encrypted_session_key = recv_full(client)
        master_key = load_master_key()
        session_key = Fernet(master_key).decrypt(encrypted_session_key)
        session_cipher = Fernet(session_key)

        encrypted_config = recv_full(client)
        config_json = session_cipher.decrypt(encrypted_config).decode()
        client_config = json.loads(config_json)

        session = PromptSession()
        username = session.prompt("Enter your username: ")
        send_full(client, session_cipher.encrypt(username.encode()))

        listener = threading.Thread(target=listen_for_messages, args=(client, session_cipher, client_config), daemon=True)
        cleaner = threading.Thread(target=buffer_cleanup_loop, args=(client_config,), daemon=True)
        listener.start()
        cleaner.start()

        while True:
            with patch_stdout():
                message = session.prompt("-> ")
            if message.lower() == 'exit':
                break

            full_message = f"{username}: {message}"
            encrypted_message = session_cipher.encrypt(full_message.encode())
            send_full(client, encrypted_message)

            timestamped = f"{time.strftime('[%H:%M]', time.localtime())} {full_message}"
            with buffer_lock:
                message_buffer.append((timestamped, time.time()))

            render_messages(client_config)

    except Exception as e:
        print(f"[ERROR] Connection failed: {e}")
    finally:
        client.close()

if __name__ == "__main__":
    start_client()
