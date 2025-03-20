import socket
import threading
from cryptography.fernet import Fernet

# Server configuration
HOST = '127.0.0.1'
PORT = 5555
SERVER_PASSWORD = "chat123"

# Generate encryption key
encryption_key = Fernet.generate_key()
cipher = Fernet(encryption_key)

clients = {}  # Stores client sockets mapped to usernames
usernames = set()  # Stores active usernames

def encrypt_message(message):
    """Encrypts a message before sending."""
    return cipher.encrypt(message.encode())

def decrypt_message(message):
    """Decrypts a received message."""
    return cipher.decrypt(message).decode()

def handle_client(client_socket, addr):
    """Handles communication with a connected client."""
    print(f"[NEW CONNECTION] {addr} is attempting to connect.")

    # Send encryption key
    client_socket.send(encryption_key)

    # Request and validate username
    username = None
    while True:
        client_socket.send(encrypt_message("ENTER_USERNAME"))
        username = decrypt_message(client_socket.recv(1024))

        if username in usernames:
            client_socket.send(encrypt_message("USERNAME_TAKEN"))
        else:
            usernames.add(username)
            clients[client_socket] = username
            client_socket.send(encrypt_message("USERNAME_ACCEPTED"))
            break

    # Request and verify the server password
    attempts = 0
    while attempts < 3:
        client_socket.send(encrypt_message("ENTER_PASSWORD"))
        password = decrypt_message(client_socket.recv(1024))

        if password == SERVER_PASSWORD:
            client_socket.send(encrypt_message("AUTHENTICATION_SUCCESSFUL"))
            break
        else:
            attempts += 1
            if attempts == 3:
                client_socket.send(encrypt_message("INVALID_PASSWORD"))
                usernames.discard(username)  # Remove username from active set
                clients.pop(client_socket, None)  # Remove client from list safely
                client_socket.close()
                print(f"[FAILED] {addr} failed password authentication after 3 attempts.")
                return
            else:
                client_socket.send(encrypt_message("INVALID_PASSWORD"))
    if len(usernames) == 1:
        broadcast("You are the only member in this chat right now.", "SERVER")
    else:
        broadcast(f"{username} has joined the chat. Current members: {", ".join(usernames)}.", "SERVER")

    try:
        while True:
            message = decrypt_message(client_socket.recv(1024))
            if not message:
                break
            broadcast(f"{username}: {message}", client_socket)
    except:
        pass
    finally:
        usernames.discard(username)
        if len(usernames) == 1:
            broadcast(f"{username} has left the chat. You are now the only member in this chat.", "SERVER")
        else:
            broadcast(f"{username} has left the chat Current members: {", ".join(usernames)}.", "SERVER")
        clients.pop(client_socket, None)
        client_socket.close()

def broadcast(message, exclude_client=None):
    """Sends an encrypted message to all connected clients, except the sender."""
    encrypted_message = encrypt_message(message)
    
    for client in list(clients.keys()):
        if client != exclude_client:  # Exclude the sender from receiving the message
            try:
                client.send(encrypted_message)
            except:
                client.close()
                clients.pop(client, None)  # Safely remove disconnected clients

def start_server():
    """Starts the chat server."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen(5)

    print(f"[LISTENING] Server is listening on {HOST}:{PORT}")

    while True:
        client_socket, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(client_socket, addr))
        thread.start()

if __name__ == "__main__":
    start_server()
