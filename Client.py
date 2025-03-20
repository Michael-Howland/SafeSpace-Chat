import socket
import threading
from cryptography.fernet import Fernet
import getpass  # Secure password input

def display_welcome_message():
    """Displays a simple ASCII-style welcome message."""
    print("\n" + "=" * 40)
    print("         WELCOME TO SAFESPACE         ")
    print("=" * 40)
    print("A Secure Chat Platform\n")

def receive_messages(client_socket, cipher):
    """Handles receiving and decrypting messages from the server."""
    while True:
        try:
            message = client_socket.recv(1024)
            if not message:
                break
            print(cipher.decrypt(message).decode())
        except:
            print("Disconnected from server.")
            break

def start_client():
    """Connects to the server and starts sending messages."""

    # Display the welcome message
    display_welcome_message()

    # Prompt user for server details
    host = input("Enter chat server IP address: ")
    port = int(input("Enter chat server port number: "))

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    try:
        client.connect((host, port))
    except:
        print("Failed to connect to the server. Check the IP and port.")
        return

    # Receive encryption key from server
    encryption_key = client.recv(1024)
    cipher = Fernet(encryption_key)

    # Enter username and check if it's unique
    while True:
        response = cipher.decrypt(client.recv(1024)).decode()
        if response == "ENTER_USERNAME":
            username = input("Enter your username: ")
            client.send(cipher.encrypt(username.encode()))
        elif response == "USERNAME_TAKEN":
            print("This username is already taken. Please choose another.")
        elif response == "USERNAME_ACCEPTED":
            break

    # Server password authentication (3 attempts)
    attempts = 0
    while attempts < 3:
        response = cipher.decrypt(client.recv(1024)).decode()
        if response == "ENTER_PASSWORD":
            password = getpass.getpass("Enter server password: ")
            client.send(cipher.encrypt(password.encode()))
            response = cipher.decrypt(client.recv(1024)).decode()

            if response == "AUTHENTICATION_SUCCESSFUL":
                break
            elif response == "INVALID_PASSWORD":
                attempts += 1
                if attempts == 3:
                    print("Incorrect password entered 3 times. Closing connection.")
                    client.close()
                    return
                else:
                    print(f"Incorrect password. You have {3 - attempts} attempts left.")

    print("Connected to the chat server. Type messages and press Enter to send.")

    # Start a thread to receive messages
    thread = threading.Thread(target=receive_messages, args=(client, cipher))
    thread.start()

    try:
        while True:
            message = input()
            if message.lower() == "exit":
                break
            client.send(cipher.encrypt(message.encode()))
    except KeyboardInterrupt:
        print("Exiting...")
    finally:
        client.close()

if __name__ == "__main__":
    start_client()
