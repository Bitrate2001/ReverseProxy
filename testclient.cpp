#include <arpa/inet.h>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <iostream>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <thread>
#include <unistd.h>

int main() {
  const char *serverIP = "127.0.0.1"; // Server IP address
  const int serverPort = 8815;        // Server port
  const int numRequests = 100;        // Number of requests to send

  for (int i = 0; i < numRequests; ++i) {
    // Create a socket for each request
    int clientSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (clientSocket < 0) {
      std::cerr << "Socket creation failed: " << strerror(errno) << std::endl;
      return 1;
    }

    // Setup server address structure
    sockaddr_in serverAddr;
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(serverPort);
    inet_pton(AF_INET, serverIP, &serverAddr.sin_addr);

    // Connect to the server
    if (connect(clientSocket, (struct sockaddr *)&serverAddr,
                sizeof(serverAddr)) < 0) {
      std::cerr << "Connect failed: " << strerror(errno) << std::endl;
      close(clientSocket);
      return 1;
    }

    // Prepare and send an HTTP GET request
    const char *request = "GET / HTTP/1.1\r\n"
                          "Host: localhost\r\n"
                          "Connection: close\r\n"
                          "Mi piace la Patatona\r\n"
                          "\r\n";
    send(clientSocket, request, strlen(request), 0);

    // Receive the response
    char buffer[4096];
    int bytesRead = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
    if (bytesRead > 0) {
      buffer[bytesRead] = '\0'; // Null-terminate the buffer
      std::cout << "Response from server for request " << (i + 1) << ":\n"
                << buffer << std::endl;
    } else {
      std::cerr << "Failed to read response for request " << (i + 1) << ": "
                << strerror(errno) << std::endl;
    }

    // Close the client socket
    close(clientSocket);
    auto now = std::chrono::system_clock::now();
    std::this_thread::sleep_for(std::chrono::seconds(1));
  }

  return 0;
}
