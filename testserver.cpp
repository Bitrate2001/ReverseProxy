#include <cerrno>
#include <cstring>
#include <iostream>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

int main() {
  int serverSocket = socket(AF_INET, SOCK_STREAM, 0);
  if (serverSocket < 0) {
    std::cerr << "Socket creation failed: " << strerror(errno) << std::endl;
    return 1;
  }

  sockaddr_in serverAddr;
  memset(&serverAddr, 0, sizeof(serverAddr));
  serverAddr.sin_family = AF_INET;
  serverAddr.sin_addr.s_addr = INADDR_ANY; // Bind to all interfaces
  serverAddr.sin_port = htons(8813);       // Listen on port 80

  if (bind(serverSocket, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) <
      0) {
    std::cerr << "Bind failed: " << strerror(errno) << std::endl;
    close(serverSocket);
    return 1;
  }

  if (listen(serverSocket, 5) < 0) {
    std::cerr << "Listen failed: " << strerror(errno) << std::endl;
    close(serverSocket);
    return 1;
  }

  std::cout << "Test server listening on port 8813" << std::endl;

  while (true) {
    int clientSocket = accept(serverSocket, nullptr, nullptr);
    if (clientSocket < 0) {
      std::cerr << "Accept failed: " << strerror(errno) << std::endl;
      continue; // Continue to the next connection
    }

    // Buffer to store the incoming request
    char buffer[4096];
    int bytesRead = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
    if (bytesRead > 0) {
      buffer[bytesRead] = '\0'; // Null-terminate the string
      std::cout << "Received request:\n" << buffer << std::endl;

      // Prepare a simple HTTP response
      const char *response = "HTTP/1.1 200 OK\r\n"
                             "Content-Type: text/plain\r\n"
                             "Content-Length: 13\r\n"
                             "Anche a me !\r\n"
                             "Connection: close\r\n"
                             "\r\n";
      send(clientSocket, response, strlen(response), 0);
    }

    close(clientSocket);
  }

  close(serverSocket);
  return 0;
}
