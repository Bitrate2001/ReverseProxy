#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>

const int port = 8811;

void clientHandler (int clientSocket) {
  char buffer[4096];
  int bytesRead = recv(clientSocket, buffer, sizeof(buffer), 0);

  if (bytesRead > 0) {
    int targetSocket = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in targetAddr;
    targetAddr.sin_family = AF_INET;
    targetAddr.sin_port = htons(80);

    inet_pton(AF_INET, "127.0.0.1", &targetAddr.sin_addr);
    connect(targetSocket, (struct sockaddr*)&targetAddr, sizeof(targetAddr));
    send(targetSocket, buffer, bytesRead, 0);
    bytesRead = recv(targetSocket, buffer, sizeof(buffer), 0);
    send(clientSocket, buffer, bytesRead, 0);

    close(clientSocket);
  } 

}

int main (int argc, char *argv[]) {
 int serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(81);
    bind(serverSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr));
    listen(serverSocket, 5);

    while (true) {
        int clientSocket = accept(serverSocket, nullptr, nullptr);
        clientHandler(clientSocket);
    }

    close(serverSocket);
    return 0; 
  return 0;
}
