#include "reverseproxy.h"
#include "sslSetup.h"
#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <iostream>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <sys/socket.h>
#include <unistd.h>

void ReverseProxy::initProxy() {
    int serverSocket =
        socket(AF_INET, SOCK_STREAM, 0); // Server to forward resources
    sockaddr_in serverAddr;
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(port); // Target server port
    if (bind(serverSocket, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) <
        0) {
      std::cerr << "Bind failed: " << strerror(errno) << std::endl;
      close(serverSocket);
    }

    if (listen(serverSocket, 5) < 0) {
      std::cerr << "Listen failed: " << strerror(errno) << std::endl;
      close(serverSocket);
    }
    while (true) {
      int clientSocket = accept(serverSocket, nullptr, nullptr);
      if (clientSocket < 0) {
        std::cerr << "Accept failed: " << strerror(errno) << std::endl;
      }
      SSL* ssl = SSL_new(ctx);
      SSL_set_fd(ssl, clientSocket);
      if (SSL_accept(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
      } else {
        clientHandler(ssl);
      }
      SSL_free(ssl);
      close(clientSocket);
    }

    close(serverSocket);
}

ReverseProxy::ReverseProxy() {
  initSSL();
  ctx = createContext();
  configureContext(ctx);
}

void ReverseProxy::clientHandler(SSL* clientSSL) {
  char buffer[4096];
  int bytesRead = SSL_read(clientSSL, buffer, sizeof(buffer));

  if (bytesRead > 0) {
    int targetSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (targetSocket < 0) {
      std::cerr << "Socket creation for target failed: " << strerror(errno)
                << std::endl;
      SSL_shutdown(clientSSL);
      return; // Clean up
    }
    sockaddr_in targetAddr;
    targetAddr.sin_family = AF_INET;
    targetAddr.sin_port = htons(targetPort); // Target server port

    inet_pton(AF_INET, "127.0.0.1", &targetAddr.sin_addr);
    if (connect(targetSocket, (struct sockaddr *)&targetAddr,
                sizeof(targetAddr)) < 0) {
      std::cerr << "Connect to target failed: " << strerror(errno) << std::endl;
      close(targetSocket);
      SSL_shutdown(clientSSL);
    }
    send(targetSocket, buffer, bytesRead, 0);
    bytesRead = recv(targetSocket, buffer, sizeof(buffer), 0);
    if (bytesRead > 0) {
      std::cout << "Request received \n" << buffer;
      SSL_write(clientSSL, buffer, bytesRead);
    }
    close(targetSocket);
  } else {
    std::cerr << "No bytes received or error: " << strerror(errno) << std::endl;
  }
  SSL_shutdown(clientSSL);
}

ReverseProxy::~ReverseProxy() {
  SSL_CTX_free(ctx);
  EVP_cleanup();
}

