#include <arpa/inet.h>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <thread>
#include <unistd.h>

// Init ssl
void initializeSSL() {
  SSL_load_error_strings();
  OpenSSL_add_ssl_algorithms();
}

// Create context funct
SSL_CTX* createContext() {
    const SSL_METHOD* method = SSLv23_client_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
}

void cleanupSSL() { EVP_cleanup(); }

int main() {
  // Server params
  const char *serverIP = "127.0.0.1"; // Server IP address
  const int serverPort = 8815;        // Server port
  const int numRequests = 100;        // Number of requests to send

  // Call ssl init functions
  initializeSSL();
  SSL_CTX *ctx = createContext();

  // Loop request in n < numRequests
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

    // Create SSL object
    SSL *ssl = SSL_new(ctx);
    if (SSL_set_fd(ssl, clientSocket) <= 0) {
      ERR_print_errors_fp(stderr);
    } 

    // Perform SSL handshake
    if (SSL_connect(ssl) <= 0) {
      ERR_print_errors_fp(stderr);
    } else {
      // Prepare and send an HTTP GET request
      const char *request = "GET / HTTP/1.1\r\n"
                            "Host: localhost\r\n"
                            "Connection: close\r\n"
                            "\r\n";
      SSL_write(ssl, request, strlen(request));

      // Receive the response
      char buffer[4096];
      int bytesRead = SSL_read(ssl, buffer, sizeof(buffer) - 1);
      if (bytesRead > 0) {
        buffer[bytesRead] = '\0'; // Null-terminate the buffer
        std::cout << "Response from server for request " << (i + 1) << ":\n"
                  << buffer << std::endl;
      } else {
        ERR_print_errors_fp(stderr);
      }
    }

    // Clean up
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(clientSocket);

    std::this_thread::sleep_for(
        std::chrono::seconds(5)); // Pause between requests
  }

  SSL_CTX_free(ctx);
  cleanupSSL();

  return 0;
}
