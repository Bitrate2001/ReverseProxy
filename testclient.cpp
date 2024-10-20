#include <arpa/inet.h>
#include <chrono>
#include <cstring>
#include <iostream>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <thread>
#include <unistd.h>

void initializeSSL() {
  SSL_load_error_strings();
  OpenSSL_add_ssl_algorithms();
}

SSL_CTX *createContext() {
  const SSL_METHOD *method = TLS_client_method();
  SSL_CTX *ctx = SSL_CTX_new(method);
  if (!ctx) {
    perror("Unable to create SSL context");
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
  }

  // Set the location of the CA certificates
  if (SSL_CTX_load_verify_locations(ctx, "server.crt", NULL) <= 0) {
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
  } else {
    std::cout << "Certificate valid \n";
  }

  // Require server certificate verification
  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

  return ctx;
}

void cleanupSSL() { EVP_cleanup(); }

int main() {
  const char *serverIP = "127.0.0.1"; // Server IP address
  const int serverPort = 8815;        // Server port
  const int numRequests = 100;        // Number of requests to send

  initializeSSL();
  SSL_CTX *ctx = createContext();

  for (int i = 0; i < numRequests; ++i) {
    // Create a socket for each request
    int clientSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (clientSocket < 0) {
      std::cerr << "Socket creation failed: " << strerror(errno) << std::endl;
      continue;
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
      continue;
    }

    // Create SSL object
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, clientSocket);

    // Perform SSL handshake
    if (SSL_connect(ssl) <= 0) {
      ERR_print_errors_fp(stderr);
      SSL_free(ssl);
      close(clientSocket);
      continue;
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
        int ssl_err = SSL_get_error(ssl, bytesRead);
        switch (ssl_err) {
        case SSL_ERROR_ZERO_RETURN:
          std::cerr << "SSL connection closed by peer" << std::endl;
        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_WRITE:
          std::cerr << "SSL read/write operation did not complete, retrying"
                    << std::endl;
        case SSL_ERROR_SYSCALL:
          std::cerr << "SSL_read syscall error: " << strerror(errno)
                    << std::endl;
        case SSL_ERROR_SSL:
          std::cerr << "SSL protocol error" << std::endl;
          ERR_print_errors_fp(stderr);
        default:
          std::cerr << "SSL read error: " << ssl_err << std::endl;
        }
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
