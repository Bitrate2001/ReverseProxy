#include <arpa/inet.h>
#include <cstring>
#include <iostream>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <unistd.h>

void initializeSSL() {
  SSL_load_error_strings();
  OpenSSL_add_ssl_algorithms();
}

SSL_CTX *createContext() {
  const SSL_METHOD *method = SSLv23_server_method();
  SSL_CTX *ctx = SSL_CTX_new(method);
  if (!ctx) {
    perror("Unable to create SSL context");
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
  }
  return ctx;
}

void configureContext(SSL_CTX *ctx) {
  SSL_CTX_set_ecdh_auto(ctx, 1);
  if (SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM) <= 0) {
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
  }
  if (SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM) <= 0) {
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
  }
}

void handleClient(SSL *ssl) {
  char buffer[4096];
  int bytesRead = SSL_read(ssl, buffer, sizeof(buffer) - 1);
  if (bytesRead > 0) {
    buffer[bytesRead] = '\0';
    std::cout << "Received request:\n" << buffer << std::endl;
    const char *response = "HTTP/1.1 200 OK\r\n"
                           "Content-Type: text/plain\r\n"
                           "Content-Length: 13\r\n"
                           "Connection: close\r\n"
                           "\r\n";
    SSL_write(ssl, response, strlen(response));
  } else {
    std::cout << "Bytesread error";
  }
  SSL_shutdown(ssl);
  SSL_free(ssl);
}

int main() {
  initializeSSL();
  SSL_CTX *ctx = createContext();
  configureContext(ctx);

  int serverSocket = socket(AF_INET, SOCK_STREAM, 0);
  if (serverSocket < 0) {
    std::cerr << "Socket creation failed: " << strerror(errno) << std::endl;
    return 1;
  }

  sockaddr_in serverAddr;
  memset(&serverAddr, 0, sizeof(serverAddr));
  serverAddr.sin_family = AF_INET;
  serverAddr.sin_addr.s_addr = INADDR_ANY;
  serverAddr.sin_port = htons(8813);
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
      continue;
    }

    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, clientSocket);
    if (SSL_accept(ssl) <= 0) {
      std::cerr << "Oh ohh, SSL not accepted" << std::endl;
      ERR_print_errors_fp(stderr);
    } else {
      handleClient(ssl);
    }
    close(clientSocket);
  }

  close(serverSocket);
  SSL_CTX_free(ctx);
  EVP_cleanup();

  return 0;
}
