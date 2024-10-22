#include "sslsetup.h"

void initSSL() {
  SSL_load_error_strings();
  OpenSSL_add_ssl_algorithms();
}

SSL_CTX* createContext() {
  const SSL_METHOD *method = SSLv23_server_method();
  SSL_CTX *ctx = SSL_CTX_new(method);
  if (!ctx) {
    perror("Unable to create SSL context");
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
  }
  return ctx;
}

void configureContext (SSL_CTX *ctx) {
  SSL_CTX_set_ecdh_auto(ctx, 1);
  if (SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM) <= 0) {
      ERR_print_errors_fp(stderr);
      exit(EXIT_FAILURE);
  }
  if (SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM) <= 0 ) {
      ERR_print_errors_fp(stderr);
      exit(EXIT_FAILURE);
  }
}

SSL_CTX* createClientContext() {
    const SSL_METHOD* method = SSLv23_client_method(); // Use client-specific method
    SSL_CTX* ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL client context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
}
