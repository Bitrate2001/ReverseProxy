#ifndef SSLSETUP_H
#define SSLSETUP_H

#include <openssl/ssl.h>
#include <openssl/err.h>

void initSSL();
SSL_CTX* createContext();
void configureContext(SSL_CTX *ctx);

SSL_CTX* createClientContext();

#endif // !sslSetup
