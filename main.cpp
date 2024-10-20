#include "reverseproxy.h"
#include "sslSetup.h"

int main(int argc, char *argv[]) {
  initSSL();
  SSL_CTX *ctx = createContext();
  configureContext(ctx);

  ReverseProxy mainServer;
  mainServer.port = 8815;
  mainServer.targetPort = 8813;
  mainServer.initProxy();

  SSL_CTX_free(ctx);
  EVP_cleanup();
  return 0;
}
