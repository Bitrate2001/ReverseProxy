#ifndef REVERSEPROXY_H
#define REVERSEPROXY_H

#include <openssl/ssl.h>

class ReverseProxy {
public:
  ReverseProxy();
  ReverseProxy(ReverseProxy &&) = default;
  ReverseProxy(const ReverseProxy &) = default;
  ReverseProxy &operator=(ReverseProxy &&) = default;
  ReverseProxy &operator=(const ReverseProxy &) = default;
  ~ReverseProxy();

  int port;
  int targetPort;

  void initProxy();

private:
  SSL_CTX* ctx;
  void clientHandler(SSL* clientSSL);
};

#endif // !REVERSEPROXY_H
