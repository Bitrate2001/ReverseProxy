#ifndef REVERSEPROXY_H
#define REVERSEPROXY_H


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
  void clientHandler(int clientSocket);
};

#endif // !REVERSEPROXY_H
