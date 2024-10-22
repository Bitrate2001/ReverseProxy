#include "reverseproxy.h"

int main(int argc, char *argv[]) {

  ReverseProxy mainServer;
  mainServer.port = 8815;
  mainServer.targetPort = 8813;
  mainServer.initProxy();

  return 0;
}
