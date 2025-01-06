# Compilation commands

For reverse proxy server
```` console
g++ main.cpp reverseproxy.cpp sslSetup.cpp -o reverseproxy.app -lssl -lcrypto
````

## Test files

For client
```` console
g++ testclient.cpp -o testclient.app -lssl -lcrypto
````

For server
```` console
g++ testserver.cpp -o testserver.app -lssl -lcrypto
````

## Todo

<ol>
  <li>Add a backend server vector of str "ip"</li>
  <li>Add a load balancer</li>
  <li>Use Round-robin scheduling algo</li>
</ol>
