# NDN Hijack Library

Requires [ndn-cxx](https://github.com/named-data/ndn-cxx) libraries to be installed on the system.

## Building - 
```bash
  g++ -std=c++17 -Wall -shared -fPIC -o hijack.so hijack.cpp \
    -I/usr/local/include -L/usr/local/lib \
    -DBOOST_STACKTRACE_DYN_LINK -DBOOST_LOG_DYN_LINK \
    -lndn-cxx -lboost_chrono -lboost_log -lboost_thread -lboost_stacktrace_backtrace \
    -lcrypto -lsqlite3 -latomic -lrt -lpthread -ldl
```
The provided Test.c is just a small simple http get request sender.

## Usage - 

- NFD should be running in background.
- The route for the server needs to be setup in this case "/ndn-test/test/\*" (\* is the actual URL).
- The server should be accepting "/ndn-test/test/*"
- Also requires a trust-schema.conf (See ndn-cxx to know more) file to get the server's public key. (Currently hardcoded to "../../trust-schema.conf")
 
```bash
    LD_PRELOAD=./hijack.so wget http://httpforever.com/
```

## Working -

The hijack.cpp file currently hijacks 4 POSIX system calls 
- getaddrinfo
- connect
- send / write
- close

### getaddrinfo
1. It checks if node is a valid string, then if it is valid then a unique IP address is assigned to this node and any request to this IP will use this as host.
2. And a dummy addrinfo with ip is sent back to the application.

### Connect
1. Checks if this is a hijacked IP address and then intercepts it.
2. Creates a POSIX socketpair and then using the `dup2` libcall, the original sockfd is replaced by this socketpair's read fd.
3. Saves the write fd to write `send` calls response into it. (This is the reason we didn't had to override recv call)

### Send / Write
1. Performs the previous checks, and also if this socket is present in the hijacked socket then intercepts it.
2. Then stiches the host and the path and then sends the request via the NDN interest sending interface.
3. The response is then written into the POSIX socketpair's write end and it is closed after the request is written and returns 

### Close
It is hijacked only for the cleanup of the hijacked sockets and then the original close is called
