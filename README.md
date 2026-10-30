# NDN Hijack Library

Requires [ndn-cxx](https://github.com/named-data/ndn-cxx) libraries to be installed on the system.

Building - 
```bash
  g++ -std=c++17 -Wall -shared -fPIC -o hijack.so hijack.cpp \
    -I/usr/local/include -L/usr/local/lib \
    -DBOOST_STACKTRACE_DYN_LINK -DBOOST_LOG_DYN_LINK \
    -lndn-cxx -lboost_chrono -lboost_log -lboost_thread -lboost_stacktrace_backtrace \
    -lcrypto -lsqlite3 -latomic -lrt -lpthread -ldl
```
The provided Test.c is just a small simple http get request sender.

Usage - 

- NFD should be running in background.
- The route for the server needs to be setup in this case "/ndn-test/test/*" (* is the actual URL).
- The server should be accepting "/ndn-test/test/*"
- Also requires a trust-schema.conf (See ndn-cxx to know more) file to get the server's public key. (Currently hardcoded to "../../trust-schema.conf")
 
```bash
    LD_PRELOAD=./hijack.so ./test.out
```
