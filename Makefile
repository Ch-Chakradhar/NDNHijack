HTTP_PREFIX := -DHTTP_PREFIX=\"http-test\"

test_wget: hijack.so
	LD_PRELOAD=./hijack.so wget http://httpforever.com/

hijack.so: hijack.cpp
	g++ -std=c++17 -Wall -shared -fPIC -o hijack.so hijack.cpp \
	 $(HTTP_PREFIX) \
    -I/usr/local/include -L/usr/local/lib \
    -DBOOST_STACKTRACE_DYN_LINK -DBOOST_LOG_DYN_LINK \
    -lndn-cxx -lboost_chrono -lboost_log -lboost_thread -lboost_stacktrace_backtrace \
    -lcrypto -lsqlite3 -latomic -lrt -lpthread -ldl

Test: Test.c
	gcc -o Test Test.c

Server/server: Server/server.cpp
	g++ -std=c++17 -Wall Server/server.cpp -I/usr/local/include \
	$(HTTP_PREFIX) \
	-DBOOST_STACKTRACE_DYN_LINK -DBOOST_LOG_DYN_LINK -L/usr/local/lib \
	-lndn-cxx -lboost_chrono -lboost_log -lboost_thread \
	-lboost_stacktrace_backtrace -lcrypto -lsqlite3 -latomic -lrt -lpthread -lcurl -o Server/server

.PHONY: test_wget
