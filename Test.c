#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#define BUFFER_SIZE 4096

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <hostname> <path>\n", argv[0]);
        fprintf(stderr, "Example: %s example.com /\n", argv[0]);
        return 1;
    }

    char *host = argv[1];
    char *path = argv[2];
    int sock_fd;
    struct addrinfo hints, *res;
    char request[BUFFER_SIZE];
    char buffer[BUFFER_SIZE];
    ssize_t n_bytes;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;       // IPv4
    hints.ai_socktype = SOCK_STREAM; // TCP

    if (getaddrinfo(host, "80", &hints, &res) != 0) {
        perror("DNS resolution failed");
        return 1;
    }

    sock_fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sock_fd < 0) {
        perror("Socket creation failed");
        freeaddrinfo(res);
        return 1;
    }

    if (connect(sock_fd, res->ai_addr, res->ai_addrlen) < 0) {
        perror("Connection failed");
        close(sock_fd);
        freeaddrinfo(res);
        return 1;
    }
    freeaddrinfo(res); 

    snprintf(request, sizeof(request),
             "GET %s HTTP/1.0\r\n"
             "Host: %s\r\n"
             "User-Agent: CCLient/1.0\r\n"
             "\r\n", path, host);

    if (send(sock_fd, request, strlen(request), 0) < 0) {
        perror("Failed to send request");
        close(sock_fd);
        return 1;
    }

    while ((n_bytes = recv(sock_fd, buffer, sizeof(buffer) - 1, 0)) > 0) {
        buffer[n_bytes] = '\0';
        printf("%s", buffer);
    }

    if (n_bytes < 0) {
        perror("Error receiving data");
    }

    close(sock_fd);
    return 0;
}