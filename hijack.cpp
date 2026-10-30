#define _GNU_SOURCE
#include <dlfcn.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>

#include <iostream>
#include <sstream>
#include <string>
#include <map>
#include <mutex>

#include <ndn-cxx/face.hpp>
#include <ndn-cxx/security/validator-config.hpp>

using connect_func = int (*)(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
using send_func = ssize_t (*)(int socket, const void *buffer, size_t length, int flags);
using close_func = int (*)(int fd);

static connect_func orig_connect = nullptr;
static send_func orig_send = nullptr;
static close_func orig_close = nullptr;


// Prevents intercepting ndn-cxx internal sockets to NFD
thread_local bool g_in_ndn = false;

struct NdnGuard {
    NdnGuard() { g_in_ndn = true; }
    ~NdnGuard() { g_in_ndn = false; }
};

struct HijackedSocket {
    int peer_fd;
    std::string ip;
    uint16_t port;
};

static std::map<int, HijackedSocket> g_hijacked_sockets;
static std::mutex g_sockets_mutex;

static void init_net_functions() {
    if (!orig_connect) orig_connect = (connect_func)dlsym(RTLD_NEXT, "connect");
    if (!orig_send) orig_send = (send_func)dlsym(RTLD_NEXT, "send");
    if (!orig_close) orig_close = (close_func)dlsym(RTLD_NEXT, "close");
}

static std::string fetch_ndn_data(const std::string& host, const std::string& path) {
    ndn::Name interest_name("/ndn-test/test");
    interest_name.append(host);

    std::stringstream ss(path);
    std::string segment;
    while (std::getline(ss, segment, '/')) {
        if (!segment.empty()) {
            interest_name.append(segment);
        }
    }

    std::string response;
    bool done = false;

    try {
        ndn::Face face;
        ndn::ValidatorConfig validator{face};
        bool validator_loaded = false;
        try {
            validator.load("../trust-schema.conf");
            validator_loaded = true;
        } catch (const std::exception& e) {
            std::cerr << "[NDN_HIJACK] Warning: Failed to load trust-schema.conf: " << e.what() << std::endl;
        }

        ndn::Interest interest(interest_name);
        interest.setCanBePrefix(true);
        interest.setMustBeFresh(true);
        interest.setInterestLifetime(ndn::time::seconds(10));

        std::cout << "[NDN_HIJACK] Expressing Interest: " << interest.getName().toUri() << std::endl;

        face.expressInterest(
            interest,
            [&](const ndn::Interest&, const ndn::Data& data) {
                if (validator_loaded) {
                    validator.validate(
                        data,
                        [&](const ndn::Data& valid_data) {
                            response.assign(reinterpret_cast<const char*>(valid_data.getContent().value()),
                                            valid_data.getContent().value_size());
                            done = true;
                        },
                        [&](const ndn::Data&, const ndn::security::ValidationError& error) {
                            std::cerr << "[NDN_HIJACK] Validation error: " << error << std::endl;
                            response = "HTTP/1.0 502 Bad Gateway\r\n\r\nNDN Data Validation Error\r\n";
                            done = true;
                        });
                } else {
                    response.assign(reinterpret_cast<const char*>(data.getContent().value()),
                                    data.getContent().value_size());
                    done = true;
                }
            },
            [&](const ndn::Interest&, const ndn::lp::Nack& nack) {
                std::cerr << "[NDN_HIJACK] Received Nack reason: " << nack.getReason() << std::endl;
                response = "HTTP/1.0 502 Bad Gateway\r\n\r\nNDN Nack Received\r\n";
                done = true;
            },
            [&](const ndn::Interest& timed_out_interest) {
                std::cerr << "[NDN_HIJACK] Interest timed out: " << timed_out_interest.getName().toUri() << std::endl;
                response = "HTTP/1.0 504 Gateway Timeout\r\n\r\nNDN Interest Timeout\r\n";
                done = true;
            });

        while (!done) {
            face.processEvents(ndn::time::milliseconds(100));
        }
    } catch (const std::exception& e) {
        std::cerr << "[NDN_HIJACK] Error: " << e.what() << std::endl;
        response = "HTTP/1.0 500 Internal Server Error\r\n\r\nNDN Error: " + std::string(e.what()) + "\r\n";
    }

    return response;
}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    init_net_functions();

    if (g_in_ndn || addr == nullptr || addr->sa_family != AF_INET) {
        return orig_connect(sockfd, addr, addrlen);
    }

    const struct sockaddr_in *in = (const struct sockaddr_in *)addr;
    uint16_t port = ntohs(in->sin_port);
    if (port == 6363) {
        return orig_connect(sockfd, addr, addrlen);
    }

    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(in->sin_addr), ip, sizeof(ip));

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
        return orig_connect(sockfd, addr, addrlen);
    }

    // Replace original TCP sockfd with sv[0]
    if (dup2(sv[0], sockfd) < 0) {
        close(sv[0]);
        close(sv[1]);
        return orig_connect(sockfd, addr, addrlen);
    }
    close(sv[0]);

    HijackedSocket info;
    info.peer_fd = sv[1];
    info.ip = ip;
    info.port = port;

    {
        std::lock_guard<std::mutex> lock(g_sockets_mutex);
        g_hijacked_sockets[sockfd] = info;
    }

    return 0;
}

ssize_t send(int sockfd, const void *buffer, size_t length, int flags) {
    init_net_functions();

    if (g_in_ndn) {
        return orig_send(sockfd, buffer, length, flags);
    }

    HijackedSocket info;
    bool is_hijacked = false;
    {
        std::lock_guard<std::mutex> lock(g_sockets_mutex);
        auto it = g_hijacked_sockets.find(sockfd);
        if (it != g_hijacked_sockets.end()) {
            info = it->second;
            g_hijacked_sockets.erase(it);
            is_hijacked = true;
        }
    }

    if (!is_hijacked) {
        return orig_send(sockfd, buffer, length, flags);
    }

    std::string req(static_cast<const char*>(buffer), length);
    std::string path = "/";
    std::string host;

    size_t first_space = req.find(' ');
    if (first_space != std::string::npos) {
        size_t second_space = req.find(' ', first_space + 1);
        if (second_space != std::string::npos) {
            path = req.substr(first_space + 1, second_space - first_space - 1);
        }
    }

    size_t host_pos = req.find("Host:");
    if (host_pos == std::string::npos) {
        host_pos = req.find("host:");
    }
    if (host_pos != std::string::npos) {
        size_t val_start = host_pos + 5;
        while (val_start < req.size() && (req[val_start] == ' ' || req[val_start] == '\t')) {
            val_start++;
        }
        size_t line_end = req.find_first_of("\r\n", val_start);
        host = (line_end != std::string::npos) ? req.substr(val_start, line_end - val_start)
                                               : req.substr(val_start);
        size_t colon = host.find(':');
        if (colon != std::string::npos) {
            host = host.substr(0, colon);
        }
    }

    if (host.empty()) {
        host = info.ip;
    }

    std::string response;
    {
        NdnGuard guard;
        response = fetch_ndn_data(host, path);
    }

    if (!response.empty()) {
        const char *data_ptr = response.data();
        size_t remaining = response.size();
        while (remaining > 0) {
            ssize_t written = write(info.peer_fd, data_ptr, remaining);
            if (written <= 0) break;
            data_ptr += written;
            remaining -= written;
        }
    }

    // Close peer_fd so caller's recv() hits EOF when buffer is drained
    close(info.peer_fd);

    return length;
}

int close(int fd) {
    init_net_functions();

    int peer_to_close = -1;
    {
        std::lock_guard<std::mutex> lock(g_sockets_mutex);
        auto it = g_hijacked_sockets.find(fd);
        if (it != g_hijacked_sockets.end()) {
            peer_to_close = it->second.peer_fd;
            g_hijacked_sockets.erase(it);
        }
    }

    if (peer_to_close != -1) {
        orig_close(peer_to_close);
    }

    return orig_close(fd);
}
