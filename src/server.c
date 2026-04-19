#include "server.h"

#include "cache.h"
#include "dispatcher.h"
#include "memory.h"
#include "parser.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
typedef int socklen_t;
#else
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#define closesocket close
#endif

#define DNS_HEADER_SIZE 12
#define BUFFER_SIZE 512
#define ARENA_SIZE 4096

void server_start(int port)
{
#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        fprintf(stderr, "WSAStartup failed.\n");
        return;
    }
    SOCKET sockfd;
#else
    int sockfd;
#endif

    struct sockaddr_in server_addr, client_addr;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        fprintf(stderr, "Socket creation failed.\n");
        return;
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);

    if (bind(sockfd, (const struct sockaddr*)&server_addr,
             sizeof(server_addr)) < 0) {
        fprintf(stderr,
                "Bind failed. Note: Binding to Port %d usually "
                "requires Admin/Root privileges.\n",
                port);
        closesocket(sockfd);
        return;
    }

    cache_init();

    uint8_t buffer[BUFFER_SIZE];
    uint8_t arena_buffer[ARENA_SIZE];
    Arena arena;
    arena_init(&arena, arena_buffer, ARENA_SIZE);

    socklen_t len = sizeof(client_addr);

    printf("Server listening on port %d...\n", port);

    while (1) {
        int n = recvfrom(sockfd, (char*)buffer, BUFFER_SIZE, 0,
                         (struct sockaddr*)&client_addr, &len);
        if (n < 0)
            continue;

        // Automatically clean up memory from previous request
        arena_reset(&arena);

        DNS dns;
        rc_t rc;
        rc = dns_parse_header(buffer, n, &dns);
        switch (rc) {
        case OK:
            if (dns_parse_body(buffer, n, &dns, &arena) == OK) {
                dispatcher_handle(&dns, &arena);

                size_t out_len = dns_format_response(&dns, buffer, BUFFER_SIZE);
                if (out_len > 0) {
                    sendto(sockfd, (const char*)buffer, (int)out_len, 0,
                           (const struct sockaddr*)&client_addr, len);
                }
            }
            break;

        case OK_RECURSE:
            // Not implemented yet.
            break;

        case ERR_NO_ECHO:
            break;

        case ERR_ECHO:
            dns_format_response(&dns, buffer, DNS_HEADER_SIZE);
            sendto(sockfd, (const char*)buffer, (int)n, 0,
                   (const struct sockaddr*)&client_addr, DNS_HEADER_SIZE);
            break;
        }
    }

    closesocket(sockfd);
#ifdef _WIN32
    WSACleanup();
#endif
}
