#include "server.h"

#include "cache.h"
#include "db.h"
#include "protocol.h"

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

#define BUFFER_SIZE 512 // Standard max size for DNS UDP packets

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
        fprintf(stderr, "Bind failed. Note: Binding to Port 53 usually "
                        "requires Admin/Root privileges.\n");
        closesocket(sockfd);
        return;
    }

    cache_init();

    uint8_t buffer[BUFFER_SIZE];
    socklen_t len = sizeof(client_addr);

    while (1) {
        int n = recvfrom(sockfd, (char*)buffer, BUFFER_SIZE, 0,
                         (struct sockaddr*)&client_addr, &len);
        if (n < 0)
            continue;

        char domain[256];
        int query_end =
            protocol_parse_request(buffer, n, domain, sizeof(domain));

        if (query_end > 0) {
            IPv4Address ipv4;

            char outbuf[INET_ADDRSTRLEN];

            // 1. Try Memory Cache
            if (cache_get(domain, &ipv4)) {
                inet_ntop(AF_INET, ipv4.bytes, outbuf, sizeof(outbuf));
                printf("Query: %s -> %s (Cache Hit)\n", domain, outbuf);
            } else {
                // 2. Fallback to SQLite DB
                if (db_query(domain, &ipv4)) {
                    cache_set(domain, &ipv4);
                    inet_ntop(AF_INET, ipv4.bytes, outbuf, sizeof(outbuf));
                    printf("Query: %s -> %s (DB Hit)\n", domain, outbuf);
                } else {
                    // 3. Not found, trigger NXDOMAIN
                    printf("Query: %s -> NXDOMAIN\n", domain);
                }
            }

            size_t resp_len =
                protocol_build_response(buffer, query_end, &ipv4);
            sendto(sockfd, (const char*)buffer, (int)resp_len, 0,
                   (const struct sockaddr*)&client_addr, len);
        }
    }

    closesocket(sockfd);
#ifdef _WIN32
    WSACleanup();
#endif
}
