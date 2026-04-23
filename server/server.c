#include "server.h"

#include "cache.h"
#include "debug.h"
#include "dispatcher.h"
#include "memory.h"
#include "parser.h"
#include "queue.h"
#include "resolver/resolver.h"

#include <stdalign.h>
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

#define ALIGNMENT 64
#define DNS_HEADER_SIZE 12
#define BUFFER_SIZE MAX_PACKET_SIZE
#define ARENA_SIZE 4096

static PacketQueue queue;

/* -------------------------------------------------------------------------
 * Processing hook
 * Operates on the worker's private stack copy: no shared state.
 * Modify pkt->data and pkt->len in-place to form the response.
 * ---------------------------------------------------------------------- */
static server_action_t process_packet(struct ServerContext* ctx, Packet* pkt, Arena* arena)
{
    DnsMessage dns;
    parse_rc_t rc;

    rc = dns_parse_header(pkt->data, pkt->len, &dns);
    if (rc != PARSE_OK) {
        if (rc == PARSE_ERR_UNEXPECTED_EOF) return ACTION_DROP;
        server_action_t err_act = dispatcher_handle_error(&dns, rc);
        pkt->len = dns_format_response(&dns, pkt->data, BUFFER_SIZE);
        return err_act;
    }

    rc = dns_parse_body(pkt->data, pkt->len, &dns, arena);
    if (rc != PARSE_OK) {
        if (rc == PARSE_ERR_UNEXPECTED_EOF) return ACTION_DROP;
        server_action_t err_act = dispatcher_handle_error(&dns, rc);
        pkt->len = dns_format_response(&dns, pkt->data, BUFFER_SIZE);
        return err_act;
    }
    print_dns(&dns);

    server_action_t act = dispatcher_handle(ctx, &dns, arena);
    if (act == ACTION_SEND_REPLY) {
        pkt->len = dns_format_response(&dns, pkt->data, BUFFER_SIZE);
    }
    return act;
}

/* -------------------------------------------------------------------------
 * Worker thread
 *
 * Each worker owns a Packet on its own stack. It loops:
 *   1. Block on queue_pop until an item is available.
 *   2. process_packet — fully unlocked, no shared mutable state.
 *   3. sendto — thread-safe on a shared UDP fd for datagrams.
 *   4. Repeat until queue_pop returns false (shutdown + empty).
 * ---------------------------------------------------------------------- */
static int worker_fn(void* arg)
{
    WorkerCtx* ctx = arg;

    /*
     * arena and local are reused every iteration — no per-request allocation.
     */
    alignas(ALIGNMENT) uint8_t processing_buffer[ARENA_SIZE];
    Arena                      arena;
    arena_init(&arena, processing_buffer, ARENA_SIZE);
    Packet local;

    while (queue_pop(ctx->queue, &local)) {
        server_action_t act = process_packet(ctx->sctx, &local, &arena);

        switch (act) {
        case ACTION_SEND_REPLY: {
            long sent = sendto(ctx->sockfd, (char*)local.data, local.len, 0,
                               (const struct sockaddr*)&local.client_addr, local.addr_len);
            if (sent < 0) {
                perror("sendto");
            }
            break;
        }
        case ACTION_DROP:
        case ACTION_ERROR:
        default:
            break;
        }
        arena_reset(&arena);
    }

    return 0;
}

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

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return;
    }

    struct sockaddr_in server_addr = {
        .sin_family      = AF_INET,
        .sin_addr.s_addr = INADDR_ANY,
        .sin_port        = htons((uint16_t)port),
    };

    if (bind(sockfd, (const struct sockaddr*)&server_addr,
             sizeof(server_addr)) < 0) {
        perror("bind");
        closesocket(sockfd);
        return;
    }

    if (queue_init(&queue) != 0) {
        fprintf(stderr, "queue_init failed\n");
        closesocket(sockfd);
        return;
    }

    cache_init();

    ServerContext app_ctx = {
        .resolve_a_records = resolve_a_records,
    };

    thrd_t    workers[WORKER_COUNT];
    WorkerCtx ctxs[WORKER_COUNT];

    for (int i = 0; i < WORKER_COUNT; i++) {
        ctxs[i] = (WorkerCtx){
            .queue     = &queue,
            .sockfd    = sockfd,
            .worker_id = i,
            .sctx      = &app_ctx,
        };
        if (thrd_create(&workers[i], worker_fn, &ctxs[i]) != thrd_success) {
            fprintf(stderr, "thrd_create failed for worker %d\n", i);
            /*
             * Partial startup: shut down the queue so already-running
             * workers drain and exit, then wait for them before we
             * unwind the stack (ctxs[] must outlive all threads).
             */
            queue_shutdown(&queue);
            for (int j = 0; j < i; j++) {
                thrd_join(workers[j], nullptr);
            }
            queue_destroy(&queue);
            closesocket(sockfd);
            return;
        }
    }

    Packet pkt;

    while (1) {
        pkt.addr_len = sizeof(pkt.client_addr);

        int n = recvfrom(sockfd, (char*)pkt.data, BUFFER_SIZE, 0,
                         (struct sockaddr*)&pkt.client_addr, &pkt.addr_len);
        if (n < 0) {
            perror("recvfrom");
            break;
        }

        pkt.len = (size_t)n;

        /*
         * queue_push blocks here if the queue is full — this is the
         * backpressure point. The kernel's socket receive buffer
         * absorbs incoming datagrams while we wait, up to its limit.
         * Packets beyond that are silently dropped by the kernel,
         * which is correct behaviour for a bounded-resource UDP server.
         */
        if (!queue_push(&queue, &pkt)) {
            break; /* shutdown was requested */
        }
    }

    /* ----- Graceful shutdown --------------------------------------- */

    /*
     * Signal all workers. They will drain any remaining items in the
     * queue before exiting — no in-flight work is lost.
     */
    queue_shutdown(&queue);

    for (int i = 0; i < WORKER_COUNT; i++) {
        thrd_join(workers[i], nullptr);
    }

    queue_destroy(&queue);

    closesocket(sockfd);
#ifdef _WIN32
    WSACleanup();
#endif
}