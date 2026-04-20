/**
 * "queue.h"
 *
 * This file contains the signature of queue module.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <threads.h>

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

#define QUEUE_CAPACITY 128
#define WORKER_COUNT 64
#define MAX_PACKET_SIZE 512

/*
 * Packet — a single UDP datagram plus the sender's address.
 *
 * This struct is the element type of the ring buffer arena.
 * It lives entirely inside PacketQueue.slots[], so no heap
 * allocation is ever needed per-packet.
 */
typedef struct {
    uint8_t data[MAX_PACKET_SIZE];
    size_t len;
    struct sockaddr_in client_addr;
    socklen_t addr_len;
} Packet;

/*
 * PacketQueue — bounded SPMC ring buffer.
 *
 * The arena is the flat slots[] array embedded directly in this
 * struct. Place this in static or global storage (BSS) at startup
 * so the ~51 KB arena never touches the heap.
 *
 * Invariants:
 *   head  — next write position (producer owns this)
 *   tail  — next read  position (consumer claims under mutex)
 *   count — number of items currently in the queue
 *
 * Both head and tail advance modulo QUEUE_CAPACITY, forming a ring.
 */
typedef struct {
    Packet slots[QUEUE_CAPACITY]; /* the arena: 128 × 400 B ≈ 50 KB */
    size_t head;
    size_t tail;
    size_t count;
    bool shutdown;
    mtx_t mutex;
    cnd_t not_empty; /* workers wait here when queue is empty */
    cnd_t not_full;  /* producer waits here when queue is full */
} PacketQueue;

/*
 * Context passed to each worker thread at creation.
 * Lives on the stack of server_start() for the full server lifetime.
 */
typedef struct {
    PacketQueue* queue;
    int sockfd;
    int worker_id;
} WorkerCtx;

/* Lifecycle */
int queue_init(PacketQueue* q);
void queue_destroy(PacketQueue* q);
void queue_shutdown(PacketQueue* q);

/*
 * queue_push — copy pkt into the next free arena slot.
 *
 * Blocks if the queue is full (backpressure). Returns false only
 * if shutdown was requested while the producer was waiting.
 */
bool queue_push(PacketQueue* q, const Packet* pkt);

/*
 * queue_pop — copy the next item out of the arena into *out.
 *
 * The copy happens while the mutex is held, but it is a fixed-size
 * memcpy of at most MAX_PACKET_SIZE bytes — the lock is released
 * immediately after, so workers do all heavy processing unlocked.
 *
 * Returns false only when shutdown is set AND the queue is empty.
 */
bool queue_pop(PacketQueue* q, Packet* out);