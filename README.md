# MiniDNS

A minimal, performant authoritative DNS server written in C, backed by SQLite.

MiniDNS is a learning project for exploring low-level C programming, UDP networking, and the DNS wire protocol. It is designed to be simple to understand, modular, and correct — not a production-grade replacement for BIND or Unbound.

---

## Features

- **Authoritative DNS server** — answers `A` record queries from a local SQLite database
- **In-memory cache** — hash-table-based TTL cache (60 s) sits in front of the database, providing fast cache-hit responses with zero allocations
- **Multi-threaded worker pool** — a fixed-size pool of 64 worker threads processes packets fully off the I/O path
- **Bounded packet queue** — a lock-protected SPMC ring buffer (128 slots) provides backpressure between the I/O thread and workers; no heap allocation per packet
- **Arena allocator** — each worker owns a stack-allocated 4 KB arena that is reset every request, eliminating per-request `malloc`/`free` calls
- **CLI management** — `init`, `add`, `list`, `delete`, and `clear` sub-commands for managing DNS records
- **Cross-platform** — builds on both Linux/macOS (BSD sockets) and Windows (Winsock2)
- **C23** — written to the C23 standard; uses `nullptr`, typed enums, and `<threads.h>`

---

## Requirements

| Dependency | Notes |
|---|---|
| C compiler | GCC ≥ 13, Clang ≥ 17, or MSVC (latest) with `/std:clatest` |
| CMake | ≥ 4.0 |
| POSIX Threads / Windows threads | provided by the platform |
| SQLite3 | vendored in `third_party/sqlite3` — no system install needed |

---

## Building

```sh
# Configure (Debug build with warnings)
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug

# Build
cmake --build build

# (Optional) Install to system
cmake --install build
```

The resulting binary is `build/minidns` (Linux/macOS) or `build/Debug/minidns.exe` (Windows).

---

## Usage

### Initialize the database

Must be run once before any other command.

```sh
./minidns init
# Database initialized successfully at 'minidns.db'.
```

### Start the server

```sh
./minidns serve <port>
# Starting MiniDNS server on port 5353...
```

> **Note:** Ports below 1024 require elevated privileges on Linux/macOS.

### Manage DNS records

```sh
# Add / update an A record
./minidns add example.local 192.168.1.10

# List all records
./minidns list

# Delete a record
./minidns delete example.local

# Remove all records
./minidns clear
```

### Query the server (example with `dig`)

```sh
dig @127.0.0.1 -p 5353 example.local A
```

---

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│                      server_start()                      │
│  ┌─────────────────┐      ┌──────────────────────────┐  │
│  │   I/O Thread    │      │    Worker Pool (×64)     │  │
│  │                 │      │  ┌────────────────────┐  │  │
│  │  recvfrom()     │─────▶│  │  process_packet()  │  │  │
│  │  queue_push()   │      │  │   dns_parse_*()    │  │  │
│  │                 │      │  │   dispatcher_*()   │  │  │
│  └─────────────────┘      │  │   sendto()         │  │  │
│                           │  └────────────────────┘  │  │
│         PacketQueue       └──────────────────────────┘  │
│         (ring buffer, 128 slots, ~50 KB BSS)            │
└──────────────────────────────────────────────────────────┘
```

### Request lifecycle

1. The **I/O thread** receives a UDP datagram via `recvfrom` and copies it into the next free `PacketQueue` slot.
2. A **worker thread** pops the packet from the queue and processes it entirely on its own stack — no shared mutable state after the pop.
3. `dns_parse_header` and `dns_parse_body` deserialise the wire-format packet into a `DnsMessage` struct, allocating question/answer buffers from the worker's per-request **arena**.
4. The **dispatcher** inspects the opcode and routes to the appropriate handler. Unknown or unimplemented opcodes return `RCODE_NOTIMP`.
5. For `OPCODE_QUERY` + `QTYPE_A`, the **A-record handler** calls `resolve_a_records()` via the `ServerContext` function pointer (dependency injection — the handler never touches the cache or DB directly).
6. The **resolver** checks the **in-memory cache** first, then falls back to the **SQLite DB**. Cache hits are written back so subsequent queries skip the DB.
7. `dns_format_response` serialises the `DnsMessage` back into the same packet buffer in-place.
8. The worker calls `sendto` to return the response to the client.

---

## Module Reference

```
server/
├── main.c              CLI entry point — argument parsing, sub-command dispatch
├── server.c            UDP socket setup, worker pool lifecycle, I/O loop
├── dispatcher.c        Opcode routing and error normalisation
├── parser.c            DNS wire-format parser and response formatter
├── resolver/
│   └── resolver.c      Cache-then-DB lookup, returns IPv4Address[]
├── handler/
│   ├── opcode_query.c  OPCODE_QUERY dispatcher (routes by QTYPE)
│   └── qtype_a.c       QTYPE_A handler — calls ctx->resolve_a_records()
├── cache.c             Hash-table TTL cache (1 024 slots, 60 s TTL)
├── db.c                SQLite3 wrapper (init, add, list, delete, clear, query)
├── queue.c             Bounded SPMC ring buffer with mutex + condition variables
├── memory.c            Arena / bump allocator
├── debug.c             DNS message pretty-printer (debug builds)
└── core/
    └── types.h/.c      Shared types: DnsMessage, enums, flag accessors, ServerContext
```

### Key types

| Type | Location | Description |
|---|---|---|
| `DnsMessage` | `core/types.h` | Parsed DNS message (header + questions + answers) |
| `DnsQuestion` | `core/types.h` | A single question section entry (`qname`, `qtype`, `qclass`) |
| `DnsResourceRecord` | `core/types.h` | Generic resource record (used for authority/additional) |
| `IPv4Address` | `core/types.h` | Union of `octets[4]` / `uint32_t` for zero-copy byte access |
| `ServerContext` | `core/types.h` | Dependency-injection struct; holds `resolve_a_records` fn pointer |
| `PacketQueue` | `queue.h` | Bounded ring buffer; embeds `Packet slots[128]` in BSS |
| `Packet` | `queue.h` | A UDP datagram + sender address, max 512 bytes |
| `Arena` | `memory.h` | Bump allocator over a caller-supplied buffer |
| `parse_rc_t` | `parser.h` | Parser return codes: `PARSE_OK`, `PARSE_ERR_*` |
| `server_action_t` | `core/types.h` | Worker action after processing: `ACTION_SEND_REPLY`, `ACTION_DROP`, `ACTION_ERROR` |

### DNS flag helpers (`core/types.h`)

```c
qr_t     flags_get_qr(uint16_t flags);
opcode_t flags_get_opcode(uint16_t flags);
rcode_t  flags_get_rcode(uint16_t flags);
// ... plus flags_set_* variants for building responses
```

---

## Configuration constants

These are compile-time constants defined in `queue.h`:

| Constant | Default | Description |
|---|---|---|
| `QUEUE_CAPACITY` | `128` | Number of slots in the packet ring buffer |
| `WORKER_COUNT` | `64` | Number of worker threads spawned at startup |
| `MAX_PACKET_SIZE` | `512` | Maximum UDP datagram size (bytes) |

And in `cache.c`:

| Constant | Default | Description |
|---|---|---|
| `CACHE_SIZE` | `1024` | Number of cache slots (hash table size) |
| `CACHE_TTL` | `60` | Cache entry TTL in seconds |
| `CACHE_MAX_IPS` | `64` | Maximum IPs stored per domain in cache |

---

## Database schema

MiniDNS uses a single SQLite table:

```sql
CREATE TABLE IF NOT EXISTS records (
    domain TEXT,
    ipv4   INTEGER   -- IPv4 address stored as a 32-bit integer (network byte order)
);
```

WAL mode is enabled automatically for concurrent read access from the worker pool during `serve`.

---

## Limitations

- **A records only** — `AAAA`, `MX`, `CNAME`, and other record types return `RCODE_NOTIMP`.
- **No recursion** — MiniDNS is purely authoritative; it will not forward unknown queries upstream.
- **No EDNS0** — extended DNS options are not parsed or generated.
- **No TCP fallback** — responses larger than 512 bytes are not supported.
- **Cache is not thread-safe for writes** — concurrent `cache_set` from multiple workers on the same domain is possible; this is acceptable for a learning project but not production-safe.
- **Hash collisions** — the cache uses open addressing without chaining; a collision evicts the existing entry.

---

## Project structure

```
minidns/
├── CMakeLists.txt
├── LICENSE
├── README.md
├── server/
│   ├── main.c
│   ├── server.c / server.h
│   ├── dispatcher.c / dispatcher.h
│   ├── parser.c / parser.h
│   ├── cache.c / cache.h
│   ├── db.c / db.h
│   ├── queue.c / queue.h
│   ├── memory.c / memory.h
│   ├── debug.c / debug.h
│   ├── core/
│   │   ├── types.c
│   │   └── types.h
│   ├── handler/
│   │   ├── handler.h
│   │   ├── opcode_query.c / opcode_query.h
│   │   └── qtype_a.c / qtype_a.h
│   └── resolver/
│       ├── resolver.c
│       └── resolver.h
└── third_party/
    └── sqlite3/          (vendored, single-file amalgamation)
```

---

## License

MIT — see [LICENSE](LICENSE).

Copyright © 2026 Zaki Indra Yudhistira