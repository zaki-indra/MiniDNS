#include "resolver.h"

#include "cache.h"
#include "db.h"

#include <stdio.h>
#include <string.h>

int resolve_a_records(const char* domain, IPv4Address** ips_out,
                      size_t* count_out, Arena* arena)
{
    if (!domain || !ips_out || !count_out || !arena) {
        perror("Invalid arguments");
        return -1;
    }

    IPv4Address cache_buf[64];
    size_t      cached = cache_get(domain, cache_buf);
    if (cached > 0) {
        IPv4Address* ip =
            (IPv4Address*)arena_alloc(arena, sizeof(IPv4Address) * cached);
        if (!ip) {
            perror("arena_alloc");
            return -1;
        }
        memcpy(ip, cache_buf, sizeof(IPv4Address) * cached);
        *ips_out   = ip;
        *count_out = cached;
        printf("Query: %s (Cache Hit, %zu IPs)\n", domain, cached);
        return (int)cached;
    }

    // Fallback to DB
    int n = db_query(domain, ips_out, arena);
    if (n > 0) {
        cache_set(domain, *ips_out, (size_t)n);
        *count_out = (size_t)n;
        printf("Query: %s (DB Hit, %d IPs)\n", domain, n);
        return n;
    }

    printf("Query: %s -> NXDOMAIN\n", domain);
    *count_out = 0;
    *ips_out   = nullptr;
    return 0;
}
