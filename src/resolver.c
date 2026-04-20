#include "resolver.h"

#include "cache.h"
#include "db.h"

#include <stdio.h>

bool resolve_a_records(const char* domain, IPv4Address** ips_out,
                       size_t* count_out, Arena* arena)
{
    if (!domain || !ips_out || !count_out || !arena) {
        return false;
    }

    // Allocate memory for at least 1 IP for now.
    // Once DB supports multiple IPs, this might vary.
    IPv4Address* ip = (IPv4Address*)arena_alloc(arena, sizeof(IPv4Address));
    if (!ip)
        return false;

    if (cache_get(domain, ip)) {
        *ips_out   = ip;
        *count_out = 1;
        printf("Query: %s (Cache Hit)\n", domain);
        return true;
    }

    if (db_query(domain, ip)) {
        cache_set(domain, ip);
        *ips_out   = ip;
        *count_out = 1;
        printf("Query: %s (DB Hit)\n", domain);
        return true;
    }

    printf("Query: %s -> NXDOMAIN\n", domain);
    *count_out = 0;
    *ips_out   = NULL;
    return false;
}
