#include "cache.h"

#include "types.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

#define CACHE_SIZE 1024
#define CACHE_TTL 60
#define CACHE_MAX_IPS 64

typedef struct {
    char        domain[256];
    IPv4Address ipv4[CACHE_MAX_IPS];
    size_t      ips;
    time_t      timestamp;
    bool        active;
} CacheEntry;

static CacheEntry cache[CACHE_SIZE];

static unsigned long hash_str(const char* str)
{
    unsigned long hash = 5381;
    int           c;
    while ((c = *str++))
        hash = ((hash << 5) + hash) + c;
    return hash;
}

void cache_init(void)
{
    for (int i = 0; i < CACHE_SIZE; i++)
        cache[i].active = false;
}

// Returns number of IPs written into ipv4_out, or 0 on miss/expiry.
// ipv4_out must point to a buffer of at least CACHE_MAX_IPS entries.
size_t cache_get(const char* domain, IPv4Address* ipv4_out)
{
    unsigned long idx   = hash_str(domain) % CACHE_SIZE;
    CacheEntry*   entry = &cache[idx];

    if (!entry->active || strcmp(entry->domain, domain) != 0)
        return 0;

    if (time(nullptr) - entry->timestamp > CACHE_TTL) {
        entry->active = false;
        return 0;
    }

    memcpy(ipv4_out, entry->ipv4, sizeof(IPv4Address) * entry->ips);
    return entry->ips;
}

void cache_set(const char* domain, const IPv4Address* ipv4, size_t count)
{
    unsigned long idx   = hash_str(domain) % CACHE_SIZE;
    CacheEntry*   entry = &cache[idx];

    size_t clamped = count < CACHE_MAX_IPS ? count : CACHE_MAX_IPS;

    snprintf(entry->domain, sizeof(entry->domain), "%s", domain);
    memcpy(entry->ipv4, ipv4, sizeof(IPv4Address) * clamped);
    entry->ips       = clamped;
    entry->timestamp = time(nullptr);
    entry->active    = true;
}