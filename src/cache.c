#include "cache.h"

#include "types.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

#define CACHE_SIZE 1024
#define CACHE_TTL 60

typedef struct {
    char domain[256];
    IPv4Address ipv4;
    time_t timestamp;
    bool active;
} CacheEntry;

// Simple fixed-size hash table
static CacheEntry cache[CACHE_SIZE];

// djb2 hash function
static unsigned long hash_str(const char* str)
{
    unsigned long hash = 5381;
    int c;
    while ((c = *str++))
        hash = ((hash << 5) + hash) + c;
    return hash;
}

void cache_init(void)
{
    for (int i = 0; i < CACHE_SIZE; i++) {
        cache[i].active = false;
    }
}

bool cache_get(const char* domain, IPv4Address* ipv4_out)
{
    unsigned long idx = hash_str(domain) % CACHE_SIZE;
    CacheEntry* entry = &cache[idx];

    if (entry->active && strcmp(entry->domain, domain) == 0) {
        if (time(nullptr) - entry->timestamp <= CACHE_TTL) {
            *ipv4_out = entry->ipv4;
            return true;
        } else {
            entry->active = false;
        }
    }
    return false;
}

void cache_set(const char* domain, const IPv4Address* ipv4)
{
    const unsigned long idx = hash_str(domain) % CACHE_SIZE;
    CacheEntry* entry = &cache[idx];

    snprintf(entry->domain, sizeof(entry->domain), "%s", domain);

    entry->ipv4 = *ipv4;

    entry->timestamp = time(nullptr);
    entry->active = true;
}