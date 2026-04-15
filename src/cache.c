#include "../include/cache.h"

#include <string.h>
#include <time.h>

#define CACHE_SIZE 1024
#define CACHE_TTL 60

typedef struct
{
    char domain[256];
    char ipv4[16];
    time_t timestamp;
    bool active;
} CacheEntry;

// Simple fixed-size hash table
static CacheEntry cache[CACHE_SIZE];

// djb2 hash function
static unsigned long hash_str(const char *str)
{
    unsigned long hash = 5381;
    int c;
    while ((c = *str++))
        hash = ((hash << 5) + hash) + c;
    return hash;
}

void cache_init(void)
{
    for (int i = 0; i < CACHE_SIZE; i++)
    {
        cache[i].active = false;
    }
}

bool cache_get(const char *domain, char *ipv4_out, int ipv4_max_len)
{
    unsigned long idx = hash_str(domain) % CACHE_SIZE;
    CacheEntry *entry = &cache[idx];

    if (entry->active && strcmp(entry->domain, domain) == 0)
    {
        if (time(nullptr) - entry->timestamp <= CACHE_TTL)
        {
#ifdef _WIN32
            strncpy_s(ipv4_out, ipv4_max_len, entry->ipv4, _TRUNCATE);
#else
            // POSIX standard fallback
            strncpy(ipv4_out, entry->ipv4, ipv4_max_len - 1);
            ipv4_out[ipv4_max_len - 1] = '\0';
#endif
            return true;
        }
        else
        {
            entry->active = false;
        }
    }
    return false;
}

void cache_set(const char *domain, const char *ipv4)
{
    const unsigned long idx = hash_str(domain) % CACHE_SIZE;
    CacheEntry *entry = &cache[idx];

#ifdef _WIN32
    errno_t err;

    err = strncpy_s(entry->domain, sizeof(entry->domain), domain, _TRUNCATE);
    if (err == EINVAL)
    {
        // Handle invalid arguments
    }
    else if (err == STRUNCATE)
    {
        // Handle truncation logging if needed
    }

    // Fixed missing function call here
    err = strncpy_s(entry->ipv4, sizeof(entry->ipv4), ipv4, _TRUNCATE);
    if (err == EINVAL)
    {
        // Handle invalid arguments
    }
    else if (err == STRUNCATE)
    {
        // Handle truncation logging if needed
    }
#else
    // POSIX standard fallback
    strncpy(entry->domain, domain, sizeof(entry->domain) - 1);
    entry->domain[sizeof(entry->domain) - 1] = '\0';

    strncpy(entry->ipv4, ipv4, sizeof(entry->ipv4) - 1);
    entry->ipv4[sizeof(entry->ipv4) - 1] = '\0';
#endif

    entry->timestamp = time(nullptr);
    entry->active = true;
}