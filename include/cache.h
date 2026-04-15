#pragma once

#include <stdbool.h>

void cache_init(void);
bool cache_get(const char *domain, char *ipv4_out, int ipv4_max_len);
void cache_set(const char *domain, const char *ipv4);
