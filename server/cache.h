#pragma once

#include "core/types.h"

void   cache_init(void);
size_t cache_get(const char* domain, IPv4Address* ipv4_out);
void   cache_set(const char* domain, const IPv4Address* ipv4, size_t count);
