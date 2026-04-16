#pragma once

#include "types.h"

void cache_init(void);
bool cache_get(const char* domain, IPv4Address* ipv4_out);
void cache_set(const char* domain, const IPv4Address* ipv4);
