#pragma once

#include "memory.h"
#include "types.h"

// Resolver module layer. Fetches records from Cache and fallback to DB.
// The list of IPs will be allocated inside the Arena.
bool resolve_a_records(const char* domain, IPv4Address** ips_out,
                       size_t* count_out, Arena* arena);

bool resolve_aaaa_records(const char* domain, IPv6Address** ips_out,
                          size_t* count_out, Arena* arena);