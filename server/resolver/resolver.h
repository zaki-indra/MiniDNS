#pragma once

#include "../core/types.h"
#include "../memory.h"

int resolve_a_records(const char* domain, IPv4Address** ips_out,
                      size_t* count_out, Arena* arena);

int resolve_aaaa_records(const char* domain, IPv6Address** ips_out,
                         size_t* count_out, Arena* arena);