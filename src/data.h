#pragma once

#include "types.h"
#include "memory.h"
#include <stdbool.h>

// Data access layer. Fetches records from Cache and fallback to DB.
// The list of IPs will be allocated inside the Arena.
bool data_query_a_records(const char* domain, IPv4Address** ips_out, size_t* count_out, Arena* arena);
