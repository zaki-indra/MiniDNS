#pragma once

#include "core.h"

#include <stddef.h>
#include <stdint.h>

// Parse the DNS request. Extracts the domain.
// Returns the offset to the end of the query block, or -1 on error.
int protocol_parse_request(const uint8_t* buffer, size_t size, char* domain_out,
                           size_t domain_max_len);

// Build the DNS response for an A record.
// ipv4_str: The IPv4 address string. If NULL, generates NXDOMAIN.
// Returns the total size of the response packet.
size_t protocol_build_response(uint8_t* buffer, size_t query_end_offset,
                               const IPv4Address* ipv4);
