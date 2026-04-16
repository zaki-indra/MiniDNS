#pragma once

#include "types.h"
#include "memory.h"
#include <stdbool.h>

// Parses the raw UDP packet into a structured DNSRequest.
// Returns false if the request is invalid or malformed.
bool dns_parse_request(const uint8_t* in_buf, size_t in_len, DNSRequest* out_req, Arena* arena);

// Formats a DNSResponse object into a raw binary buffer for transmission.
// Returns the size of the formatted packet, or 0 on failure.
size_t dns_format_response(const DNSResponse* resp, uint8_t* out_buf, size_t max_len);
