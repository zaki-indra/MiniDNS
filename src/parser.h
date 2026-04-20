#pragma once

#include "memory.h"
#include "types.h"

rc_t dns_parse_header(const uint8_t* in_buf, size_t in_len,
                      DnsMessage* out_dns);

// Parses the raw UDP packet into a structured DnsMessage.
// Returns false if the request is invalid or malformed.
rc_t dns_parse_body(const uint8_t* in_buf, size_t in_len, DnsMessage* out_dns,
                    Arena* arena);

// Formats a DnsMessage object into a raw binary buffer for transmission.
// Returns the size of the formatted packet, or 0 on failure.
size_t dns_format_response(const DnsMessage* dns, uint8_t* out_buf,
                           size_t max_len);
