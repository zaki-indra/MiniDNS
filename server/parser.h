#pragma once

#include "core/types.h"
#include "memory.h"

typedef enum {
    PARSE_OK                 = 0,
    PARSE_ERR_UNEXPECTED_EOF = 1,
    PARSE_ERR_FORMERR        = 2,
    PARSE_ERR_NOTIMP         = 3,
} parse_rc_t;

parse_rc_t dns_parse_header(const uint8_t* in_buf, size_t in_len,
                            DnsMessage* out_dns);

parse_rc_t dns_parse_body(const uint8_t* in_buf, size_t in_len,
                          DnsMessage* out_dns, Arena* arena);

// Formats a DnsMessage object into a raw binary buffer for transmission.
// Returns the size of the formatted packet, or 0 on failure.
size_t dns_format_response(const DnsMessage* dns, uint8_t* out_buf,
                           size_t max_len);