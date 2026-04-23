#pragma once

#include "core/types.h"
#include "memory.h"

typedef enum {
    OK          = 0,
    ERR_NO_ECHO = 1,
    ERR_ECHO    = 2,
} rc_t;

rc_t dns_parse_header(const uint8_t* in_buf, size_t in_len,
                      DnsMessage* out_dns);

rc_t dns_parse_header_2(const uint8_t* in_buf, size_t in_len,
                        DnsMessage* out_dns);

rc_t dns_validate_header(const DnsMessage* dns);

rc_t dns_parse_body(const uint8_t* in_buf, size_t in_len, DnsMessage* out_dns,
                    Arena* arena);

rc_t dns_parse_request(const uint8_t* in_buf, size_t in_len,
                       DnsMessage* out_dns, Arena* arena);

rc_t dns_validate_request(const DnsMessage* dns);

// Formats a DnsMessage object into a raw binary buffer for transmission.
// Returns the size of the formatted packet, or 0 on failure.
size_t dns_format_response(const DnsMessage* dns, uint8_t* out_buf,
                           size_t max_len);