#include "parser.h"

#include <stdio.h>
#include <string.h>

bool dns_parse_request(const uint8_t* in_buf, size_t in_len, DNS* out_dns,
                       Arena* arena)
{
    // TODO: Implement robust parsing logic here!
    // Extract transaction ID, Opcode, Questions, etc.

    if (in_len < 12) // Abnormal length
        return false;

    // Header
    out_dns->id = (in_buf[0] << 8) | in_buf[1];
    out_dns->flags = (in_buf[2] << 8) | in_buf[3];
    out_dns->qdcount = (in_buf[4] << 8) | in_buf[5];
    out_dns->ancount = (in_buf[6] << 8) | in_buf[7];
    out_dns->nscount = (in_buf[8] << 8) | in_buf[9];
    out_dns->arcount = (in_buf[10] << 8) | in_buf[11];

    if (out_dns->qdcount == 0)
        return false;

    size_t offset = 12;
    size_t domain_len = 0;
    char domain_out[256];

    while (offset < in_len) {
        uint8_t len = in_buf[offset++];
        if (len == 0)
            break;
        if (offset + len > in_len)
            return false;

        if (domain_len > 0 && domain_len < sizeof(domain_out) - 1) {
            domain_out[domain_len++] = '.';
        }
        for (int i = 0; i < len; i++) {
            if (domain_len < sizeof(domain_out) - 1) {
                domain_out[domain_len++] = in_buf[offset++];
            } else {
                offset++;
            }
        }
    }
    domain_out[domain_len] = '\0';
    snprintf(out_dns->question.qname, sizeof(out_dns->question.qname), "%s",
             domain_out);

    if (offset + 4 > in_len)
        return false;
    out_dns->question.qtype = (in_buf[offset] << 8) | in_buf[offset + 1];
    out_dns->question.qclass = (in_buf[offset + 2] << 8) | in_buf[offset + 3];

    return true;
}

size_t dns_format_response(const DNS* dns, uint8_t* out_buf, size_t max_len)
{
    // TODO: Implement robust formatting logic here!
    // Serialize the response into the output buffer based on DNS wire format.

    if (max_len < 12)
        return 0;

    // ID
    out_buf[0] = (dns->id >> 8) & 0xFF;
    out_buf[1] = dns->id & 0xFF;

    // Flags
    out_buf[2] = (dns->flags >> 8) & 0xFF;
    out_buf[3] = dns->flags & 0xFF;

    // QDCOUNT
    out_buf[4] = (dns->qdcount >> 8) & 0xFF;
    out_buf[5] = dns->qdcount & 0xFF;

    // ANCOUNT
    out_buf[6] = (dns->ancount >> 8) & 0xFF;
    out_buf[7] = dns->ancount & 0xFF;

    // NSCOUNT
    out_buf[8] = (dns->nscount >> 8) & 0xFF;
    out_buf[9] = dns->nscount & 0xFF;

    // ARCOUNT
    out_buf[10] = (dns->arcount >> 8) & 0xFF;
    out_buf[11] = dns->arcount & 0xFF;

    size_t offset = 12;

    const char* name = dns->question.qname;
    const char* start = name;
    const char* dot = strchr(start, '.');
    while (dot != NULL) {
        size_t len = dot - start;
        if (offset < max_len)
            out_buf[offset++] = (uint8_t)len;
        for (size_t i = 0; i < len; i++) {
            if (offset < max_len)
                out_buf[offset++] = start[i];
        }
        start = dot + 1;
        dot = strchr(start, '.');
    }
    size_t last_len = strlen(start);
    if (last_len > 0) {
        if (offset < max_len)
            out_buf[offset++] = (uint8_t)last_len;
        for (size_t i = 0; i < last_len; i++) {
            if (offset < max_len)
                out_buf[offset++] = start[i];
        }
    }
    if (offset < max_len)
        out_buf[offset++] = 0x00;

    if (offset + 4 > max_len)
        return 0;
    out_buf[offset++] = (dns->question.qtype >> 8) & 0xFF;
    out_buf[offset++] = dns->question.qtype & 0xFF;
    out_buf[offset++] = (dns->question.qclass >> 8) & 0xFF;
    out_buf[offset++] = dns->question.qclass & 0xFF;

    // Write Answers
    for (size_t a = 0; a < dns->ancount; a++) {
        if (offset + 16 > max_len)
            return 0;

        // Name pointer compression
        out_buf[offset++] = 0xC0;
        out_buf[offset++] = 0x0C; // Pointer to byte 12

        // Type A (1)
        out_buf[offset++] = 0x00;
        out_buf[offset++] = 0x01;

        // Class IN (1)
        out_buf[offset++] = 0x00;
        out_buf[offset++] = 0x01;

        // TTL (60s)
        out_buf[offset++] = 0x00;
        out_buf[offset++] = 0x00;
        out_buf[offset++] = 0x00;
        out_buf[offset++] = 0x3C;

        // RDLENGTH = 4
        out_buf[offset++] = 0x00;
        out_buf[offset++] = 0x04;

        // RDATA
        out_buf[offset++] = dns->answers[a].octets[0];
        out_buf[offset++] = dns->answers[a].octets[1];
        out_buf[offset++] = dns->answers[a].octets[2];
        out_buf[offset++] = dns->answers[a].octets[3];
    }

    return offset;
}
