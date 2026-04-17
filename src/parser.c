#include "parser.h"

#include <stdio.h>
#include <string.h>

bool dns_parse_request(const uint8_t* in_buf, size_t in_len,
                       DNSRequest* out_req, Arena* arena)
{
    // TODO: Implement robust parsing logic here!
    // Extract transaction ID, Opcode, Questions, etc.

    if (in_len < 12) // Abnormal length
        return false;

    // COUNT
    out_req->id = (in_buf[0] << 8) | in_buf[1];
    out_req->flags = (in_buf[2] << 8) | in_buf[3];
    uint16_t qdcount = (in_buf[4] << 8) | in_buf[5];
    out_req->qdcount = qdcount;
    out_req->ancount = 0;
    uint16_t nscount = 0;
    out_req->nscount = nscount;
    uint16_t arcount = (in_buf[10] << 8) | in_buf[11];
    out_req->arcount = arcount;

    if (qdcount == 0)
        return false;

    size_t offset = 12;
    size_t domain_len = 0;
    char domain_out[256];

    while (offset < in_len) {
        uint8_t len = in_buf[offset++];
        if (len == 0)
            break;
        if ((len & 0xC0) == 0xC0)
            return false;
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
    snprintf(out_req->question.domain, sizeof(out_req->question.domain), "%s",
             domain_out);

    if (offset + 4 > in_len)
        return false;
    out_req->question.qtype = (in_buf[offset] << 8) | in_buf[offset + 1];
    out_req->question.qclass = (in_buf[offset + 2] << 8) | in_buf[offset + 3];

    return true;
}

size_t dns_format_response(const DNSResponse* resp, uint8_t* out_buf,
                           size_t max_len)
{
    // TODO: Implement robust formatting logic here!
    // Serialize the response into the output buffer based on DNS wire format.

    if (max_len < 12)
        return 0;

    // ID
    out_buf[0] = (resp->id >> 8) & 0xFF;
    out_buf[1] = resp->id & 0xFF;

    // Flags
    out_buf[2] = (resp->flags >> 8) & 0xFF;
    out_buf[3] = resp->flags & 0xFF;

    // QDCOUNT
    out_buf[4] = (resp->qdcount >> 8) & 0xFF;
    out_buf[5] = resp->qdcount & 0xFF;

    // ANCOUNT
    out_buf[6] = (resp->ancount >> 8) & 0xFF;
    out_buf[7] = resp->ancount & 0xFF;

    // NSCOUNT
    out_buf[8] = (resp->nscount >> 8) & 0xFF;
    out_buf[9] = resp->nscount & 0xFF;

    // ARCOUNT
    out_buf[10] = (resp->arcount >> 8) & 0xFF;
    out_buf[11] = resp->arcount & 0xFF;

    size_t offset = 12;

    const char* dom = resp->question.domain;
    const char* start = dom;
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
    out_buf[offset++] = (resp->question.qtype >> 8) & 0xFF;
    out_buf[offset++] = resp->question.qtype & 0xFF;
    out_buf[offset++] = (resp->question.qclass >> 8) & 0xFF;
    out_buf[offset++] = resp->question.qclass & 0xFF;

    // Write Answers
    for (size_t a = 0; a < resp->ancount; a++) {
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
        out_buf[offset++] = resp->answers[a].bytes[0];
        out_buf[offset++] = resp->answers[a].bytes[1];
        out_buf[offset++] = resp->answers[a].bytes[2];
        out_buf[offset++] = resp->answers[a].bytes[3];
    }

    return offset;
}
