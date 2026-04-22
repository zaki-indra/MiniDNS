#include "parser.h"

#include <stdio.h>
#include <string.h>

rc_t dns_parse_header(const uint8_t* in_buf, size_t in_len, DnsMessage* out_dns)
{
    // 1. Buffer bounds check
    if (in_len < 12) {
        return ERR_NO_ECHO;
    }

    // 2. Parse directly into the struct to DRY up the code
    out_dns->id      = (in_buf[0] << 8) | in_buf[1];
    out_dns->flags   = (in_buf[2] << 8) | in_buf[3];
    out_dns->qdcount = (in_buf[4] << 8) | in_buf[5];
    out_dns->ancount = (in_buf[6] << 8) | in_buf[7];
    out_dns->nscount = (in_buf[8] << 8) | in_buf[9];
    out_dns->arcount = (in_buf[10] << 8) | in_buf[11];

    // 3. Drop responses immediately (we are a server handling queries)
    if (flags_get_qr(out_dns->flags) == QR_RESPONSE) {
        return ERR_NO_ECHO;
    }

    uint16_t opcode = flags_get_opcode(out_dns->flags);

    // 4. Handle completely unknown opcodes
    if (opcode == OPCODE_UNKNOWN) {
        flags_set_qr(&out_dns->flags, QR_RESPONSE);
        flags_set_rcode(&out_dns->flags, RCODE_NOTIMP);
        return ERR_ECHO;
    }

    // 5. Handle known, but non-standard queries
    if (opcode != OPCODE_QUERY) {
        // return OK_RECURSE; // NO recursive ability for now
    }

    // 6. Handle Standard Queries
    if (opcode == OPCODE_QUERY && out_dns->qdcount == 1) {
        flags_set_qr(&out_dns->flags, QR_RESPONSE);
        flags_set_ra(&out_dns->flags, RA_NO);
        flags_set_z(&out_dns->flags);
        return OK;
    }

    // 7. Format Error Fallback (qdcount is 0 or > 1)
    flags_set_qr(&out_dns->flags, QR_RESPONSE);
    flags_set_opcode(&out_dns->flags, OPCODE_QUERY);
    flags_set_tc(&out_dns->flags, TC_NO);
    flags_set_ra(&out_dns->flags, RA_NO);
    flags_set_z(&out_dns->flags);
    flags_set_rcode(&out_dns->flags, RCODE_FORMERR);

    // Safely strip payload counts so the error echo is just the header
    out_dns->qdcount = 0;
    out_dns->ancount = 0;
    out_dns->nscount = 0;
    out_dns->arcount = 0;

    return ERR_ECHO;
}

rc_t dns_parse_body(const uint8_t* in_buf, size_t in_len, DnsMessage* out_dns,
                    Arena* arena)
{
    // TODO: Implement robust parsing logic here!
    // Extract transaction ID, Opcode, Questions, etc.

    size_t offset = 12;

    out_dns->questions = (DnsQuestion*)arena_alloc(
        arena, out_dns->qdcount * sizeof(DnsQuestion));

    // Parse question records
    size_t domain_len;
    for (size_t q = 0; q < out_dns->qdcount; q++) {
        domain_len = 0;
        char domain_out[256];
        while (offset < in_len) {
            uint8_t len = in_buf[offset++];
            if (len == 0) {
                goto outer;
            }
            if (offset + len > in_len) {
                flags_set_rcode(&out_dns->flags, RCODE_FORMERR);
                return ERR_ECHO;
            }

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
    outer:
        domain_out[domain_len] = '\0';
        snprintf(out_dns->questions[q].qname,
                 sizeof(out_dns->questions[q].qname), "%s", domain_out);

        if (offset + 4 > in_len)
            return ERR_NO_ECHO;
        uint16_t qtype  = (in_buf[offset] << 8) | in_buf[offset + 1];
        uint16_t qclass = (in_buf[offset + 2] << 8) | in_buf[offset + 3];

        qtype_t  qtype_e  = get_qtype(qtype);
        qclass_t qclass_e = get_qclass(qclass);

        if (qtype_e == QTYPE_ANY || qclass_e == QCLASS_ANY) {
            flags_set_rcode(&out_dns->flags, RCODE_NOTIMP);
            return ERR_ECHO;
        }

        out_dns->questions[q].qtype  = qtype;
        out_dns->questions[q].qclass = qclass;

        offset += 4;
    }

    // Parse additional records
    out_dns->authorities = nullptr;

    uint16_t arcount   = out_dns->arcount;
    size_t   remaining = in_len - offset;
    if (remaining <= 0) {
        return OK;
    }
    out_dns->additional_data =
        (uint8_t*)arena_alloc(arena, remaining * sizeof(uint8_t));
    memcpy(out_dns->additional_data, in_buf + offset, remaining);
    out_dns->additional_len = remaining;
    return OK;
}

size_t dns_format_response(const DnsMessage* dns, uint8_t* out_buf,
                           size_t max_len)
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

    const char* name  = dns->questions[0].qname;
    const char* start = name;
    const char* dot   = strchr(start, '.');
    while (dot != nullptr) {
        size_t len = dot - start;
        if (offset < max_len)
            out_buf[offset++] = (uint8_t)len;
        for (size_t i = 0; i < len; i++) {
            if (offset < max_len)
                out_buf[offset++] = start[i];
        }
        start = dot + 1;
        dot   = strchr(start, '.');
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
    out_buf[offset++] = (dns->questions[0].qtype >> 8) & 0xFF;
    out_buf[offset++] = dns->questions[0].qtype & 0xFF;
    out_buf[offset++] = (dns->questions[0].qclass >> 8) & 0xFF;
    out_buf[offset++] = dns->questions[0].qclass & 0xFF;

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

    memcpy(out_buf + offset, dns->additional_data,
           dns->additional_len * sizeof(uint8_t));
    offset += dns->additional_len;

    return offset;
}
