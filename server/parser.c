#include "parser.h"

#include <stdio.h>
#include <string.h>

#define MAX_QUESTIONS 10      // Prevent memory exhaustion / DoS
#define MAX_POINTER_JUMPS 100 // Prevent cyclic pointer infinite loops

// Helper function to safely parse a DNS domain name, including pointer
// compression
static parse_rc_t parse_qname(const uint8_t* in_buf, size_t in_len,
                              size_t* offset, char* out_name,
                              size_t max_name_len)
{
    size_t curr_offset = *offset;
    size_t name_len    = 0;
    int    jumped      = 0;
    int    jump_count  = 0;

    while (curr_offset < in_len) {
        if (jump_count > MAX_POINTER_JUMPS) {
            return PARSE_ERR_FORMERR; // Prevent infinite loops
        }

        uint8_t len = in_buf[curr_offset++];

        // 0-length octet marks the end of the domain name
        if (len == 0) {
            break;
        }

        // Check if top 2 bits are 11 (0xC0), indicating a pointer
        if ((len & 0xC0) == 0xC0) {
            if (curr_offset >= in_len) {
                return PARSE_ERR_UNEXPECTED_EOF;
            }
            uint8_t  next_byte  = in_buf[curr_offset++];
            uint16_t ptr_offset = ((len & 0x3F) << 8) | next_byte;

            // When a pointer is first encountered, the logical position in the
            // current record ends here (after the 2-byte pointer).
            if (!jumped) {
                *offset = curr_offset;
                jumped  = 1;
            }
            curr_offset = ptr_offset; // Jump to the pointer location
            jump_count++;
            continue;
        }

        // Standard label (max length is 63 per RFC 1035)
        if (len > 63 || curr_offset + len > in_len) {
            return PARSE_ERR_FORMERR;
        }

        // Append a dot if this isn't the first label
        if (name_len > 0 && name_len < max_name_len - 1) {
            out_name[name_len++] = '.';
        }

        // Copy the label characters
        for (int i = 0; i < len; i++) {
            if (name_len < max_name_len - 1) {
                out_name[name_len++] = in_buf[curr_offset++];
            } else {
                curr_offset++; // Truncate cleanly but continue reading to
                               // validate format
            }
        }
    }

    out_name[name_len] = '\0';

    // If we never jumped, update the outer offset to where we finished
    if (!jumped) {
        *offset = curr_offset;
    }

    return PARSE_OK;
}

// Helper function to parse a standard Resource Record into DnsResourceRecord
// struct
static parse_rc_t parse_rr(const uint8_t* in_buf, size_t in_len, size_t* offset,
                           DnsResourceRecord* out_rr)
{
    parse_rc_t rc =
        parse_qname(in_buf, in_len, offset, out_rr->name, sizeof(out_rr->name));
    if (rc != PARSE_OK)
        return rc;

    if (*offset + 10 > in_len)
        return PARSE_ERR_UNEXPECTED_EOF;

    out_rr->type  = (in_buf[*offset] << 8) | in_buf[*offset + 1];
    out_rr->class = (in_buf[*offset + 2] << 8) | in_buf[*offset + 3];
    out_rr->ttl   = (in_buf[*offset + 4] << 24) | (in_buf[*offset + 5] << 16) |
                    (in_buf[*offset + 6] << 8) | in_buf[*offset + 7];
    out_rr->rdlength = (in_buf[*offset + 8] << 8) | in_buf[*offset + 9];

    *offset += 10;

    if (*offset + out_rr->rdlength > in_len)
        return PARSE_ERR_UNEXPECTED_EOF;

    // Defend against arbitrary payload size crashing the fixed-size 256 array
    if (out_rr->rdlength > sizeof(out_rr->rdata)) {
        return PARSE_ERR_FORMERR;
    }

    if (out_rr->rdlength > 0) {
        memcpy(out_rr->rdata, in_buf + *offset, out_rr->rdlength);
        *offset += out_rr->rdlength;
    }

    return PARSE_OK;
}

// Helper to format a label-sequence domain name to the wire
static size_t format_name(const char* name, uint8_t* out_buf, size_t offset,
                          size_t max_len)
{
    // Root domain (empty string)
    if (name == NULL || name[0] == '\0') {
        if (offset < max_len)
            out_buf[offset++] = 0x00;
        return offset;
    }

    const char* start = name;
    const char* dot   = strchr(start, '.');

    while (dot != NULL) {
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

    return offset;
}

parse_rc_t dns_parse_header(const uint8_t* in_buf, size_t in_len,
                            DnsMessage* out_dns)
{
    if (in_len < 12) {
        return PARSE_ERR_UNEXPECTED_EOF;
    }

    out_dns->id      = (in_buf[0] << 8) | in_buf[1];
    out_dns->flags   = (in_buf[2] << 8) | in_buf[3];
    out_dns->qdcount = (in_buf[4] << 8) | in_buf[5];
    out_dns->ancount = (in_buf[6] << 8) | in_buf[7];
    out_dns->nscount = (in_buf[8] << 8) | in_buf[9];
    out_dns->arcount = (in_buf[10] << 8) | in_buf[11];

    return PARSE_OK;
}

parse_rc_t dns_parse_body(const uint8_t* in_buf, size_t in_len,
                          DnsMessage* out_dns, Arena* arena)
{
    size_t offset = 12;

    // DOS Protection: Limit max questions to prevent arena exhaustion
    if (out_dns->qdcount > MAX_QUESTIONS) {
        return PARSE_ERR_FORMERR;
    }

    if (out_dns->qdcount > 0) {
        out_dns->questions = (DnsQuestion*)arena_alloc(
            arena, out_dns->qdcount * sizeof(DnsQuestion));
    } else {
        out_dns->questions = NULL;
    }

    // Parse question records
    for (size_t q = 0; q < out_dns->qdcount; q++) {
        parse_rc_t rc =
            parse_qname(in_buf, in_len, &offset, out_dns->questions[q].qname,
                        sizeof(out_dns->questions[q].qname));
        if (rc != PARSE_OK)
            return rc;

        if (offset + 4 > in_len)
            return PARSE_ERR_UNEXPECTED_EOF;

        uint16_t qtype  = (in_buf[offset] << 8) | in_buf[offset + 1];
        uint16_t qclass = (in_buf[offset + 2] << 8) | in_buf[offset + 3];

        qtype_t  qtype_e  = get_qtype(qtype);
        qclass_t qclass_e = get_qclass(qclass);

        // Explicitly block ANY queries to prevent amplification attacks
        if (qtype_e == QTYPE_ANY || qclass_e == QCLASS_ANY) {
            return PARSE_ERR_NOTIMP;
        }

        out_dns->questions[q].qtype  = qtype;
        out_dns->questions[q].qclass = qclass;

        offset += 4;
    }

    // Skip over Answers and Authorities securely so we can reach the Additional
    // section
    size_t skip_count = out_dns->ancount + out_dns->nscount;
    for (size_t i = 0; i < skip_count; i++) {
        char       dummy_name[256];
        parse_rc_t rc = parse_qname(in_buf, in_len, &offset, dummy_name,
                                    sizeof(dummy_name));
        if (rc != PARSE_OK)
            return rc;

        if (offset + 10 > in_len)
            return PARSE_ERR_UNEXPECTED_EOF;

        uint16_t rdlength = (in_buf[offset + 8] << 8) | in_buf[offset + 9];
        offset += 10 + rdlength;

        if (offset > in_len)
            return PARSE_ERR_UNEXPECTED_EOF;
    }

    // Parse Additional records (e.g., EDNS0 OPT) into structured RRs
    out_dns->authorities = NULL; // We skipped them, so leave them NULL

    if (out_dns->arcount > 0) {
        out_dns->additional = (DnsResourceRecord*)arena_alloc(
            arena, out_dns->arcount * sizeof(DnsResourceRecord));
        for (size_t i = 0; i < out_dns->arcount; i++) {
            parse_rc_t rc =
                parse_rr(in_buf, in_len, &offset, &out_dns->additional[i]);
            if (rc != PARSE_OK)
                return rc;
        }
    } else {
        out_dns->additional = NULL;
    }

    // Clear the old raw memory fields just in case anything else checks them
    out_dns->additional_data = NULL;
    out_dns->additional_len  = 0;

    return PARSE_OK;
}

size_t dns_format_response(const DnsMessage* dns, uint8_t* out_buf,
                           size_t max_len)
{
    if (max_len < 12)
        return 0;

    // Header
    out_buf[0]  = (dns->id >> 8) & 0xFF;
    out_buf[1]  = dns->id & 0xFF;
    out_buf[2]  = (dns->flags >> 8) & 0xFF;
    out_buf[3]  = dns->flags & 0xFF;
    out_buf[4]  = (dns->qdcount >> 8) & 0xFF;
    out_buf[5]  = dns->qdcount & 0xFF;
    out_buf[6]  = (dns->ancount >> 8) & 0xFF;
    out_buf[7]  = dns->ancount & 0xFF;
    out_buf[8]  = (dns->nscount >> 8) & 0xFF;
    out_buf[9]  = dns->nscount & 0xFF;
    out_buf[10] = (dns->arcount >> 8) & 0xFF;
    out_buf[11] = dns->arcount & 0xFF;

    size_t offset = 12;

    // Encode Question Section
    if (dns->qdcount > 0 && dns->questions != NULL) {
        offset = format_name(dns->questions[0].qname, out_buf, offset, max_len);

        if (offset + 4 > max_len)
            return 0;
        out_buf[offset++] = (dns->questions[0].qtype >> 8) & 0xFF;
        out_buf[offset++] = dns->questions[0].qtype & 0xFF;
        out_buf[offset++] = (dns->questions[0].qclass >> 8) & 0xFF;
        out_buf[offset++] = dns->questions[0].qclass & 0xFF;
    }

    // Write Answers
    for (size_t a = 0; a < dns->ancount; a++) {
        if (offset + 16 > max_len)
            return 0;

        if (dns->qdcount == 1) {
            out_buf[offset++] = 0xC0;
            out_buf[offset++] = 0x0C;
        } else {
            out_buf[offset++] = 0x00;
        }

        // Type A (1), Class IN (1)
        out_buf[offset++] = 0x00;
        out_buf[offset++] = 0x01;
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

        // RDATA (IPv4 Address)
        out_buf[offset++] = dns->answers[a].octets[0];
        out_buf[offset++] = dns->answers[a].octets[1];
        out_buf[offset++] = dns->answers[a].octets[2];
        out_buf[offset++] = dns->answers[a].octets[3];
    }

    // Write Additional Records
    if (dns->arcount > 0 && dns->additional != NULL) {
        for (size_t i = 0; i < dns->arcount; i++) {
            const DnsResourceRecord* rr = &dns->additional[i];

            offset = format_name(rr->name, out_buf, offset, max_len);

            if (offset + 10 > max_len)
                return 0;

            out_buf[offset++] = (rr->type >> 8) & 0xFF;
            out_buf[offset++] = rr->type & 0xFF;

            out_buf[offset++] = (rr->class >> 8) & 0xFF;
            out_buf[offset++] = rr->class & 0xFF;

            out_buf[offset++] = (rr->ttl >> 24) & 0xFF;
            out_buf[offset++] = (rr->ttl >> 16) & 0xFF;
            out_buf[offset++] = (rr->ttl >> 8) & 0xFF;
            out_buf[offset++] = rr->ttl & 0xFF;

            out_buf[offset++] = (rr->rdlength >> 8) & 0xFF;
            out_buf[offset++] = rr->rdlength & 0xFF;

            if (rr->rdlength > 0) {
                if (offset + rr->rdlength > max_len)
                    return 0;
                memcpy(out_buf + offset, rr->rdata, rr->rdlength);
                offset += rr->rdlength;
            }
        }
    }

    return offset;
}