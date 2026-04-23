#pragma once

#include <stddef.h>
#include <stdint.h>

typedef union IPv4Address {
    uint8_t  octets[4];
    uint16_t hwords[2];
    uint32_t words;
} IPv4Address;

typedef union IPv6Address {
    uint8_t  octets[16];
    uint16_t hwords[8];
    uint32_t words[4];
    uint64_t dwords[2];
} IPv6Address;

typedef enum {
    QR_REQUEST  = 0,
    QR_RESPONSE = 1,
} qr_t;

typedef enum {
    OPCODE_QUERY   = 0,
    OPCODE_IQUERY  = 1,
    OPCODE_STATUS  = 2,
    OPCODE_NOTIFY  = 4,
    OPCODE_UPDATE  = 5,
    OPCODE_DSO     = 6,
    OPCODE_UNKNOWN = 7,
} opcode_t;

typedef enum {
    AA_NO  = 0,
    AA_YES = 1,
} aa_t;

typedef enum {
    TC_NO  = 0,
    TC_YES = 1,
} tc_t;

typedef enum {
    RD_NO  = 0,
    RD_YES = 1,
} rd_t;

typedef enum {
    RA_NO  = 0,
    RA_YES = 1,
} ra_t;

typedef enum {
    RCODE_NOERROR  = 0,
    RCODE_FORMERR  = 1,
    RCODE_SERVFAIL = 2,
    RCODE_NXDOMAIN = 3,
    RCODE_NOTIMP   = 4,
    RCODE_REFUSED  = 5,
    RCODE_YXDOMAIN = 6,
    RCODE_YXRRSET  = 7,
    RCODE_NXRRSET  = 8,
    RCODE_NOTAUTH  = 9,
    RCODE_NOTZONE  = 10,
} rcode_t;

typedef enum {
    QTYPE_A   = 1,
    QTYPE_ANY = 65536,
} qtype_t;

typedef enum {
    QCLASS_IN  = 1,
    QCLASS_ANY = 65536,
} qclass_t;

typedef struct {
    char     qname[256];
    uint16_t qtype;
    uint16_t qclass;
} DnsQuestion;

typedef struct {
    char     name[256];
    uint16_t type;
    uint16_t class;
    uint32_t ttl;
    uint16_t rdlength;
    uint8_t  rdata[256];
} DnsResourceRecord;

typedef struct {
    // Header
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;

    DnsQuestion* questions;

    IPv4Address* answers;

    DnsResourceRecord* authorities;
    DnsResourceRecord* additional;

    size_t   additional_len;
    uint8_t* additional_data;
} DnsMessage;

qr_t     flags_get_qr(uint16_t flags);
opcode_t flags_get_opcode(uint16_t flags);
aa_t     flags_get_aa(uint16_t flags);
tc_t     flags_get_tc(uint16_t flags);
rd_t     flags_get_rd(uint16_t flags);
ra_t     flags_get_ra(uint16_t flags);
rcode_t  flags_get_rcode(uint16_t flags);

void flags_set_qr(uint16_t* flags, qr_t qr);
void flags_set_opcode(uint16_t* flags, opcode_t opcode);
void flags_set_aa(uint16_t* flags, aa_t aa);
void flags_set_tc(uint16_t* flags, tc_t tc);
void flags_set_rd(uint16_t* flags, rd_t rd);
void flags_set_ra(uint16_t* flags, ra_t ra);
void flags_set_z(uint16_t* flags);
void flags_set_rcode(uint16_t* flags, rcode_t rcode);

qtype_t  get_qtype(uint16_t qtype);
qclass_t get_qclass(uint16_t qclass);