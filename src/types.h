#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef union IPv4Address {
    uint8_t bytes[4];
    uint16_t hwords[2];
    uint32_t words;
} IPv4Address;

typedef union IPv6Address {
    uint8_t bytes[16];
    uint16_t hwords[8];
    uint32_t words[4];
    uint64_t dwords[2];
} IPv6Address;

typedef struct {
    char domain[256];
    uint16_t qtype;
    uint16_t qclass;
} DNSQuestion;

typedef struct {
    uint16_t id;
    bool is_response;
    uint16_t op_code;
    // ... basic flags ...

    DNSQuestion question;
    int q_count;
} DNSRequest;

typedef struct {
    uint16_t id;
    uint8_t rcode;

    DNSQuestion question;

    IPv4Address* answers;
    size_t answer_count;
} DNSResponse;
