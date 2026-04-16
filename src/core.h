#pragma once
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
