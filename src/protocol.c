#include "protocol.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef _WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif

#include "core.h"

int protocol_parse_request(const uint8_t *buffer, size_t size, char *domain_out, size_t domain_max_len) {
    if (size < 12) return -1; // Too small to be a DNS header
    
    // Ensure it's a standard query (Opcode 0) and not a response
    if ((buffer[2] & 0x80) != 0) return -1; // QR bit set (is a response)
    
    uint16_t qdcount = (buffer[4] << 8) | buffer[5];
    if (qdcount == 0) return -1; // No questions
    
    size_t offset = 12; // Start of Question section
    size_t domain_len = 0;
    
    // Parse QNAME (Domain name)
    while (offset < size) {
        uint8_t len = buffer[offset++];
        if (len == 0) break; // End of QNAME
        
        // Pointers (compression) are invalid in the Question section
        if ((len & 0xC0) == 0xC0) return -1; 
        
        if (offset + len > size) return -1; // Bounds check
        
        if (domain_len > 0 && domain_len < domain_max_len - 1) {
            domain_out[domain_len++] = '.';
        }
        
        for (int i = 0; i < len; i++) {
            if (domain_len < domain_max_len - 1) {
                domain_out[domain_len++] = buffer[offset++];
            } else {
                offset++; // Skip if domain_out buffer is too small
            }
        }
    }
    domain_out[domain_len] = '\0';
    
    if (offset + 4 > size) return -1; // Missing QTYPE and QCLASS
    
    uint16_t qtype = (buffer[offset] << 8) | buffer[offset + 1];
    if (qtype != 1) return -1; // Only support Type A (IPv4)
    
    offset += 4; // Skip QTYPE and QCLASS
    return (int)offset;
}

size_t protocol_build_response(uint8_t *buffer, size_t query_end_offset, const IPv4Address *ipv4) {
    // Modify Header Flags
    buffer[2] = (buffer[2] & 0x7F) | 0x80; // Set QR (Response)
    
    if (ipv4 == NULL) {
        // NXDOMAIN: Non-Existent Domain
        buffer[3] = (buffer[3] & 0x80) | 0x03; // RCODE 3

        // Set ARCOUNT (Additional records count) to 0
        buffer[10] = 0x00;
        buffer[11] = 0x00;
        return query_end_offset; // Return packet with header + question only
    }
    
    // Found: Set NOERROR
    buffer[3] = (buffer[3] & 0xF0) | 0x00; // RCODE 0
    
    // Set ANCOUNT (Answer count) to 1
    buffer[6] = 0x00;
    buffer[7] = 0x01;

    // Set ARCOUNT (Additional records count) to 0
    buffer[10] = 0x00;
    buffer[11] = 0x00;

    size_t offset = query_end_offset;
    
    // --- Answer Section ---
    // Name (Pointer back to Question QNAME at offset 12)
    buffer[offset++] = 0xC0;
    buffer[offset++] = 0x0C;
    
    // Type A (1)
    buffer[offset++] = 0x00;
    buffer[offset++] = 0x01;
    
    // Class IN (1)
    buffer[offset++] = 0x00;
    buffer[offset++] = 0x01;
    
    // TTL (e.g., 60 seconds)
    buffer[offset++] = 0x00;
    buffer[offset++] = 0x00;
    buffer[offset++] = 0x00;
    buffer[offset++] = 0x3C;
    
    // RDLENGTH (4 bytes for IPv4)
    buffer[offset++] = 0x00;
    buffer[offset++] = 0x04;
    
    // RDATA (IPv4 Address)
    memcpy(&buffer[offset], (void *)ipv4, 4);
    offset += 4;
    
    return offset;
}