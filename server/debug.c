#include "debug.h"

#include <stdio.h>
#include <string.h>

void print_dns(const DnsMessage* dns)
{
#ifdef DEBUG
    printf("DNS message:\n");
    printf("  ID: %hu\n", dns->id);
    char flags[15] = "";
#ifdef _WIN32
    if (flags_get_qr(dns->flags) == QR_RESPONSE) {
        strcat_s(flags, sizeof(flags), "qr ");
    }
    if (flags_get_aa(dns->flags) == AA_YES) {
        strcat_s(flags, sizeof(flags), "aa ");
    }
    if (flags_get_tc(dns->flags) == TC_YES) {
        strcat_s(flags, sizeof(flags), "tc ");
    }
    if (flags_get_rd(dns->flags) == RD_YES) {
        strcat_s(flags, sizeof(flags), "rd ");
    }
    if (flags_get_ra(dns->flags) == RA_YES) {
        strcat_s(flags, sizeof(flags), "ra ");
    }
#else
    if (flags_get_qr(dns->flags) == QR_RESPONSE) {
        strcat(flags, "qr ");
    }
    if (flags_get_aa(dns->flags) == AA_YES) {
        strcat(flags, "aa ");
    }
    if (flags_get_tc(dns->flags) == TC_YES) {
        strcat(flags, "tc ");
    }
    if (flags_get_rd(dns->flags) == RD_YES) {
        strcat(flags, "rd ");
    }
    if (flags_get_ra(dns->flags) == RA_YES) {
        strcat(flags, "ra ");
    }
#endif
    printf("  flags: %s\n", flags);
    printf("  QDCOUNT: %hu\n", dns->qdcount);
    printf("  ARCOUNT: %hu\n", dns->arcount);

    printf("  Questions:\n");
    for (int i = 0; i < dns->qdcount; i++) {
        printf("    - %d:\n", i);
        printf("      QNAME: %s\n", dns->questions[i].qname);
        printf("      QTYPE: %hu\n", dns->questions[i].qtype);
        printf("      QCLASS: %hu\n", dns->questions[i].qclass);
    }
    if (dns->arcount > 0) {
        printf("  Additional:\n");
    }
    // for (int i = 0; i < dns->arcount; i++) {
    //     printf("    - %d:\n", i);
    //     printf("      NAME: %s\n", dns->additional[i].name);
    //     printf("      TYPE: %hu\n", dns->additional[i].type);
    //     printf("      CLASS: %hu\n", dns->additional[i].class);
    //     printf("      TTL: %u\n", dns->additional[i].ttl);
    //     printf("      RDLENGTH: %hu\n", dns->additional[i].rdlength);
    //     printf("      RDATA: ");
    //     for (int j = 0; j < dns->additional[i].rdlength; j++) {
    //         printf("%02x ", dns->additional[i].rdata[j]);
    //     }
    //     printf("\n");
    // }
#endif
}