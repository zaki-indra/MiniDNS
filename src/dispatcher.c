#include "dispatcher.h"

#include "data.h"

#include <stdio.h>

void dispatcher_handle(DNS* dns, Arena* arena)
{
    flags_set_qr(&dns->flags, QR_RESPONSE);
    flags_set_aa(&dns->flags, AA_NO);
    flags_set_tc(&dns->flags, TC_NO);
    flags_set_ra(&dns->flags, RA_NO);

    if (dns->qdcount > 0) {
        if (get_qtype(dns->questions[0].qtype) == QTYPE_A) {
            size_t       count = 0;
            IPv4Address* ips   = nullptr;

            if (data_query_a_records(dns->questions[0].qname, &ips, &count,
                                     arena)) {
                flags_set_rcode(&dns->flags, RCODE_NOERROR);
                dns->answers = ips;
                dns->ancount = count;
            } else {
                flags_set_rcode(&dns->flags, RCODE_NXDOMAIN);
                dns->answers = nullptr;
                dns->ancount = 0;
            }
        } else {
            flags_set_rcode(&dns->flags, RCODE_NOTIMP);
        }
    }
}
