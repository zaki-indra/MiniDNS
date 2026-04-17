#include "dispatcher.h"

#include "data.h"

void dispatcher_handle(DNS* dns, Arena* arena)
{

    // Extract header
    uint16_t id = dns->id;
    uint16_t flags = dns->flags;
    uint16_t qdcount = dns->qdcount;
    uint16_t ancount = dns->ancount;
    uint16_t nscount = dns->nscount;
    uint16_t arcount = dns->arcount;

    qr_t qr = flags_get_qr(flags);
    opcode_t opcode = flags_get_opcode(flags);
    rd_t rd = flags_get_rd(flags);
    aa_t aa = flags_get_aa(flags);
    tc_t tc = flags_get_tc(flags);
    ra_t ra = flags_get_ra(flags);

    // Set default response flags
    flags_set_qr(&dns->flags, QR_RESPONSE);
    flags_set_aa(&dns->flags, AA_NO);
    flags_set_tc(&dns->flags, TC_NO);
    flags_set_rd(&dns->flags, rd);
    flags_set_ra(&dns->flags, RA_NO);

    if (qr == QR_RESPONSE) {
        flags_set_rcode(&dns->flags, RCODE_FORMERR);
        return;
    }

    if (dns->qdcount > 0) {
        if (get_qtype(dns->question.qtype) == QTYPE_A) {
            size_t count = 0;
            IPv4Address* ips = nullptr;

            if (data_query_a_records(dns->question.qname, &ips, &count,
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
