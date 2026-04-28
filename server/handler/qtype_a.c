#include "qtype_a.h"

#include <stddef.h>

void handle_qtype_a(ServerContext* ctx, DnsMessage* msg, DnsQuestion* q,
                    Arena* arena)
{
    size_t       count = 0;
    IPv4Address* ips   = nullptr;

    int n = ctx->resolve_a_records(q->qname, &ips, &count, arena);
    if (n > 0) {
        flags_set_rcode(&msg->flags, RCODE_NOERROR);
        msg->answers = ips;
        msg->ancount = (uint16_t)count;
    } else if (n == 0) {
        flags_set_rcode(&msg->flags, RCODE_NXDOMAIN);
        msg->answers = nullptr;
        msg->ancount = 0;
    } else {
        flags_set_rcode(&msg->flags, RCODE_SERVFAIL);
        msg->answers = nullptr;
        msg->ancount = 0;
    }
}
