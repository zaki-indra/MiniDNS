#include "qtype_a.h"

#include "../resolver.h"

#include <stddef.h>

bool handle_qtype_a(DnsMessage* msg, DnsQuestion* q, Arena* arena)
{
    size_t       count = 0;
    IPv4Address* ips   = nullptr;

    if (resolve_a_records(q->qname, &ips, &count, arena)) {
        flags_set_rcode(&msg->flags, RCODE_NOERROR);
        msg->answers = ips;
        msg->ancount = count;
        return true;
    } else {
        flags_set_rcode(&msg->flags, RCODE_NXDOMAIN);
        msg->answers = nullptr;
        msg->ancount = 0;
        return false;
    }
}
