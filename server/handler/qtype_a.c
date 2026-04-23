#include "qtype_a.h"

#include "../resolver/resolver.h"

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

hdl_rc_t handle_qtype_a_2(DnsMessage* msg, DnsQuestion* q, Arena* arena)
{
    size_t       count = 0;
    IPv4Address* ips   = nullptr;

    int n = resolve_a_records(q->qname, &ips, &count, arena);
    if (n > 0) {
        flags_set_rcode(&msg->flags, RCODE_NOERROR);
        msg->answers = ips;
        msg->ancount = count;
        return HANDLER_OK;
    } else if (n == 0) {
        flags_set_rcode(&msg->flags, RCODE_NXDOMAIN);
        msg->answers = nullptr;
        msg->ancount = 0;
        return HANDLER_OK;
    } else {
        return HANDLER_ERR;
    }
}
