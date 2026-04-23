#include "opcode_query.h"

#include "qtype_a.h"

void handle_opcode_query(DnsMessage* msg, Arena* arena)
{
    if (msg->qdcount > 0) {
        DnsQuestion* q     = &msg->questions[0];
        qtype_t      qtype = get_qtype(q->qtype);

        switch (qtype) {
        case QTYPE_A:
            handle_qtype_a(msg, q, arena);
            break;
        default:
            flags_set_rcode(&msg->flags, RCODE_NOTIMP);
            break;
        }
    }
}

hdl_rc_t handle_opcode_query_2(DnsMessage* msg, Arena* arena)
{
    if (!msg->qdcount) {
        return HANDLER_OK;
    }

    hdl_rc_t     rc;
    DnsQuestion* q     = &msg->questions[0];
    qtype_t      qtype = get_qtype(q->qtype);
    switch (qtype) {
    case QTYPE_A:
        rc = handle_qtype_a_2(msg, q, arena);
        break;
    default:
        flags_set_rcode(&msg->flags, RCODE_NOTIMP);
        rc = HANDLER_ERR;
    }

    return rc;
}
