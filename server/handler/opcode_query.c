#include "opcode_query.h"

#include "qtype_a.h"

void handle_opcode_query(ServerContext* ctx, DnsMessage* msg, Arena* arena)
{
    if (msg->qdcount > 0) {
        DnsQuestion* q     = &msg->questions[0];
        qtype_t      qtype = get_qtype(q->qtype);

        switch (qtype) {
        case QTYPE_A:
            handle_qtype_a(ctx, msg, q, arena);
            break;
        default:
            flags_set_rcode(&msg->flags, RCODE_NOTIMP);
            break;
        }
    }
}
