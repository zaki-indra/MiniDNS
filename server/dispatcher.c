#include "dispatcher.h"

#include "handler/opcode_query.h"

#include <stdio.h>

server_action_t dispatcher_handle_error(DnsMessage* msg, parse_rc_t err)
{
    dns_prepare_response(msg);
    flags_set_opcode(&msg->flags, OPCODE_QUERY);
    flags_set_z(&msg->flags);

    if (err == PARSE_ERR_NOTIMP) {
        flags_set_rcode(&msg->flags, RCODE_NOTIMP);
    } else {
        flags_set_rcode(&msg->flags, RCODE_FORMERR);
    }

    msg->qdcount = 0;
    msg->ancount = 0;
    msg->nscount = 0;
    msg->arcount = 0;

    return ACTION_SEND_REPLY;
}

server_action_t dispatcher_handle(ServerContext* ctx, DnsMessage* msg, Arena* arena)
{
    if (flags_get_qr(msg->flags) == QR_RESPONSE) {
        return ACTION_DROP;
    }

    opcode_t opcode = flags_get_opcode(msg->flags);

    if (opcode == OPCODE_UNKNOWN) {
        dns_prepare_response(msg);
        flags_set_rcode(&msg->flags, RCODE_NOTIMP);
        return ACTION_SEND_REPLY;
    }

    if (opcode == OPCODE_QUERY && msg->qdcount != 1) {
        return dispatcher_handle_error(msg, PARSE_ERR_FORMERR);
    }

    dns_prepare_response(msg);
    flags_set_z(&msg->flags);

    switch (opcode) {
    case OPCODE_QUERY:
        handle_opcode_query(ctx, msg, arena);
        return ACTION_SEND_REPLY;
    default:
        flags_set_rcode(&msg->flags, RCODE_NOTIMP);
        return ACTION_SEND_REPLY;
    }
}
