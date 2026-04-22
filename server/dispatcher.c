#include "dispatcher.h"

#include "handlers/opcode_query.h"

#include <stdio.h>

void dispatcher_handle(DnsMessage* msg, Arena* arena)
{
    // Setting default response flags for a server
    flags_set_qr(&msg->flags, QR_RESPONSE);
    flags_set_aa(&msg->flags, AA_NO);
    flags_set_tc(&msg->flags, TC_NO);
    flags_set_ra(&msg->flags, RA_NO);

    opcode_t opcode = flags_get_opcode(msg->flags);

    switch (opcode) {
    case OPCODE_QUERY:
        handle_opcode_query(msg, arena);
        break;
    default:
        flags_set_rcode(&msg->flags, RCODE_NOTIMP);
        break;
    }
}
