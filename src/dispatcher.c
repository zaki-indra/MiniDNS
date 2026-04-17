#include "dispatcher.h"

#include "data.h"

void dispatcher_handle(const DNSRequest* req, DNSResponse* resp, Arena* arena)
{
    // Basic setup for response
    resp->id = req->id;
    resp->question = req->question;
    resp->answers = NULL;
    resp->qdcount = req->qdcount;
    resp->ancount = 0;
    resp->nscount = 0;
    resp->arcount = req->arcount;

    // Extract request flags
    opcode_t opcode = flags_get_opcode(req->flags);
    rd_t rd = flags_get_rd(req->flags);

    // Set default response flags
    flags_set_qr(&resp->flags, QR_RESPONSE);
    flags_set_opcode(&resp->flags, opcode);
    flags_set_aa(&resp->flags, AA_NO);
    flags_set_tc(&resp->flags, TC_NO);
    flags_set_rd(&resp->flags, rd);
    flags_set_ra(&resp->flags, RA_NO);
    flags_set_rcode(&resp->flags, RCODE_NXDOMAIN);

    if (req->qdcount > 0) {
        if (get_qtype(req->question.qtype) == QTYPE_A) {
            size_t count = 0;
            IPv4Address* ips = NULL;

            if (data_query_a_records(req->question.domain, &ips, &count,
                                     arena)) {
                flags_set_rcode(&resp->flags, RCODE_NOERROR);
                resp->answers = ips;
                resp->ancount = count;
            }
        } else {
            flags_set_rcode(&resp->flags, RCODE_NOTIMP);
        }
    }
}
