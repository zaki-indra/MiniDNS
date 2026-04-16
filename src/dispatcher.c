#include "dispatcher.h"

#include "data.h"

void dispatcher_handle(const DNSRequest* req, DNSResponse* resp, Arena* arena)
{
    // Basic setup for response
    resp->id = req->id;
    resp->question = req->question;

    // Default to Name Error (NXDOMAIN)
    resp->rcode = 3;
    resp->answers = NULL;
    resp->answer_count = 0;

    if (req->q_count > 0) {
        // Supported QTYPE: Type A = 1
        if (req->question.qtype == 1) {
            size_t count = 0;
            IPv4Address* ips = NULL;

            if (data_query_a_records(req->question.domain, &ips, &count,
                                     arena)) {
                // Success
                resp->rcode = 0; // NOERROR
                resp->answers = ips;
                resp->answer_count = count;
            }
        } else {
            // Not Implemented or refused
            resp->rcode = 4; // Not Implemented
        }
    }
}
