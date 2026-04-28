#pragma once

#include "../core/types.h"
#include "../memory.h"
#include "handler.h"

void handle_qtype_a(ServerContext* ctx, DnsMessage* msg, DnsQuestion* q,
                    Arena* arena);
