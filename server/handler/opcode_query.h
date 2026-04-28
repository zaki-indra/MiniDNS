#pragma once

#include "../core/types.h"
#include "../memory.h"
#include "handler.h"

void handle_opcode_query(ServerContext* ctx, DnsMessage* msg, Arena* arena);
