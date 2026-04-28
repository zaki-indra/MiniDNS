#pragma once

#include "core/types.h"
#include "memory.h"
#include "parser.h"

server_action_t dispatcher_handle(ServerContext* ctx, DnsMessage* msg, Arena* arena);
server_action_t dispatcher_handle_error(DnsMessage* msg, parse_rc_t err);
