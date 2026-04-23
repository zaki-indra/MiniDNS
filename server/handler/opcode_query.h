#pragma once

#include "../core/types.h"
#include "../memory.h"
#include "handler.h"

void handle_opcode_query(DnsMessage* msg, Arena* arena);

hdl_rc_t handle_opcode_query_2(DnsMessage* msg, Arena* arena);
