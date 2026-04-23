#pragma once

#include "../core/types.h"
#include "../memory.h"
#include "handler.h"

bool handle_qtype_a(DnsMessage* msg, DnsQuestion* q, Arena* arena);

hdl_rc_t handle_qtype_a_2(DnsMessage* msg, DnsQuestion* q, Arena* arena);
