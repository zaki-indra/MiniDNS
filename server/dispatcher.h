#pragma once

#include "memory.h"
#include "types.h"

// Dispatches the queried request into the correct opcode handler and populates
// the response
void dispatcher_handle(DnsMessage* msg, Arena* arena);
