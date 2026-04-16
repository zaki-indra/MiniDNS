#pragma once

#include "memory.h"
#include "types.h"

// Dispatches the queried request into the data layer and populates the response
void dispatcher_handle(const DNSRequest* req, DNSResponse* resp, Arena* arena);
