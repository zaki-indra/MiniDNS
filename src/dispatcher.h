#pragma once

#include "types.h"
#include "memory.h"

// Dispatches the queried request into the data layer and populates the response
void dispatcher_handle(const DNSRequest* req, DNSResponse* resp, Arena* arena);
