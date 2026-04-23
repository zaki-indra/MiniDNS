#pragma once

#include "core/types.h"
#include "memory.h"

typedef enum : int {
    DISP_OK  = 0,
    DISP_ERR = 1,
} disp_rc_t;

void dispatcher_handle(DnsMessage* msg, Arena* arena);

disp_rc_t dispatcher_handle_2(DnsMessage* msg, Arena* arena);
