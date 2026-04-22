#pragma once

#include "memory.h"
#include "types.h"

bool db_init(const char* db_path);
bool db_serve_init(const char* db_path);
bool db_add(const char* domain, const IPv4Address* ipv4);
bool db_list(void);
bool db_delete(const char* domain);
bool db_clear(void);
int  db_query(const char* domain, IPv4Address** out_ipv4, Arena* arena);
void db_close(void);
