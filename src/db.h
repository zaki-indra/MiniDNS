#pragma once

#include <stdbool.h>

#include "core.h"

bool db_init(const char *db_path);
bool db_serve_init(const char *db_path);
bool db_add(const char *domain, const IPv4Address *ipv4);
bool db_list(void);
bool db_delete(const char *domain);
bool db_clear(void);
bool db_query(const char *domain, IPv4Address *ipv4_out);
void db_close(void);
