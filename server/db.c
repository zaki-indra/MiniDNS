#include "db.h"

#include "sqlite3.h"

#include <stdio.h>
#include <string.h>

static sqlite3*      db         = nullptr;
static sqlite3_stmt* stmt_query = nullptr;

bool db_init(const char* db_path)
{
    if (sqlite3_open(db_path, &db) != SQLITE_OK) {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        return false;
    }

    // Enable WAL mode for concurrent read/writes
    sqlite3_exec(db, "PRAGMA journal_mode=WAL;", nullptr, nullptr, nullptr);

    const char* sql = "CREATE TABLE IF NOT EXISTS records ("
                      "domain TEXT, "
                      "ipv4 INTEGER"
                      ");";
    if (sqlite3_exec(db, sql, nullptr, nullptr, nullptr) != SQLITE_OK) {
        fprintf(stderr, "Failed to create table: %s\n", sqlite3_errmsg(db));
        return false;
    }
    return true;
}

bool db_serve_init(const char* db_path)
{
    // Open DB for serving.
    if (sqlite3_open(db_path, &db) != SQLITE_OK) {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        return false;
    }

    // Prepare the SELECT statement once for high performance
    const char* sql = "SELECT ipv4 FROM records WHERE domain = ?;";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt_query, nullptr) != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n",
                sqlite3_errmsg(db));
        return false;
    }
    return true;
}

bool db_list(void)
{
    sqlite3_stmt* stmt;
    const char*   sql = "SELECT rowid, domain, ipv4 FROM records;";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n",
                sqlite3_errmsg(db));
        return false;
    }

    printf("DNS Records:\n");

    IPv4Address ip;

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const long           id     = (long)sqlite3_column_int64(stmt, 0);
        const unsigned char* domain = sqlite3_column_text(stmt, 1);
        ip.words                    = sqlite3_column_int(stmt, 2);
        printf("  %ld: %s -> %hhu.%hhu.%hhu.%hhu\n", id, (const char*)domain,
               ip.octets[0], ip.octets[1], ip.octets[2], ip.octets[3]);
    }
    sqlite3_finalize(stmt);
    return true;
}

bool db_add(const char* domain, const IPv4Address* ipv4_out)
{
    sqlite3_stmt* stmt;
    const char*   sql = "INSERT INTO records (domain, ipv4) VALUES (?, ?);";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return false;

    sqlite3_bind_text(stmt, 1, domain, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 2, (int)ipv4_out->words);

    bool success = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);
    return success;
}

bool db_delete(const char* domain)
{
    sqlite3_stmt* stmt;
    const char*   sql = "DELETE FROM records WHERE domain = ?;";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return false;

    sqlite3_bind_text(stmt, 1, domain, -1, SQLITE_STATIC);
    bool success = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);
    return success;
}

bool db_clear(void)
{
    const char* sql = "DELETE FROM records;";
    return sqlite3_exec(db, sql, nullptr, nullptr, nullptr) == SQLITE_OK;
}

int db_query(const char* domain, IPv4Address** ips_out, Arena* arena)
{
    if (!stmt_query) {
        perror("Statement not prepared");
        return -1;
    }

    sqlite3_bind_text(stmt_query, 1, domain, -1, SQLITE_STATIC);

    IPv4Address ip_list[64];
    int         ips = 0;

    while (sqlite3_step(stmt_query) == SQLITE_ROW && ips < 64) {
        ip_list[ips++].words = sqlite3_column_int(stmt_query, 0);
    }

    sqlite3_reset(stmt_query);

    if (ips == 0) {
        *ips_out = nullptr;
        return 0;
    }

    *ips_out = (IPv4Address*)arena_alloc(arena, sizeof(IPv4Address) * ips);
    if (!*ips_out)
        return -1;

    memcpy(*ips_out, ip_list, sizeof(IPv4Address) * ips);
    return ips;
}

void db_close(void)
{
    if (stmt_query)
        sqlite3_finalize(stmt_query);
    if (db)
        sqlite3_close(db);
}
