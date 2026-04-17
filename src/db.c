#include "db.h"

#include "sqlite3.h"
#include "types.h"

#include <stdio.h>

static sqlite3* db = nullptr;
static sqlite3_stmt* stmt_query = nullptr;

bool db_init(const char* db_path)
{
    if (sqlite3_open(db_path, &db) != SQLITE_OK) {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        return false;
    }

    // Enable WAL mode for concurrent read/writes
    sqlite3_exec(db, "PRAGMA journal_mode=WAL;", nullptr, NULL, nullptr);

    const char* sql = "CREATE TABLE IF NOT EXISTS records (domain TEXT PRIMARY "
                      "KEY, ipv4 INTEGER);";
    if (sqlite3_exec(db, sql, nullptr, NULL, nullptr) != SQLITE_OK) {
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
    const char* sql = "SELECT domain, ipv4 FROM records;";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n",
                sqlite3_errmsg(db));
        return false;
    }

    printf("DNS Records:\n");

    IPv4Address ip;

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const unsigned char* domain = sqlite3_column_text(stmt, 0);
        ip.words = sqlite3_column_int(stmt, 1);
        printf("  %s -> %hhu.%hhu.%hhu.%hhu\n", (const char*)domain, ip.octets[0],
               ip.octets[1], ip.octets[2], ip.octets[3]);
    }
    sqlite3_finalize(stmt);
    return true;
}

bool db_add(const char* domain, const IPv4Address* ipv4_out)
{
    sqlite3_stmt* stmt;
    const char* sql = "INSERT INTO records (domain, ipv4) VALUES (?, ?) "
                      "ON CONFLICT(domain) DO UPDATE SET ipv4=excluded.ipv4;";
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
    const char* sql = "DELETE FROM records WHERE domain = ?;";
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
    return sqlite3_exec(db, sql, nullptr, NULL, nullptr) == SQLITE_OK;
}

bool db_query(const char* domain, IPv4Address* ipv4_out)
{
    if (!stmt_query)
        return false;

    sqlite3_bind_text(stmt_query, 1, domain, -1, SQLITE_STATIC);
    bool found = false;

    if (sqlite3_step(stmt_query) == SQLITE_ROW) {
        int text = sqlite3_column_int(stmt_query, 0);
        if (text) {
            ipv4_out->words = sqlite3_column_int(stmt_query, 0);
            found = true;
        }
    }

    sqlite3_reset(stmt_query);
    return found;
}

void db_close(void)
{
    if (stmt_query)
        sqlite3_finalize(stmt_query);
    if (db)
        sqlite3_close(db);
}
