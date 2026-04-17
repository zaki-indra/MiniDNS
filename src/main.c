// main.c

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

#include "db.h"
#include "server.h"
#include "types.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void print_usage(const char* prog_name)
{
    printf("MiniDNS - A minimal, performant DNS server in C\n\n");
    printf("Usage:\n");
    printf("  %s init                      Initialize the SQLite database\n",
           prog_name);
    printf(
        "  %s serve <port>              Start the DNS server on the specified "
        "UDP port\n",
        prog_name);
    printf("  %s add <domain> <ipv4>       Add or update an A record\n",
           prog_name);
    printf("  %s list                      List all records\n", prog_name);
    printf("  %s delete <domain>           Remove a record\n", prog_name);
    printf("  %s clear                     Remove all records\n", prog_name);
}

static int parse_port(const char* port_str)
{
    char* endptr;
    errno = 0;
    long port = strtol(port_str, &endptr, 10);

    if (port_str == endptr || *endptr != '\0' || errno != 0 || port < 1 ||
        port > 65535) {
        return -1;
    }
    return (int)port;
}

int main(const int argc, char** argv)
{
    const char* err_msg;
    const char* db_path = "minidns.db";

    if (argc < 2) {
        goto help_and_fail;
    }

    const char* cmd = argv[1];

    if (strcmp(cmd, "init") == 0) {
        if (argc != 2) {
            err_msg = "Error: 'init' does not take additional arguments.";
            goto fail;
        }
        if (!db_init(db_path)) {
            err_msg = "Error: Failed to initialize database.";
            goto fail;
        }
        printf("Database initialized successfully at '%s'.\n", db_path);
    } else if (strcmp(cmd, "serve") == 0) {
        if (argc != 3) {
            err_msg = "Error: 'serve' requires exactly one argument: <port>.";
            goto fail;
        }
        const int port = parse_port(argv[2]);
        if (port == -1) {
            err_msg =
                "Error: Invalid port. Must be an integer between 1 and 65535.";
            goto fail;
        }
        if (!db_serve_init(db_path)) {
            err_msg = "Error: Failed to initialize database for serving.";
            goto fail;
        }
        printf("Starting MiniDNS server on port %d...\n", port);
        server_start(port);
    } else if (strcmp(cmd, "add") == 0) {
        if (argc != 4) {
            err_msg =
                "Error: 'add' requires exactly two arguments: <domain> <ipv4>.";
            goto fail;
        }
        IPv4Address ipv4;
        if (!inet_pton(AF_INET, argv[3], ipv4.octets)) {
            err_msg = "Error: Invalid IPv4 address.";
            goto fail;
        }
        if (!db_init(db_path) || !db_add(argv[2], &ipv4)) {
            err_msg = "Error: Failed to add record.";
            goto fail;
        }
        printf("Record added: %s -> %s\n", argv[2], argv[3]);
    } else if (strcmp(cmd, "list") == 0) {
        if (argc != 2) {
            err_msg = "Error: 'list' requires exactly one argument.";
            goto fail;
        }
        if (!db_init(db_path) || db_list()) {
        }
    } else if (strcmp(cmd, "delete") == 0) {
        if (argc != 3) {
            err_msg =
                "Error: 'delete' requires exactly one argument: <domain>.";
            goto fail;
        }
        if (!db_init(db_path) || !db_delete(argv[2])) {
            err_msg = "Error: Failed to delete record.";
            goto fail;
        }
        printf("Record deleted: %s\n", argv[2]);
    } else if (strcmp(cmd, "clear") == 0) {
        if (argc != 2) {
            err_msg = "Error: 'clear' does not take additional arguments.";
            goto fail;
        }
        if (!db_init(db_path) || !db_clear()) {
            err_msg = "Error: Failed to clear records.";
            goto fail;
        }
        printf("All records cleared.\n");
    } else {
        fprintf(stderr, "Error: Unknown command '%s'.\n\n", cmd);
        goto help_and_fail;
    }

    // --- Success Path ---
    db_close();
    return EXIT_SUCCESS;

    // --- Error Handling Paths ---
fail:
    if (err_msg) {
        fprintf(stderr, "%s\n", err_msg);
    }
    db_close(); // Ensure DB is closed even on failure
    return EXIT_FAILURE;

help_and_fail:
    print_usage(argv[0]);
    return EXIT_FAILURE;
}
