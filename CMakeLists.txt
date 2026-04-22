cmake_minimum_required(VERSION 4.0)
project(minidns C)

set(CMAKE_C_STANDARD 23)
set(CMAKE_C_STANDARD_REQUIRED ON)

if (MSVC)
    add_compile_options(/std:clatest)
endif ()

include_directories(include third_party/sqlite3)

set(SOURCES
        server/main.c
        server/types.c
        server/debug.c
        server/server.c
        server/db.c
        server/cache.c
        server/memory.c
        server/parser.c
        server/resolver.c
        server/handlers/opcode_query.c
        server/handlers/qtype_a.c
        server/dispatcher.c
        server/queue.c
        third_party/sqlite3/sqlite3.c
)

add_executable(minidns ${SOURCES})

if (CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_definitions(minidns PRIVATE DEBUG)
endif ()

target_compile_options(minidns PRIVATE
        $<$<CONFIG:Debug>:-Wall -Wextra -g>
)

find_package(Threads REQUIRED)
target_link_libraries(minidns Threads::Threads)

if (WIN32)
    target_link_libraries(minidns ws2_32)
endif ()

install(TARGETS minidns DESTINATION bin)