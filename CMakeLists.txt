cmake_minimum_required(VERSION 4.0)
project(minidns C)

# C17 Standard as requested
set(CMAKE_C_STANDARD 23)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Include directories
include_directories(include third_party/sqlite3)

# Define source files
set(SOURCES
        src/main.c
        src/server.c
        src/protocol.c
        src/db.c
        src/cache.c
        third_party/sqlite3/sqlite3.c
)

add_executable(minidns ${SOURCES})

# Threads are required by SQLite on most platforms
find_package(Threads REQUIRED)
target_link_libraries(minidns Threads::Threads)

# Windows sockets requirement
if(WIN32)
    target_link_libraries(minidns ws2_32)
endif()

install(TARGETS minidns DESTINATION bin)