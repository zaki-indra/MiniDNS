cmake_minimum_required(VERSION 4.0)
project(minidns C)

set(CMAKE_C_STANDARD 23)
set(CMAKE_C_STANDARD_REQUIRED ON)

if(MSVC)
    add_compile_options(/std:clatest)
endif()

include_directories(include third_party/sqlite3)

set(SOURCES
        src/main.c
        src/types.c
        src/server.c
        src/db.c
        src/cache.c
        src/memory.c
        src/parser.c
        src/data.c
        src/dispatcher.c
        third_party/sqlite3/sqlite3.c
)

add_executable(minidns ${SOURCES})

find_package(Threads REQUIRED)
target_link_libraries(minidns Threads::Threads)

if(WIN32)
    target_link_libraries(minidns ws2_32)
endif()

install(TARGETS minidns DESTINATION bin)