#pragma once

#include <stddef.h>
#include <stdint.h>

// A simple arena / bump allocator
typedef struct {
    uint8_t* buffer;
    size_t size;
    size_t offset;
} Arena;

// Initialize the arena with a given memory block
void arena_init(Arena* arena, void* buffer, size_t size);

// Allocate memory from the arena. Returns NULL if out of space.
void* arena_alloc(Arena* arena, size_t size);

// Reset the arena offset, freeing all allocated memory at once.
void arena_reset(Arena* arena);
