#include "memory.h"

// Align to 8 bytes for pointer safety on most architectures
#define ALIGNMENT 8
#define ALIGN_UP(n, a) (((n) + (a) - 1) & ~((a) - 1))

void arena_init(Arena* arena, void* buffer, size_t size)
{
    arena->buffer = (uint8_t*)buffer;
    arena->size = size;
    arena->offset = 0;
}

void* arena_alloc(Arena* arena, size_t size)
{
    size_t aligned_size = ALIGN_UP(size, ALIGNMENT);

    if (arena->offset + aligned_size > arena->size) {
        return nullptr; // OOM
    }

    void* ptr = arena->buffer + arena->offset;
    arena->offset += aligned_size;
    return ptr;
}

void arena_reset(Arena* arena)
{
    arena->offset = 0;
}
