/* -------------------------------------------------------------------------
 * "queue.c"
 *
 * Implementation of the queue
 * ---------------------------------------------------------------------- */

 #include "queue.h"


int queue_init(PacketQueue* q)
{
    q->head = 0;
    q->tail = 0;
    q->count = 0;
    q->shutdown = false;

    if (mtx_init(&q->mutex, mtx_plain) != thrd_success) {
        return -1;
    }
    if (cnd_init(&q->not_empty) != thrd_success) {
        mtx_destroy(&q->mutex);
        return -1;
    }
    if (cnd_init(&q->not_full) != thrd_success) {
        cnd_destroy(&q->not_empty);
        mtx_destroy(&q->mutex);
        return -1;
    }

    return 0;
}

void queue_destroy(PacketQueue* q)
{
    cnd_destroy(&q->not_full);
    cnd_destroy(&q->not_empty);
    mtx_destroy(&q->mutex);
}

void queue_shutdown(PacketQueue* q)
{
    mtx_lock(&q->mutex);
    q->shutdown = true;
    /*
     * Wake everyone: workers blocked on not_empty will drain remaining
     * items then exit. The producer blocked on not_full will also wake
     * and see shutdown = true.
     */
    cnd_broadcast(&q->not_empty);
    cnd_broadcast(&q->not_full);
    mtx_unlock(&q->mutex);
}

bool queue_push(PacketQueue* q, const Packet* pkt)
{
    mtx_lock(&q->mutex);

    /* Wait while full. cnd_wait atomically releases the mutex and
     * suspends. On wake it re-acquires before returning. */
    while (q->count == QUEUE_CAPACITY && !q->shutdown) {
        cnd_wait(&q->not_full, &q->mutex);
    }

    if (q->shutdown) {
        mtx_unlock(&q->mutex);
        return false;
    }

    /* Copy packet into the arena slot. The lock hold time is one
     * struct copy (~400 B) — negligible compared to network I/O. */
    q->slots[q->head] = *pkt;
    q->head = (q->head + 1) % QUEUE_CAPACITY;
    q->count++;

    /* Signal one waiting worker. cnd_signal is cheaper than
     * cnd_broadcast here because only one worker can consume one item. */
    cnd_signal(&q->not_empty);
    mtx_unlock(&q->mutex);
    return true;
}

bool queue_pop(PacketQueue* q, Packet* out)
{
    mtx_lock(&q->mutex);

    while (q->count == 0 && !q->shutdown) {
        cnd_wait(&q->not_empty, &q->mutex);
    }

    /* Drain remaining items even after shutdown, so in-flight work
     * completes cleanly. Only exit when both shutdown and empty. */
    if (q->count == 0) {
        mtx_unlock(&q->mutex);
        return false;
    }

    /* Copy out while holding the mutex, then release immediately.
     * The worker processes the local copy unlocked. */
    *out = q->slots[q->tail];
    q->tail = (q->tail + 1) % QUEUE_CAPACITY;
    q->count--;

    cnd_signal(&q->not_full);
    mtx_unlock(&q->mutex);
    return true;
}