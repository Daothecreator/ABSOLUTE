/*
 * Ring Buffer Header
 * 
 * Part of Sovereign Privacy Widget
 * License: MIT
 */

#ifndef RING_BUFFER_H
#define RING_BUFFER_H

#include <stddef.h>
#include <stdbool.h>
#include <stdatomic.h>

#ifdef __cplusplus
extern "C" {
#endif

/* === Single-Producer Single-Consumer Ring Buffer === */

typedef struct {
    void* buffer;
    size_t capacity;
    size_t element_size;
    size_t mask;
    atomic_size_t head;
    atomic_size_t tail;
} ring_buffer_t;

/* === Operations === */

ring_buffer_t* ring_buffer_create(size_t capacity, size_t element_size);
void ring_buffer_destroy(ring_buffer_t* rb);

size_t ring_buffer_capacity(const ring_buffer_t* rb);
size_t ring_buffer_size(const ring_buffer_t* rb);
bool ring_buffer_empty(const ring_buffer_t* rb);
bool ring_buffer_full(const ring_buffer_t* rb);

bool ring_buffer_push(ring_buffer_t* rb, const void* element);
bool ring_buffer_pop(ring_buffer_t* rb, void* element);
bool ring_buffer_peek(const ring_buffer_t* rb, void* element);

size_t ring_buffer_push_batch(ring_buffer_t* rb, const void* elements, size_t count);
size_t ring_buffer_pop_batch(ring_buffer_t* rb, void* elements, size_t max_count);

void ring_buffer_clear(ring_buffer_t* rb);

/* === Multi-Producer Multi-Consumer Ring Buffer === */

typedef struct mp_ring_buffer_s mp_ring_buffer_t;

mp_ring_buffer_t* mp_ring_buffer_create(size_t capacity, size_t element_size);
void mp_ring_buffer_destroy(mp_ring_buffer_t* mp_rb);

bool mp_ring_buffer_push(mp_ring_buffer_t* mp_rb, const void* element, bool blocking);
bool mp_ring_buffer_pop(mp_ring_buffer_t* mp_rb, void* element, bool blocking);

#ifdef __cplusplus
}
#endif

#endif /* RING_BUFFER_H */
