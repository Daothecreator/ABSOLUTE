/*
 * Ring Buffer Implementation
 * Lock-free single-producer single-consumer ring buffer
 * 
 * Part of Sovereign Privacy Widget
 * License: MIT
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
#include <stdbool.h>

#include "ring_buffer.h"

/* === Ring Buffer Operations === */

ring_buffer_t* ring_buffer_create(size_t capacity, size_t element_size) {
    if (capacity == 0 || element_size == 0) return NULL;
    
    /* Round capacity to power of 2 for efficient masking */
    size_t cap = 1;
    while (cap < capacity) cap <<= 1;
    
    ring_buffer_t* rb = calloc(1, sizeof(ring_buffer_t));
    if (!rb) return NULL;
    
    rb->buffer = calloc(cap, element_size);
    if (!rb->buffer) {
        free(rb);
        return NULL;
    }
    
    rb->capacity = cap;
    rb->element_size = element_size;
    rb->mask = cap - 1;
    atomic_init(&rb->head, 0);
    atomic_init(&rb->tail, 0);
    
    return rb;
}

void ring_buffer_destroy(ring_buffer_t* rb) {
    if (!rb) return;
    
    free(rb->buffer);
    free(rb);
}

size_t ring_buffer_capacity(const ring_buffer_t* rb) {
    if (!rb) return 0;
    return rb->capacity;
}

size_t ring_buffer_size(const ring_buffer_t* rb) {
    if (!rb) return 0;
    
    size_t head = atomic_load_explicit(&rb->head, memory_order_acquire);
    size_t tail = atomic_load_explicit(&rb->tail, memory_order_acquire);
    
    return (head - tail) & rb->mask;
}

bool ring_buffer_empty(const ring_buffer_t* rb) {
    if (!rb) return true;
    
    size_t head = atomic_load_explicit(&rb->head, memory_order_acquire);
    size_t tail = atomic_load_explicit(&rb->tail, memory_order_acquire);
    
    return head == tail;
}

bool ring_buffer_full(const ring_buffer_t* rb) {
    if (!rb) return true;
    
    size_t head = atomic_load_explicit(&rb->head, memory_order_acquire);
    size_t tail = atomic_load_explicit(&rb->tail, memory_order_acquire);
    
    return ((head + 1) & rb->mask) == tail;
}

/* === Single-Producer Single-Consumer Operations === */

bool ring_buffer_push(ring_buffer_t* rb, const void* element) {
    if (!rb || !element) return false;
    
    size_t head = atomic_load_explicit(&rb->head, memory_order_relaxed);
    size_t next_head = (head + 1) & rb->mask;
    size_t tail = atomic_load_explicit(&rb->tail, memory_order_acquire);
    
    /* Check if full */
    if (next_head == tail) {
        return false; /* Buffer full */
    }
    
    /* Copy element */
    memcpy((char*)rb->buffer + head * rb->element_size, element, rb->element_size);
    
    /* Update head */
    atomic_store_explicit(&rb->head, next_head, memory_order_release);
    
    return true;
}

bool ring_buffer_pop(ring_buffer_t* rb, void* element) {
    if (!rb || !element) return false;
    
    size_t tail = atomic_load_explicit(&rb->tail, memory_order_relaxed);
    size_t head = atomic_load_explicit(&rb->head, memory_order_acquire);
    
    /* Check if empty */
    if (tail == head) {
        return false; /* Buffer empty */
    }
    
    /* Copy element */
    memcpy(element, (char*)rb->buffer + tail * rb->element_size, rb->element_size);
    
    /* Update tail */
    size_t next_tail = (tail + 1) & rb->mask;
    atomic_store_explicit(&rb->tail, next_tail, memory_order_release);
    
    return true;
}

bool ring_buffer_peek(const ring_buffer_t* rb, void* element) {
    if (!rb || !element) return false;
    
    size_t tail = atomic_load_explicit(&rb->tail, memory_order_acquire);
    size_t head = atomic_load_explicit(&rb->head, memory_order_acquire);
    
    /* Check if empty */
    if (tail == head) {
        return false;
    }
    
    /* Copy element without removing */
    memcpy(element, (char*)rb->buffer + tail * rb->element_size, rb->element_size);
    
    return true;
}

/* === Batch Operations === */

size_t ring_buffer_push_batch(ring_buffer_t* rb, const void* elements, size_t count) {
    if (!rb || !elements || count == 0) return 0;
    
    size_t pushed = 0;
    const char* src = elements;
    
    for (size_t i = 0; i < count; i++) {
        if (!ring_buffer_push(rb, src + i * rb->element_size)) {
            break;
        }
        pushed++;
    }
    
    return pushed;
}

size_t ring_buffer_pop_batch(ring_buffer_t* rb, void* elements, size_t max_count) {
    if (!rb || !elements || max_count == 0) return 0;
    
    size_t popped = 0;
    char* dst = elements;
    
    for (size_t i = 0; i < max_count; i++) {
        if (!ring_buffer_pop(rb, dst + i * rb->element_size)) {
            break;
        }
        popped++;
    }
    
    return popped;
}

/* === Clear === */

void ring_buffer_clear(ring_buffer_t* rb) {
    if (!rb) return;
    
    atomic_store_explicit(&rb->head, 0, memory_order_release);
    atomic_store_explicit(&rb->tail, 0, memory_order_release);
}

/* === Multi-Producer Multi-Consumer (with locks) === */

#include <pthread.h>

struct mp_ring_buffer_s {
    ring_buffer_t* rb;
    pthread_mutex_t mutex;
    pthread_cond_t not_empty;
    pthread_cond_t not_full;
};

mp_ring_buffer_t* mp_ring_buffer_create(size_t capacity, size_t element_size) {
    mp_ring_buffer_t* mp_rb = calloc(1, sizeof(mp_ring_buffer_t));
    if (!mp_rb) return NULL;
    
    mp_rb->rb = ring_buffer_create(capacity, element_size);
    if (!mp_rb->rb) {
        free(mp_rb);
        return NULL;
    }
    
    pthread_mutex_init(&mp_rb->mutex, NULL);
    pthread_cond_init(&mp_rb->not_empty, NULL);
    pthread_cond_init(&mp_rb->not_full, NULL);
    
    return mp_rb;
}

void mp_ring_buffer_destroy(mp_ring_buffer_t* mp_rb) {
    if (!mp_rb) return;
    
    pthread_mutex_destroy(&mp_rb->mutex);
    pthread_cond_destroy(&mp_rb->not_empty);
    pthread_cond_destroy(&mp_rb->not_full);
    
    ring_buffer_destroy(mp_rb->rb);
    free(mp_rb);
}

bool mp_ring_buffer_push(mp_ring_buffer_t* mp_rb, const void* element, bool blocking) {
    if (!mp_rb || !element) return false;
    
    pthread_mutex_lock(&mp_rb->mutex);
    
    while (ring_buffer_full(mp_rb->rb)) {
        if (!blocking) {
            pthread_mutex_unlock(&mp_rb->mutex);
            return false;
        }
        pthread_cond_wait(&mp_rb->not_full, &mp_rb->mutex);
    }
    
    bool result = ring_buffer_push(mp_rb->rb, element);
    
    pthread_cond_signal(&mp_rb->not_empty);
    pthread_mutex_unlock(&mp_rb->mutex);
    
    return result;
}

bool mp_ring_buffer_pop(mp_ring_buffer_t* mp_rb, void* element, bool blocking) {
    if (!mp_rb || !element) return false;
    
    pthread_mutex_lock(&mp_rb->mutex);
    
    while (ring_buffer_empty(mp_rb->rb)) {
        if (!blocking) {
            pthread_mutex_unlock(&mp_rb->mutex);
            return false;
        }
        pthread_cond_wait(&mp_rb->not_empty, &mp_rb->mutex);
    }
    
    bool result = ring_buffer_pop(mp_rb->rb, element);
    
    pthread_cond_signal(&mp_rb->not_full);
    pthread_mutex_unlock(&mp_rb->mutex);
    
    return result;
}
