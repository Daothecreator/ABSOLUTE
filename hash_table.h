/*
 * Hash Table Header
 * 
 * Part of Sovereign Privacy Widget
 * License: MIT
 */

#ifndef HASH_TABLE_H
#define HASH_TABLE_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* === Types === */

typedef enum {
    HT_GENERIC_KEYS,
    HT_STRING_KEYS,
    HT_UINT64_KEYS
} hash_table_type_t;

typedef enum {
    ENTRY_EMPTY,
    ENTRY_OCCUPIED,
    ENTRY_TOMBSTONE
} entry_state_t;

typedef struct {
    void* key;
    size_t key_len;
    void* value;
    size_t value_len;
    uint64_t hash;
    entry_state_t state;
    size_t distance;
} hash_entry_t;

typedef struct {
    hash_entry_t* entries;
    size_t capacity;
    size_t count;
    size_t tombstone_count;
    hash_table_type_t type;
} hash_table_t;

typedef struct {
    hash_table_t* ht;
    size_t index;
} hash_iter_t;

/* === Operations === */

hash_table_t* hash_table_create(size_t initial_capacity, hash_table_type_t type);
void hash_table_destroy(hash_table_t* ht);

int hash_table_insert(hash_table_t* ht, const void* key, size_t key_len,
                      const void* value, size_t value_len);
void* hash_table_lookup(hash_table_t* ht, const void* key, size_t key_len,
                        size_t* value_len);
int hash_table_delete(hash_table_t* ht, const void* key, size_t key_len);

/* === Convenience Functions === */

int hash_table_insert_string(hash_table_t* ht, const char* key, void* value, size_t value_len);
void* hash_table_lookup_string(hash_table_t* ht, const char* key, size_t* value_len);
int hash_table_delete_string(hash_table_t* ht, const char* key);

int hash_table_insert_uint64(hash_table_t* ht, uint64_t key, void* value, size_t value_len);
void* hash_table_lookup_uint64(hash_table_t* ht, uint64_t key, size_t* value_len);
int hash_table_delete_uint64(hash_table_t* ht, uint64_t key);

/* === Iteration === */

void hash_table_iter_init(hash_table_t* ht, hash_iter_t* iter);
int hash_table_iter_next(hash_iter_t* iter, void** key, size_t* key_len,
                         void** value, size_t* value_len);

#ifdef __cplusplus
}
#endif

#endif /* HASH_TABLE_H */
