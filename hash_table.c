/*
 * Hash Table Implementation
 * Open addressing with Robin Hood hashing
 * 
 * Part of Sovereign Privacy Widget
 * License: MIT
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "hash_table.h"

/* === Hash Functions === */

static uint64_t hash_fnv1a(const void* key, size_t len) {
    const uint8_t* data = key;
    uint64_t hash = 0xcbf29ce484222325ULL;
    
    for (size_t i = 0; i < len; i++) {
        hash ^= data[i];
        hash *= 0x100000001b3ULL;
    }
    
    return hash;
}

static uint64_t hash_string(const char* str) {
    return hash_fnv1a(str, strlen(str));
}

static uint64_t hash_uint64(uint64_t key) {
    /* SplitMix64 hash */
    key += 0x9e3779b97f4a7c15ULL;
    key = (key ^ (key >> 30)) * 0xbf58476d1ce4e5b9ULL;
    key = (key ^ (key >> 27)) * 0x94d049bb133111ebULL;
    return key ^ (key >> 31);
}

/* === Hash Table Operations === */

hash_table_t* hash_table_create(size_t initial_capacity, hash_table_type_t type) {
    hash_table_t* ht = calloc(1, sizeof(hash_table_t));
    if (!ht) return NULL;
    
    /* Round up to power of 2 */
    size_t cap = 16;
    while (cap < initial_capacity) cap <<= 1;
    
    ht->entries = calloc(cap, sizeof(hash_entry_t));
    if (!ht->entries) {
        free(ht);
        return NULL;
    }
    
    ht->capacity = cap;
    ht->type = type;
    ht->tombstone_count = 0;
    
    return ht;
}

void hash_table_destroy(hash_table_t* ht) {
    if (!ht) return;
    
    for (size_t i = 0; i < ht->capacity; i++) {
        if (ht->entries[i].state == ENTRY_OCCUPIED) {
            free(ht->entries[i].key);
            free(ht->entries[i].value);
        }
    }
    
    free(ht->entries);
    free(ht);
}

static void hash_table_grow(hash_table_t* ht);

int hash_table_insert(hash_table_t* ht, const void* key, size_t key_len, 
                      const void* value, size_t value_len) {
    if (!ht || !key || !value) return -1;
    
    /* Check load factor */
    if ((ht->count + ht->tombstone_count) * 2 >= ht->capacity) {
        hash_table_grow(ht);
    }
    
    uint64_t hash;
    switch (ht->type) {
        case HT_STRING_KEYS:
            hash = hash_string(key);
            break;
        case HT_UINT64_KEYS:
            hash = hash_uint64(*(uint64_t*)key);
            break;
        default:
            hash = hash_fnv1a(key, key_len);
    }
    
    size_t idx = hash & (ht->capacity - 1);
    size_t dist = 0;
    
    /* Robin Hood insertion */
    while (ht->entries[idx].state == ENTRY_OCCUPIED) {
        /* Check for existing key */
        if (ht->entries[idx].key_len == key_len &&
            memcmp(ht->entries[idx].key, key, key_len) == 0) {
            /* Update existing entry */
            free(ht->entries[idx].value);
            ht->entries[idx].value = malloc(value_len);
            memcpy(ht->entries[idx].value, value, value_len);
            ht->entries[idx].value_len = value_len;
            return 0;
        }
        
        /* Robin Hood: swap if current entry is closer to its ideal position */
        if (ht->entries[idx].distance < dist) {
            /* Swap entries */
            hash_entry_t temp = ht->entries[idx];
            
            ht->entries[idx].key = malloc(key_len);
            memcpy(ht->entries[idx].key, key, key_len);
            ht->entries[idx].key_len = key_len;
            ht->entries[idx].value = malloc(value_len);
            memcpy(ht->entries[idx].value, value, value_len);
            ht->entries[idx].value_len = value_len;
            ht->entries[idx].hash = hash;
            ht->entries[idx].state = ENTRY_OCCUPIED;
            ht->entries[idx].distance = dist;
            
            /* Continue with swapped entry */
            key = temp.key;
            key_len = temp.key_len;
            value = temp.value;
            value_len = temp.value_len;
            hash = temp.hash;
            dist = temp.distance;
            
            free(temp.key);
            free(temp.value);
        }
        
        idx = (idx + 1) & (ht->capacity - 1);
        dist++;
    }
    
    /* Insert new entry */
    ht->entries[idx].key = malloc(key_len);
    memcpy(ht->entries[idx].key, key, key_len);
    ht->entries[idx].key_len = key_len;
    ht->entries[idx].value = malloc(value_len);
    memcpy(ht->entries[idx].value, value, value_len);
    ht->entries[idx].value_len = value_len;
    ht->entries[idx].hash = hash;
    ht->entries[idx].state = ENTRY_OCCUPIED;
    ht->entries[idx].distance = dist;
    
    ht->count++;
    
    return 0;
}

void* hash_table_lookup(hash_table_t* ht, const void* key, size_t key_len, 
                        size_t* value_len) {
    if (!ht || !key) return NULL;
    
    uint64_t hash;
    switch (ht->type) {
        case HT_STRING_KEYS:
            hash = hash_string(key);
            break;
        case HT_UINT64_KEYS:
            hash = hash_uint64(*(uint64_t*)key);
            break;
        default:
            hash = hash_fnv1a(key, key_len);
    }
    
    size_t idx = hash & (ht->capacity - 1);
    size_t dist = 0;
    
    while (ht->entries[idx].state != ENTRY_EMPTY) {
        if (ht->entries[idx].state == ENTRY_OCCUPIED &&
            ht->entries[idx].key_len == key_len &&
            memcmp(ht->entries[idx].key, key, key_len) == 0) {
            if (value_len) *value_len = ht->entries[idx].value_len;
            return ht->entries[idx].value;
        }
        
        /* Stop if we've gone past where the entry would be (Robin Hood property) */
        if (ht->entries[idx].state == ENTRY_OCCUPIED && 
            ht->entries[idx].distance < dist) {
            break;
        }
        
        idx = (idx + 1) & (ht->capacity - 1);
        dist++;
        
        /* Prevent infinite loop */
        if (dist > ht->capacity) break;
    }
    
    return NULL;
}

int hash_table_delete(hash_table_t* ht, const void* key, size_t key_len) {
    if (!ht || !key) return -1;
    
    uint64_t hash;
    switch (ht->type) {
        case HT_STRING_KEYS:
            hash = hash_string(key);
            break;
        case HT_UINT64_KEYS:
            hash = hash_uint64(*(uint64_t*)key);
            break;
        default:
            hash = hash_fnv1a(key, key_len);
    }
    
    size_t idx = hash & (ht->capacity - 1);
    size_t dist = 0;
    
    while (ht->entries[idx].state != ENTRY_EMPTY) {
        if (ht->entries[idx].state == ENTRY_OCCUPIED &&
            ht->entries[idx].key_len == key_len &&
            memcmp(ht->entries[idx].key, key, key_len) == 0) {
            /* Mark as tombstone */
            free(ht->entries[idx].key);
            free(ht->entries[idx].value);
            ht->entries[idx].key = NULL;
            ht->entries[idx].value = NULL;
            ht->entries[idx].state = ENTRY_TOMBSTONE;
            ht->count--;
            ht->tombstone_count++;
            return 0;
        }
        
        if (ht->entries[idx].state == ENTRY_OCCUPIED && 
            ht->entries[idx].distance < dist) {
            break;
        }
        
        idx = (idx + 1) & (ht->capacity - 1);
        dist++;
        
        if (dist > ht->capacity) break;
    }
    
    return -1; /* Not found */
}

static void hash_table_grow(hash_table_t* ht) {
    size_t old_capacity = ht->capacity;
    hash_entry_t* old_entries = ht->entries;
    
    ht->capacity *= 2;
    ht->entries = calloc(ht->capacity, sizeof(hash_entry_t));
    ht->count = 0;
    ht->tombstone_count = 0;
    
    /* Rehash all entries */
    for (size_t i = 0; i < old_capacity; i++) {
        if (old_entries[i].state == ENTRY_OCCUPIED) {
            hash_table_insert(ht, old_entries[i].key, old_entries[i].key_len,
                              old_entries[i].value, old_entries[i].value_len);
            free(old_entries[i].key);
            free(old_entries[i].value);
        }
    }
    
    free(old_entries);
}

/* === Iteration === */

void hash_table_iter_init(hash_table_t* ht, hash_iter_t* iter) {
    if (!ht || !iter) return;
    
    iter->ht = ht;
    iter->index = 0;
}

int hash_table_iter_next(hash_iter_t* iter, void** key, size_t* key_len,
                         void** value, size_t* value_len) {
    if (!iter || !iter->ht) return 0;
    
    hash_table_t* ht = iter->ht;
    
    while (iter->index < ht->capacity) {
        if (ht->entries[iter->index].state == ENTRY_OCCUPIED) {
            if (key) *key = ht->entries[iter->index].key;
            if (key_len) *key_len = ht->entries[iter->index].key_len;
            if (value) *value = ht->entries[iter->index].value;
            if (value_len) *value_len = ht->entries[iter->index].value_len;
            iter->index++;
            return 1;
        }
        iter->index++;
    }
    
    return 0;
}

/* === Convenience Functions === */

int hash_table_insert_string(hash_table_t* ht, const char* key, void* value, size_t value_len) {
    return hash_table_insert(ht, key, strlen(key) + 1, value, value_len);
}

void* hash_table_lookup_string(hash_table_t* ht, const char* key, size_t* value_len) {
    return hash_table_lookup(ht, key, strlen(key) + 1, value_len);
}

int hash_table_delete_string(hash_table_t* ht, const char* key) {
    return hash_table_delete(ht, key, strlen(key) + 1);
}

int hash_table_insert_uint64(hash_table_t* ht, uint64_t key, void* value, size_t value_len) {
    return hash_table_insert(ht, &key, sizeof(key), value, value_len);
}

void* hash_table_lookup_uint64(hash_table_t* ht, uint64_t key, size_t* value_len) {
    return hash_table_lookup(ht, &key, sizeof(key), value_len);
}

int hash_table_delete_uint64(hash_table_t* ht, uint64_t key) {
    return hash_table_delete(ht, &key, sizeof(key));
}
