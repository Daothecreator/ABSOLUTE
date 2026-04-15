/*
 * UCAN Authorization System
 * User-Controlled Authorization Networks
 * Decentralized, trustless capability delegation
 * 
 * License: MIT
 * Version: 1.0 (April 2026)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <sodium.h>
#include "../core/stlc_policy_engine.h"

/* === Constants === */

#define UCAN_VERSION "0.9.1"
#define DID_PREFIX "did:key:z"
#define MAX_UCAN_DEPTH 10
#define UCAN_SIG_SIZE 64
#define UCAN_KEY_SIZE 32

/* === Data Structures === */

/* Decentralized Identifier */
typedef struct did_s {
    char id[128];
    uint8_t public_key[UCAN_KEY_SIZE];
    uint8_t private_key[UCAN_KEY_SIZE];
    time_t created_at;
} did_t;

/* UCAN Capability */
typedef struct ucan_capability_s {
    char resource[256];       /* Resource URI */
    char ability[64];         /* Ability (read/write/etc) */
    type_t *stlc_type;        /* STLC type representation */
    uint64_t expires_at;      /* Expiration timestamp */
} ucan_capability_t;

/* UCAN Proof chain */
typedef struct ucan_proof_s {
    uint8_t signature[UCAN_SIG_SIZE];
    char issuer_did[128];
    char audience_did[128];
    uint64_t issued_at;
    struct ucan_proof_s *parent;  /* Parent in delegation chain */
} ucan_proof_t;

/* UCAN Token */
typedef struct ucan_token_s {
    char version[16];
    char issuer_did[128];
    char audience_did[128];
    uint64_t issued_at;
    uint64_t expires_at;
    uint64_t not_before;
    
    ucan_capability_t **capabilities;
    size_t capability_count;
    
    ucan_proof_t **proofs;
    size_t proof_count;
    
    uint8_t signature[UCAN_SIG_SIZE];
    
    struct ucan_token_s *parent;  /* Delegation parent */
} ucan_token_t;

/* UCAN Store */
typedef struct ucan_store_s {
    did_t *owner;                    /* Device owner's DID */
    ucan_token_t **tokens;           /* Active tokens */
    size_t token_count;
    size_t token_capacity;
    
    /* Revoked tokens (by signature hash) */
    uint8_t (*revoked)[UCAN_SIG_SIZE];
    size_t revoked_count;
} ucan_store_t;

/* === Cryptographic Utilities === */

static int ucan_generate_keypair(did_t *did) {
    if (!did) return -1;
    
    /* Generate Ed25519 keypair */
    if (crypto_sign_keypair(did->public_key, did->private_key) != 0) {
        return -1;
    }
    
    /* Create DID identifier */
    /* did:key:z<base58-encoded-public-key> */
    snprintf(did->id, sizeof(did->id), "%s", DID_PREFIX);
    
    /* Encode public key to base58 (simplified - use proper base58 in production) */
    for (int i = 0; i < UCAN_KEY_SIZE; i++) {
        char hex[3];
        snprintf(hex, sizeof(hex), "%02x", did->public_key[i]);
        strncat(did->id, hex, sizeof(did->id) - strlen(did->id) - 1);
    }
    
    did->created_at = time(NULL);
    
    return 0;
}

static int ucan_sign(const uint8_t *data, size_t data_len,
                     const uint8_t *private_key,
                     uint8_t *signature) {
    unsigned long long sig_len;
    return crypto_sign_detached(signature, &sig_len,
                                data, data_len, private_key);
}

static int ucan_verify(const uint8_t *data, size_t data_len,
                       const uint8_t *public_key,
                       const uint8_t *signature) {
    return crypto_sign_verify_detached(signature, data, data_len, public_key);
}

static void ucan_hash_token(ucan_token_t *token, uint8_t *hash) {
    /* Simple hash of token contents */
    crypto_generichash_state state;
    crypto_generichash_init(&state, NULL, 0, 32);
    
    crypto_generichash_update(&state, 
                              (uint8_t*)token->issuer_did, 
                              strlen(token->issuer_did));
    crypto_generichash_update(&state, 
                              (uint8_t*)token->audience_did, 
                              strlen(token->audience_did));
    crypto_generichash_update(&state, 
                              (uint8_t*)&token->issued_at, 
                              sizeof(token->issued_at));
    crypto_generichash_update(&state, 
                              (uint8_t*)&token->expires_at, 
                              sizeof(token->expires_at));
    
    crypto_generichash_final(&state, hash, 32);
}

/* === DID Operations === */

did_t* ucan_did_create(void) {
    did_t *did = calloc(1, sizeof(did_t));
    if (!did) return NULL;
    
    if (ucan_generate_keypair(did) != 0) {
        free(did);
        return NULL;
    }
    
    return did;
}

void ucan_did_destroy(did_t *did) {
    if (!did) return;
    
    /* Securely wipe private key */
    sodium_memzero(did->private_key, sizeof(did->private_key));
    
    free(did);
}

/* === Token Operations === */

ucan_token_t* ucan_token_create(did_t *issuer, const char *audience_did,
                                 ucan_capability_t **capabilities,
                                 size_t cap_count,
                                 uint64_t expires_in_seconds) {
    if (!issuer || !audience_did) return NULL;
    
    ucan_token_t *token = calloc(1, sizeof(ucan_token_t));
    if (!token) return NULL;
    
    strncpy(token->version, UCAN_VERSION, sizeof(token->version) - 1);
    strncpy(token->issuer_did, issuer->id, sizeof(token->issuer_did) - 1);
    strncpy(token->audience_did, audience_did, sizeof(token->audience_did) - 1);
    
    token->issued_at = time(NULL);
    token->expires_at = token->issued_at + expires_in_seconds;
    token->not_before = token->issued_at;
    
    /* Copy capabilities */
    token->capabilities = calloc(cap_count, sizeof(ucan_capability_t*));
    for (size_t i = 0; i < cap_count; i++) {
        token->capabilities[i] = calloc(1, sizeof(ucan_capability_t));
        memcpy(token->capabilities[i], capabilities[i], sizeof(ucan_capability_t));
    }
    token->capability_count = cap_count;
    
    /* Sign the token */
    uint8_t hash[32];
    ucan_hash_token(token, hash);
    ucan_sign(hash, sizeof(hash), issuer->private_key, token->signature);
    
    return token;
}

void ucan_token_destroy(ucan_token_t *token) {
    if (!token) return;
    
    for (size_t i = 0; i < token->capability_count; i++) {
        free(token->capabilities[i]);
    }
    free(token->capabilities);
    
    for (size_t i = 0; i < token->proof_count; i++) {
        free(token->proofs[i]);
    }
    free(token->proofs);
    
    free(token);
}

/* === Delegation === */

ucan_token_t* ucan_delegate(ucan_token_t *parent, did_t *issuer,
                             const char *audience_did,
                             ucan_capability_t **capabilities,
                             size_t cap_count,
                             uint64_t expires_in_seconds) {
    if (!parent || !issuer) return NULL;
    
    /* Verify parent token is valid and not expired */
    if (time(NULL) > parent->expires_at) {
        return NULL; /* Parent expired */
    }
    
    /* Create child token */
    ucan_token_t *child = ucan_token_create(issuer, audience_did,
                                             capabilities, cap_count,
                                             expires_in_seconds);
    if (!child) return NULL;
    
    /* Link to parent */
    child->parent = parent;
    
    /* Add proof of delegation */
    child->proofs = calloc(1, sizeof(ucan_proof_t*));
    child->proofs[0] = calloc(1, sizeof(ucan_proof_t));
    memcpy(child->proofs[0]->signature, parent->signature, UCAN_SIG_SIZE);
    strncpy(child->proofs[0]->issuer_did, parent->issuer_did, 128);
    strncpy(child->proofs[0]->audience_did, parent->audience_did, 128);
    child->proofs[0]->issued_at = parent->issued_at;
    child->proof_count = 1;
    
    return child;
}

/* === Verification === */

bool ucan_verify_token(ucan_token_t *token, const uint8_t *issuer_pubkey) {
    if (!token) return false;
    
    /* Check expiration */
    time_t now = time(NULL);
    if (now > token->expires_at) {
        return false; /* Token expired */
    }
    if (now < token->not_before) {
        return false; /* Token not yet valid */
    }
    
    /* Verify signature */
    uint8_t hash[32];
    ucan_hash_token(token, hash);
    
    if (ucan_verify(hash, sizeof(hash), issuer_pubkey, token->signature) != 0) {
        return false; /* Invalid signature */
    }
    
    /* Verify proof chain if delegated */
    if (token->parent) {
        /* Recursively verify parent */
        /* In production, would need to look up parent's public key */
        if (!ucan_verify_token(token->parent, issuer_pubkey)) {
            return false;
        }
    }
    
    return true;
}

/* === Store Operations === */

ucan_store_t* ucan_store_create(did_t *owner) {
    if (!owner) return NULL;
    
    ucan_store_t *store = calloc(1, sizeof(ucan_store_t));
    if (!store) return NULL;
    
    store->owner = owner;
    store->token_capacity = 100;
    store->tokens = calloc(store->token_capacity, sizeof(ucan_token_t*));
    
    return store;
}

void ucan_store_destroy(ucan_store_t *store) {
    if (!store) return;
    
    for (size_t i = 0; i < store->token_count; i++) {
        ucan_token_destroy(store->tokens[i]);
    }
    free(store->tokens);
    
    free(store->revoked);
    free(store);
}

bool ucan_store_add(ucan_store_t *store, ucan_token_t *token) {
    if (!store || !token) return false;
    
    if (store->token_count >= store->token_capacity) {
        store->token_capacity *= 2;
        ucan_token_t **new_tokens = realloc(store->tokens, 
                                            sizeof(ucan_token_t*) * store->token_capacity);
        if (!new_tokens) return false;
        store->tokens = new_tokens;
    }
    
    store->tokens[store->token_count++] = token;
    return true;
}

bool ucan_store_revoke(ucan_store_t *store, ucan_token_t *token) {
    if (!store || !token) return false;
    
    /* Add signature to revoked list */
    store->revoked = realloc(store->revoked, 
                             (store->revoked_count + 1) * UCAN_SIG_SIZE);
    if (!store->revoked) return false;
    
    memcpy(store->revoked[store->revoked_count], token->signature, UCAN_SIG_SIZE);
    store->revoked_count++;
    
    return true;
}

bool ucan_store_is_revoked(ucan_store_t *store, ucan_token_t *token) {
    if (!store || !token) return true;
    
    for (size_t i = 0; i < store->revoked_count; i++) {
        if (memcmp(store->revoked[i], token->signature, UCAN_SIG_SIZE) == 0) {
            return true; /* Token revoked */
        }
    }
    
    return false;
}

/* === Context Conversion === */

context_t* ucan_to_context(ucan_token_t **tokens, size_t count) {
    context_t *ctx = context_create();
    if (!ctx) return NULL;
    
    for (size_t i = 0; i < count; i++) {
        ucan_token_t *token = tokens[i];
        
        /* Convert each capability to STLC type */
        for (size_t j = 0; j < token->capability_count; j++) {
            ucan_capability_t *cap = token->capabilities[j];
            
            /* Map capability to resource type */
            resource_type_t resource = RESOURCE_PROCESS;
            confidentiality_level_t level = CONF_INTERNAL;
            
            if (strstr(cap->resource, "network")) {
                resource = RESOURCE_NETWORK;
            } else if (strstr(cap->resource, "filesystem")) {
                resource = RESOURCE_FILESYSTEM;
            } else if (strstr(cap->resource, "camera")) {
                resource = RESOURCE_CAMERA;
            }
            
            type_t *cap_type = type_create_base(resource, level);
            context_append(ctx, cap_type);
        }
    }
    
    return ctx;
}

/* === Serialization === */

char* ucan_token_serialize(ucan_token_t *token) {
    if (!token) return NULL;
    
    /* JSON serialization (simplified) */
    size_t buf_size = 4096;
    char *json = calloc(1, buf_size);
    if (!json) return NULL;
    
    snprintf(json, buf_size,
        "{"
        "\"version\":\"%s\","
        "\"issuer\":\"%s\","
        "\"audience\":\"%s\","
        "\"issued_at\":%lu,"
        "\"expires_at\":%lu,"
        "\"capabilities\":[",
        token->version,
        token->issuer_did,
        token->audience_did,
        token->issued_at,
        token->expires_at
    );
    
    for (size_t i = 0; i < token->capability_count; i++) {
        ucan_capability_t *cap = token->capabilities[i];
        char cap_json[512];
        snprintf(cap_json, sizeof(cap_json),
            "%s{\"resource\":\"%s\",\"ability\":\"%s\"}",
            i > 0 ? "," : "",
            cap->resource,
            cap->ability
        );
        strncat(json, cap_json, buf_size - strlen(json) - 1);
    }
    
    strncat(json, "]}", buf_size - strlen(json) - 1);
    
    return json;
}

/* === Initialization === */

int ucan_init(void) {
    if (sodium_init() < 0) {
        fprintf(stderr, "Failed to initialize libsodium\n");
        return -1;
    }
    
    return 0;
}
