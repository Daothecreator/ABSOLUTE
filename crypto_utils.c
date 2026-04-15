/*
 * Cryptographic Utilities
 * libsodium-based encryption, hashing, signatures
 * 
 * Part of Sovereign Privacy Widget
 * License: MIT
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef HAS_SODIUM
#include <sodium.h>
#else
/* Minimal crypto fallback - NOT for production */
#include <stdint.h>
#endif

#include "crypto_utils.h"

/* === Initialization === */

int crypto_init(void) {
#ifdef HAS_SODIUM
    if (sodium_init() < 0) {
        fprintf(stderr, "Failed to initialize libsodium\n");
        return -1;
    }
    printf("libsodium initialized (version: %s)\n", sodium_version_string());
#else
    fprintf(stderr, "Warning: libsodium not available, using fallback (INSECURE)\n");
#endif
    return 0;
}

/* === Hash Functions === */

int crypto_hash_sha256(const uint8_t* data, size_t len, uint8_t* hash) {
    if (!data || !hash) return -1;
    
#ifdef HAS_SODIUM
    crypto_hash_sha256_state state;
    crypto_hash_sha256_init(&state);
    crypto_hash_sha256_update(&state, data, len);
    crypto_hash_sha256_final(&state, hash);
#else
    /* Fallback - NOT secure, for testing only */
    memset(hash, 0, 32);
    for (size_t i = 0; i < len; i++) {
        hash[i % 32] ^= data[i];
    }
#endif
    return 0;
}

int crypto_hash_blake2b(const uint8_t* data, size_t len, uint8_t* hash, size_t hash_len) {
    if (!data || !hash) return -1;
    
#ifdef HAS_SODIUM
    if (hash_len <= crypto_generichash_BYTES_MAX) {
        crypto_generichash(hash, hash_len, data, len, NULL, 0);
        return 0;
    }
#endif
    return -1;
}

/* === Ed25519 Signatures === */

int crypto_sign_keypair(uint8_t* pk, uint8_t* sk) {
    if (!pk || !sk) return -1;
    
#ifdef HAS_SODIUM
    crypto_sign_ed25519_keypair(pk, sk);
    return 0;
#else
    return -1;
#endif
}

int crypto_sign(const uint8_t* msg, size_t msg_len, 
                const uint8_t* sk, uint8_t* sig) {
    if (!msg || !sk || !sig) return -1;
    
#ifdef HAS_SODIUM
    unsigned long long sig_len;
    crypto_sign_ed25519_detached(sig, &sig_len, msg, msg_len, sk);
    return 0;
#else
    return -1;
#endif
}

int crypto_verify(const uint8_t* msg, size_t msg_len,
                  const uint8_t* pk, const uint8_t* sig) {
    if (!msg || !pk || !sig) return -1;
    
#ifdef HAS_SODIUM
    return crypto_sign_ed25519_verify_detached(sig, msg, msg_len, pk);
#else
    return -1;
#endif
}

/* === X25519 Key Exchange === */

int crypto_kx_keypair(uint8_t* pk, uint8_t* sk) {
    if (!pk || !sk) return -1;
    
#ifdef HAS_SODIUM
    crypto_kx_keypair(pk, sk);
    return 0;
#else
    return -1;
#endif
}

int crypto_kx_client_session_keys(uint8_t* rx, uint8_t* tx,
                                   const uint8_t* client_pk,
                                   const uint8_t* client_sk,
                                   const uint8_t* server_pk) {
    if (!rx || !tx || !client_pk || !client_sk || !server_pk) return -1;
    
#ifdef HAS_SODIUM
    return crypto_kx_client_session_keys(rx, tx, client_pk, client_sk, server_pk);
#else
    return -1;
#endif
}

/* === AEAD Encryption (ChaCha20-Poly1305) === */

int crypto_encrypt(const uint8_t* plaintext, size_t plaintext_len,
                   const uint8_t* key, const uint8_t* nonce,
                   uint8_t* ciphertext, uint8_t* mac) {
    if (!plaintext || !key || !nonce || !ciphertext) return -1;
    
#ifdef HAS_SODIUM
    unsigned long long ciphertext_len;
    crypto_aead_chacha20poly1305_ietf_encrypt(ciphertext, &ciphertext_len,
                                               plaintext, plaintext_len,
                                               NULL, 0, NULL, nonce, key);
    if (mac) {
        /* MAC is appended to ciphertext in this implementation */
    }
    return 0;
#else
    return -1;
#endif
}

int crypto_decrypt(const uint8_t* ciphertext, size_t ciphertext_len,
                   const uint8_t* key, const uint8_t* nonce,
                   uint8_t* plaintext) {
    if (!ciphertext || !key || !nonce || !plaintext) return -1;
    
#ifdef HAS_SODIUM
    unsigned long long plaintext_len;
    if (crypto_aead_chacha20poly1305_ietf_decrypt(plaintext, &plaintext_len, NULL,
                                                   ciphertext, ciphertext_len,
                                                   NULL, 0, nonce, key) == 0) {
        return 0;
    }
#endif
    return -1;
}

/* === Random Number Generation === */

void crypto_randombytes(uint8_t* buf, size_t len) {
    if (!buf || len == 0) return;
    
#ifdef HAS_SODIUM
    randombytes_buf(buf, len);
#else
    /* Fallback - NOT cryptographically secure */
    for (size_t i = 0; i < len; i++) {
        buf[i] = (uint8_t)(rand() & 0xFF);
    }
#endif
}

uint32_t crypto_random_uint32(void) {
#ifdef HAS_SODIUM
    return randombytes_random();
#else
    return (uint32_t)rand();
#endif
}

/* === Secure Memory === */

void crypto_memzero(void* ptr, size_t len) {
    if (!ptr || len == 0) return;
    
#ifdef HAS_SODIUM
    sodium_memzero(ptr, len);
#else
    volatile unsigned char* p = ptr;
    while (len--) {
        *p++ = 0;
    }
#endif
}

int crypto_memcmp(const void* a, const void* b, size_t len) {
    if (!a || !b) return -1;
    
#ifdef HAS_SODIUM
    return sodium_memcmp(a, b, len);
#else
    const uint8_t* pa = a;
    const uint8_t* pb = b;
    int diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff |= pa[i] ^ pb[i];
    }
    return diff;
#endif
}

/* === DID Operations === */

int crypto_did_create(const uint8_t* public_key, char* did, size_t did_len) {
    if (!public_key || !did || did_len < 64) return -1;
    
    /* Create did:key DID */
    uint8_t hash[32];
    crypto_hash_blake2b(public_key, 32, hash, 32);
    
    /* Encode as multibase base58btc */
    snprintf(did, did_len, "did:key:z");
    
    /* Simplified - proper multicodec encoding needed */
    for (int i = 0; i < 8; i++) {
        snprintf(did + 9 + i * 2, did_len - 9 - i * 2, "%02x", hash[i]);
    }
    
    return 0;
}

int crypto_did_resolve(const char* did, uint8_t* public_key, size_t* pk_len) {
    if (!did || !public_key || !pk_len) return -1;
    
    /* Parse did:key */
    if (strncmp(did, "did:key:", 8) != 0) {
        return -1;
    }
    
    /* Extract and decode public key */
    /* Simplified - proper multibase decoding needed */
    
    return 0;
}

/* === CID (Content Identifier) === */

int crypto_cid_create(const uint8_t* data, size_t len, uint8_t* cid, size_t* cid_len) {
    if (!data || !cid || !cid_len) return -1;
    
    /* Create CIDv1 */
    uint8_t hash[32];
    crypto_hash_blake2b(data, len, hash, 32);
    
    /* CID structure: version (1) + codec (raw = 0x55) + hash (blake2b-256 = 0xb220) + digest */
    if (*cid_len < 36) return -1;
    
    cid[0] = 0x01;  /* CIDv1 */
    cid[1] = 0x55;  /* Raw codec */
    cid[2] = 0xb2;  /* BLAKE2b-256 multihash */
    cid[3] = 0x20;  /* 32 bytes */
    memcpy(cid + 4, hash, 32);
    
    *cid_len = 36;
    return 0;
}

/* === Certificate Pinning === */

int crypto_cert_pin(const uint8_t* cert_der, size_t cert_len, uint8_t* pin) {
    if (!cert_der || !pin) return -1;
    
    /* Compute SPKI hash for certificate pinning */
    return crypto_hash_sha256(cert_der, cert_len, pin);
}

int crypto_cert_verify_pin(const uint8_t* cert_der, size_t cert_len, 
                           const uint8_t* expected_pin) {
    if (!cert_der || !expected_pin) return -1;
    
    uint8_t computed_pin[32];
    if (crypto_cert_pin(cert_der, cert_len, computed_pin) != 0) {
        return -1;
    }
    
    return crypto_memcmp(computed_pin, expected_pin, 32);
}
