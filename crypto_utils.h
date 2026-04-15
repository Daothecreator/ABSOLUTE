/*
 * Cryptographic Utilities Header
 * 
 * Part of Sovereign Privacy Widget
 * License: MIT
 */

#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* === Constants === */
#define CRYPTO_HASH_SHA256_BYTES    32
#define CRYPTO_HASH_BLAKE2B_BYTES   32
#define CRYPTO_SIGN_ED25519_PK_BYTES 32
#define CRYPTO_SIGN_ED25519_SK_BYTES 64
#define CRYPTO_SIGN_ED25519_SIG_BYTES 64
#define CRYPTO_KX_PK_BYTES          32
#define CRYPTO_KX_SK_BYTES          32
#define CRYPTO_AEAD_KEY_BYTES       32
#define CRYPTO_AEAD_NONCE_BYTES     12
#define CRYPTO_AEAD_MAC_BYTES       16
#define CRYPTO_DID_MAX_LEN          256
#define CRYPTO_CID_MAX_BYTES        64

/* === Initialization === */
int crypto_init(void);

/* === Hash Functions === */
int crypto_hash_sha256(const uint8_t* data, size_t len, uint8_t* hash);
int crypto_hash_blake2b(const uint8_t* data, size_t len, uint8_t* hash, size_t hash_len);

/* === Ed25519 Signatures === */
int crypto_sign_keypair(uint8_t* pk, uint8_t* sk);
int crypto_sign(const uint8_t* msg, size_t msg_len, 
                const uint8_t* sk, uint8_t* sig);
int crypto_verify(const uint8_t* msg, size_t msg_len,
                  const uint8_t* pk, const uint8_t* sig);

/* === X25519 Key Exchange === */
int crypto_kx_keypair(uint8_t* pk, uint8_t* sk);
int crypto_kx_client_session_keys(uint8_t* rx, uint8_t* tx,
                                   const uint8_t* client_pk,
                                   const uint8_t* client_sk,
                                   const uint8_t* server_pk);

/* === AEAD Encryption === */
int crypto_encrypt(const uint8_t* plaintext, size_t plaintext_len,
                   const uint8_t* key, const uint8_t* nonce,
                   uint8_t* ciphertext, uint8_t* mac);
int crypto_decrypt(const uint8_t* ciphertext, size_t ciphertext_len,
                   const uint8_t* key, const uint8_t* nonce,
                   uint8_t* plaintext);

/* === Random Number Generation === */
void crypto_randombytes(uint8_t* buf, size_t len);
uint32_t crypto_random_uint32(void);

/* === Secure Memory === */
void crypto_memzero(void* ptr, size_t len);
int crypto_memcmp(const void* a, const void* b, size_t len);

/* === DID Operations === */
int crypto_did_create(const uint8_t* public_key, char* did, size_t did_len);
int crypto_did_resolve(const char* did, uint8_t* public_key, size_t* pk_len);

/* === CID Operations === */
int crypto_cid_create(const uint8_t* data, size_t len, uint8_t* cid, size_t* cid_len);

/* === Certificate Pinning === */
int crypto_cert_pin(const uint8_t* cert_der, size_t cert_len, uint8_t* pin);
int crypto_cert_verify_pin(const uint8_t* cert_der, size_t cert_len, 
                           const uint8_t* expected_pin);

#ifdef __cplusplus
}
#endif

#endif /* CRYPTO_UTILS_H */
