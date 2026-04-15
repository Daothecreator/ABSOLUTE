/*
 * IPFS/IPVM Distribution System
 * Content-addressed, decentralized application distribution
 * 
 * License: MIT
 * Version: 1.0 (April 2026)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

/* === Constants === */

#define IPFS_CID_VERSION 1
#define IPFS_HASH_SHA256 0x12
#define IPFS_CODEC_DAG_PB 0x70
#define IPFS_CODEC_RAW 0x55
#define MULTIBASE_BASE32 0x62 /* 'b' */

#define MAX_CID_LENGTH 128
#define MAX_BLOCK_SIZE 262144 /* 256KB */

/* === Data Structures === */

typedef struct ipfs_block_s {
    uint8_t *data;
    size_t size;
    uint8_t hash[32];
    struct ipfs_block_s **links;
    size_t link_count;
} ipfs_block_t;

typedef struct ipfs_dag_s {
    ipfs_block_t *root;
    uint8_t root_hash[32];
    char cid[MAX_CID_LENGTH];
    size_t total_size;
    size_t block_count;
} ipfs_dag_t;

typedef struct ipfs_node_s {
    char multiaddr[256];
    bool is_connected;
    uint64_t last_seen;
} ipfs_node_t;

typedef struct ipfs_distribution_s {
    ipfs_dag_t *widget_dag;
    ipfs_node_t **peers;
    size_t peer_count;
    
    /* Local cache */
    ipfs_block_t **cache;
    size_t cache_size;
    size_t cache_capacity;
} ipfs_distribution_t;

/* === Base32 Encoding (for CID) === */

static const char BASE32_ALPHABET[] = "abcdefghijklmnopqrstuvwxyz234567";

static char* base32_encode(const uint8_t *data, size_t len) {
    size_t output_len = ((len * 8) + 4) / 5;
    char *output = malloc(output_len + 1);
    if (!output) return NULL;
    
    size_t i = 0, j = 0;
    uint32_t buffer = 0;
    int bits_left = 0;
    
    while (i < len || bits_left > 0) {
        if (bits_left < 5) {
            if (i < len) {
                buffer = (buffer << 8) | data[i++];
                bits_left += 8;
            } else {
                buffer <<= (5 - bits_left);
                bits_left = 5;
            }
        }
        
        output[j++] = BASE32_ALPHABET[(buffer >> (bits_left - 5)) & 0x1F];
        bits_left -= 5;
    }
    
    output[j] = '\0';
    return output;
}

/* === CID Generation === */

char* ipfs_generate_cid_v1(const uint8_t *hash, size_t hash_len,
                            uint64_t codec) {
    /* CID v1 structure:
       <multibase><cid-version><multicodec-content-type><multihash>
    */
    
    /* Build CID bytes */
    uint8_t cid_bytes[64];
    size_t cid_len = 0;
    
    /* CID version */
    cid_bytes[cid_len++] = IPFS_CID_VERSION;
    
    /* Content codec (varint) */
    uint64_t codec_val = codec;
    while (codec_val >= 0x80) {
        cid_bytes[cid_len++] = (codec_val & 0x7F) | 0x80;
        codec_val >>= 7;
    }
    cid_bytes[cid_len++] = codec_val;
    
    /* Multihash */
    cid_bytes[cid_len++] = IPFS_HASH_SHA256;
    cid_bytes[cid_len++] = hash_len;
    memcpy(cid_bytes + cid_len, hash, hash_len);
    cid_len += hash_len;
    
    /* Base32 encode with multibase prefix */
    char *encoded = base32_encode(cid_bytes, cid_len);
    if (!encoded) return NULL;
    
    /* Prepend multibase prefix */
    char *cid = malloc(strlen(encoded) + 2);
    if (cid) {
        cid[0] = 'b'; /* base32 prefix */
        strcpy(cid + 1, encoded);
    }
    
    free(encoded);
    return cid;
}

/* === Block Operations === */

ipfs_block_t* ipfs_block_create(const uint8_t *data, size_t size) {
    ipfs_block_t *block = calloc(1, sizeof(ipfs_block_t));
    if (!block) return NULL;
    
    block->data = malloc(size);
    if (!block->data) {
        free(block);
        return NULL;
    }
    
    memcpy(block->data, data, size);
    block->size = size;
    
    /* Compute hash */
    SHA256(block->data, block->size, block->hash);
    
    return block;
}

void ipfs_block_destroy(ipfs_block_t *block) {
    if (!block) return;
    
    free(block->data);
    
    for (size_t i = 0; i < block->link_count; i++) {
        ipfs_block_destroy(block->links[i]);
    }
    free(block->links);
    
    free(block);
}

/* === DAG Building === */

ipfs_dag_t* ipfs_dag_create(const uint8_t *data, size_t size) {
    ipfs_dag_t *dag = calloc(1, sizeof(ipfs_dag_t));
    if (!dag) return NULL;
    
    /* For small data, create single block */
    if (size <= MAX_BLOCK_SIZE) {
        dag->root = ipfs_block_create(data, size);
        if (!dag->root) {
            free(dag);
            return NULL;
        }
        
        memcpy(dag->root_hash, dag->root->hash, 32);
        dag->total_size = size;
        dag->block_count = 1;
    } else {
        /* For large data, create chunked DAG */
        /* In full implementation, would create balanced tree of blocks */
        
        size_t num_chunks = (size + MAX_BLOCK_SIZE - 1) / MAX_BLOCK_SIZE;
        
        dag->root = calloc(1, sizeof(ipfs_block_t));
        dag->root->links = calloc(num_chunks, sizeof(ipfs_block_t*));
        dag->root->link_count = num_chunks;
        
        for (size_t i = 0; i < num_chunks; i++) {
            size_t chunk_offset = i * MAX_BLOCK_SIZE;
            size_t chunk_size = (chunk_offset + MAX_BLOCK_SIZE > size) ?
                                (size - chunk_offset) : MAX_BLOCK_SIZE;
            
            dag->root->links[i] = ipfs_block_create(data + chunk_offset, chunk_size);
            dag->total_size += chunk_size;
            dag->block_count++;
        }
        
        /* Compute root hash from links */
        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        EVP_DigestInit(ctx, EVP_sha256());
        
        for (size_t i = 0; i < num_chunks; i++) {
            EVP_DigestUpdate(ctx, dag->root->links[i]->hash, 32);
        }
        
        EVP_DigestFinal(ctx, dag->root_hash, NULL);
        EVP_MD_CTX_free(ctx);
    }
    
    /* Generate CID */
    char *cid = ipfs_generate_cid_v1(dag->root_hash, 32, IPFS_CODEC_RAW);
    if (cid) {
        strncpy(dag->cid, cid, MAX_CID_LENGTH - 1);
        free(cid);
    }
    
    return dag;
}

void ipfs_dag_destroy(ipfs_dag_t *dag) {
    if (!dag) return;
    
    ipfs_block_destroy(dag->root);
    free(dag);
}

/* === Distribution Operations === */

ipfs_distribution_t* ipfs_distribution_create(void) {
    ipfs_distribution_t *dist = calloc(1, sizeof(ipfs_distribution_t));
    if (!dist) return NULL;
    
    dist->cache_capacity = 1000;
    dist->cache = calloc(dist->cache_capacity, sizeof(ipfs_block_t*));
    
    return dist;
}

void ipfs_distribution_destroy(ipfs_distribution_t *dist) {
    if (!dist) return NULL;
    
    ipfs_dag_destroy(dist->widget_dag);
    
    for (size_t i = 0; i < dist->peer_count; i++) {
        free(dist->peers[i]);
    }
    free(dist->peers);
    
    for (size_t i = 0; i < dist->cache_size; i++) {
        ipfs_block_destroy(dist->cache[i]);
    }
    free(dist->cache);
    
    free(dist);
}

/* Add widget to distribution */
int ipfs_distribution_publish_widget(ipfs_distribution_t *dist,
                                        const uint8_t *wasm_binary,
                                        size_t wasm_size) {
    if (!dist || !wasm_binary) return -1;
    
    /* Create DAG from WASM binary */
    dist->widget_dag = ipfs_dag_create(wasm_binary, wasm_size);
    if (!dist->widget_dag) return -1;
    
    printf("[IPFS] Widget published with CID: %s\n", dist->widget_dag->cid);
    printf("[IPFS] Total size: %zu bytes in %zu blocks\n",
           dist->widget_dag->total_size, dist->widget_dag->block_count);
    
    return 0;
}

/* Verify widget integrity */
bool ipfs_distribution_verify_widget(ipfs_distribution_t *dist,
                                      const char *expected_cid) {
    if (!dist || !dist->widget_dag || !expected_cid) return false;
    
    bool valid = (strcmp(dist->widget_dag->cid, expected_cid) == 0);
    
    if (valid) {
        printf("[IPFS] Widget CID verified: %s\n", expected_cid);
    } else {
        printf("[IPFS] CID mismatch! Expected: %s, Got: %s\n",
               expected_cid, dist->widget_dag->cid);
    }
    
    return valid;
}

/* === P2P Networking (Simplified) === */

int ipfs_distribution_add_peer(ipfs_distribution_t *dist,
                                const char *multiaddr) {
    if (!dist || !multiaddr) return -1;
    
    ipfs_node_t *node = calloc(1, sizeof(ipfs_node_t));
    strncpy(node->multiaddr, multiaddr, sizeof(node->multiaddr) - 1);
    node->is_connected = false;
    
    dist->peers = realloc(dist->peers, 
                          (dist->peer_count + 1) * sizeof(ipfs_node_t*));
    dist->peers[dist->peer_count++] = node;
    
    printf("[IPFS] Added peer: %s\n", multiaddr);
    
    return 0;
}

/* Announce widget to network */
int ipfs_distribution_announce(ipfs_distribution_t *dist) {
    if (!dist || !dist->widget_dag) return -1;
    
    printf("[IPFS] Announcing widget CID to %zu peers...\n", dist->peer_count);
    
    for (size_t i = 0; i < dist->peer_count; i++) {
        printf("[IPFS] Announcing to %s: %s\n",
               dist->peers[i]->multiaddr, dist->widget_dag->cid);
    }
    
    return 0;
}

/* Fetch widget from network */
ipfs_dag_t* ipfs_distribution_fetch(ipfs_distribution_t *dist,
                                     const char *cid) {
    if (!dist || !cid) return NULL;
    
    printf("[IPFS] Fetching widget with CID: %s\n", cid);
    
    /* In full implementation, would:
       1. Query DHT for providers of CID
       2. Connect to peers
       3. Download blocks
       4. Verify hashes
       5. Reconstruct DAG
    */
    
    /* For now, check local cache */
    if (dist->widget_dag && strcmp(dist->widget_dag->cid, cid) == 0) {
        printf("[IPFS] Widget found in local cache\n");
        return dist->widget_dag;
    }
    
    printf("[IPFS] Widget not found locally, would fetch from network\n");
    
    return NULL;
}

/* === IPVM Integration === */

/* Execute widget in IPVM */
int ipfs_distribution_execute_widget(ipfs_distribution_t *dist) {
    if (!dist || !dist->widget_dag) return -1;
    
    printf("[IPVM] Loading widget from CID: %s\n", dist->widget_dag->cid);
    
    /* In full implementation, would:
       1. Load WASM binary from DAG
       2. Instantiate in Wasmtime
       3. Start monitoring
    */
    
    printf("[IPVM] Widget execution started\n");
    
    return 0;
}

/* === Bootstrap Nodes === */

static const char* BOOTSTRAP_NODES[] = {
    "/dnsaddr/bootstrap.libp2p.io/p2p/QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN",
    "/dnsaddr/bootstrap.libp2p.io/p2p/QmQCU2EcMqAqQPR2i9bChDtGNJchTbq5TbXJJ16u19uLTa",
    "/dnsaddr/bootstrap.libp2p.io/p2p/QmbLHAnMoJPWSCR5Zhtx6BHJX9KiKNN6tpvbUcqanj75Nb",
    NULL
};

int ipfs_distribution_connect_bootstrap(ipfs_distribution_t *dist) {
    if (!dist) return -1;
    
    printf("[IPFS] Connecting to bootstrap nodes...\n");
    
    for (int i = 0; BOOTSTRAP_NODES[i]; i++) {
        ipfs_distribution_add_peer(dist, BOOTSTRAP_NODES[i]);
    }
    
    return 0;
}
