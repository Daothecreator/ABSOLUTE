# ABSOLUTE Vault Format (MVP)

## Purpose

Define a portable local storage format for secrets, policy state and append-only audit anchors.

## KDF

- Algorithm: `argon2id`
- Parameters (MVP default):
  - memory: `64 MiB`
  - iterations: `3`
  - parallelism: `2`
- Salt: `16 bytes` random

## Encryption

- Algorithm: `chacha20-poly1305`
- Nonce: `12 bytes` random per object
- AAD: `vault_version || object_path || created_at`

## Container

```json
{
  "version": "0.1",
  "kdf": {
    "name": "argon2id",
    "memory_mib": 64,
    "iterations": 3,
    "parallelism": 2,
    "salt_b64": "..."
  },
  "objects": [
    {
      "path": "policies/current.json",
      "algo": "chacha20-poly1305",
      "nonce_b64": "...",
      "ciphertext_b64": "...",
      "tag_b64": "..."
    }
  ],
  "recovery": {
    "mnemonic_words": 24,
    "checksum": "bip39"
  }
}
```
