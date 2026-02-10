# Environment Variables Encryption/Decryption Sequence

## Overview

Environment variables are encrypted **by the operator** (via `vmm-cli.py`) before deployment, and decrypted **inside the CVM** at boot time. Neither the VMM nor the KMS ever see the plaintext env vars.

## Sequence Diagram

```mermaid
sequenceDiagram
    participant Op as Operator<br/>(vmm-cli.py)
    participant KMS as KMS
    participant VMM as VMM (Host)
    participant CVM as App CVM<br/>(dstack-util)

    Note over Op,KMS: Phase 1: Get Encryption Public Key

    Op->>Op: Calculate app_id<br/>from docker-compose.yaml
    Op->>KMS: GetAppEnvEncryptPubKey(app_id)

    Note over KMS: Derive env encryption key pair
    KMS->>KMS: secret = HKDF(ca_key, app_id + "env-encrypt-key")
    KMS->>KMS: env_private_key = X25519PrivateKey(secret)
    KMS->>KMS: env_public_key = X25519PublicKey(env_private_key)
    KMS->>KMS: Sign public key with k256_root:<br/>sig = Sign(k256_root,<br/>"dstack-env-encrypt-pubkey" +<br/>app_id + timestamp + env_public_key)
    KMS-->>Op: env_public_key + signature + timestamp

    Op->>Op: Verify signature<br/>(check k256 signer against whitelist)

    Note over Op: Phase 2: Encrypt Env Vars

    Op->>Op: Read .env file<br/>→ [{"key":"DB_PASS","value":"secret123"}, ...]
    Op->>Op: Serialize to JSON:<br/>{"env": [{"key":"DB_PASS","value":"secret123"}]}

    Note over Op: X25519 Key Exchange
    Op->>Op: Generate ephemeral X25519 key pair:<br/>eph_private_key (random)<br/>eph_public_key = X25519PublicKey(eph_private_key)
    Op->>Op: Compute shared secret:<br/>shared = X25519_DH(eph_private_key, env_public_key)

    Note over Op: AES-256-GCM Encryption
    Op->>Op: Generate random IV (12 bytes)
    Op->>Op: ciphertext = AES-256-GCM.encrypt(<br/>  key = shared,<br/>  iv = IV,<br/>  plaintext = JSON bytes<br/>)

    Note over Op: Pack encrypted blob
    Op->>Op: encrypted_env = eph_public_key (32 bytes)<br/>  || IV (12 bytes)<br/>  || ciphertext (N bytes)

    Note over Op,VMM: Phase 3: Deploy with Encrypted Env

    Op->>VMM: CreateVm({<br/>  compose: app-compose.json,<br/>  encrypted_env: hex(encrypted_env)<br/>})
    VMM->>VMM: Store encrypted_env<br/>in host-shared/<br/>(NEVER decrypted by VMM)

    Note over VMM,CVM: Phase 4: CVM Boot

    VMM->>CVM: Start CVM (TDX)
    CVM->>CVM: Load encrypted_env<br/>from host-shared/

    Note over CVM,KMS: Phase 5: Get Decryption Key from KMS

    CVM->>KMS: GetAppKey(vm_config)<br/>via mTLS with TDX attestation
    KMS->>KMS: Verify attestation + auth check
    KMS->>KMS: Derive env_crypt_key:<br/>secret = HKDF(ca_key, app_id + "env-encrypt-key")<br/>env_crypt_key = X25519PrivateKey(secret).to_bytes()
    KMS-->>CVM: AppKeyResponse<br/>(..., env_crypt_key, ...)

    Note over CVM: Phase 6: Decrypt Env Vars

    Note over CVM: Parse encrypted blob
    CVM->>CVM: Extract from encrypted_env:<br/>eph_public_key = bytes[0..32]<br/>IV = bytes[32..44]<br/>ciphertext = bytes[44..]

    Note over CVM: X25519 Key Agreement
    CVM->>CVM: Compute shared secret:<br/>shared = X25519_DH(env_crypt_key, eph_public_key)

    Note over CVM: AES-256-GCM Decryption
    CVM->>CVM: plaintext = AES-256-GCM.decrypt(<br/>  key = shared,<br/>  iv = IV,<br/>  ciphertext = ciphertext<br/>)

    CVM->>CVM: Parse JSON:<br/>{"env": [{"key":"DB_PASS","value":"secret123"}]}
    CVM->>CVM: Filter by allowed_envs<br/>(from app-compose.json)
    CVM->>CVM: Write to /dstack/.decrypted_env<br/>and /dstack/.decrypted_env.json

    Note over CVM: Env vars available to<br/>docker-compose containers
```

## Cryptographic Details

### Key Derivation (KMS side)

The KMS derives **the same X25519 key pair** for both `GetAppEnvEncryptPubKey` (returns public key) and `GetAppKey` (returns private key):

```
secret = HKDF(ca_key, app_id || "env-encrypt-key")   // 32 bytes
env_private_key = X25519PrivateKey(secret)
env_public_key  = X25519PublicKey(env_private_key)
```

- `GetAppEnvEncryptPubKey` → returns `env_public_key` (to operator for encryption)
- `GetAppKey` → returns `env_private_key` as `env_crypt_key` (to CVM for decryption)

### Encryption (Operator side - vmm-cli.py)

```
eph_sk, eph_pk = X25519.generate()           // ephemeral key pair
shared = X25519_DH(eph_sk, env_public_key)   // 32-byte shared secret
IV = random(12)                               // 12-byte nonce
ciphertext = AES-256-GCM(shared, IV, JSON)   // authenticated encryption
output = eph_pk || IV || ciphertext           // concatenated blob
```

### Decryption (CVM side - dstack-util)

```
eph_pk     = output[0..32]                    // extract ephemeral public key
IV         = output[32..44]                   // extract nonce
ciphertext = output[44..]                     // extract ciphertext
shared = X25519_DH(env_crypt_key, eph_pk)     // same shared secret
plaintext = AES-256-GCM.decrypt(shared, IV, ciphertext)
```

### Why This Works

The shared secret is identical on both sides because of the X25519 Diffie-Hellman property:

```
X25519_DH(eph_sk, env_public_key) == X25519_DH(env_crypt_key, eph_pk)
```

Both compute the same elliptic curve point: `eph_sk * env_private_key * G`

## Security Properties

| Property | Guarantee |
|----------|-----------|
| **Confidentiality** | Only someone with `env_crypt_key` (= the CVM after KMS attestation) can decrypt |
| **Forward secrecy** | Each encryption uses an ephemeral key; compromising `env_crypt_key` later doesn't reveal previous ciphertexts without the ephemeral private key (which is discarded) |
| **Integrity** | AES-GCM provides authenticated encryption — tampering is detected |
| **VMM blindness** | The VMM only sees the encrypted blob, never the plaintext |
| **KMS blindness** | The KMS never sees the encrypted env vars — it only provides keys |
| **App-specific** | Each app has a unique `env_crypt_key` derived from its `app_id` |
| **Instance-shared** | All instances of the same app share the same `env_crypt_key` (derived from `app_id` only, not `instance_id`) |

## Data Flow Summary

```
Operator                    KMS                      VMM              CVM
   │                         │                        │                │
   │──GetAppEnvEncryptPubKey─▶│                        │                │
   │◀──env_public_key────────│                        │                │
   │                         │                        │                │
   │  encrypt(env_vars,      │                        │                │
   │    env_public_key)       │                        │                │
   │──CreateVm(encrypted)───────────────────────────▶│                │
   │                         │                        │──encrypted────▶│
   │                         │                        │                │
   │                         │◀──GetAppKey(attestation)───────────────│
   │                         │──env_crypt_key────────────────────────▶│
   │                         │                        │                │
   │                         │                        │      decrypt(encrypted,
   │                         │                        │       env_crypt_key)
   │                         │                        │         = env_vars
```
