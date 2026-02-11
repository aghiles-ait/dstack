# dstack KMS API Documentation

This document describes the KMS API endpoints that can be called from the host machine (or any external client). Endpoints that require TDX attestation (mTLS with RA-TLS client certificate) are listed at the end for reference but cannot be called with plain `curl`.

## Overview

The KMS exposes two services on the same HTTPS port, but at different lifecycle stages:

1. **Onboard Service** — available only during initial setup (before keys are generated)
2. **KMS Service** — available after onboarding is complete (normal operation)

Both services use the `/prpc` prefix for RPC endpoints.

## Base URL

The KMS listens on **HTTPS** port 8000 inside the CVM, typically mapped to port **9201** on the host:

```
https://<kms-host>:9201
```

Since the KMS uses a self-signed TLS certificate, you must use `-k` (or `--insecure`) with `curl`:

```bash
# Example
curl -sk https://localhost:9201/prpc/GetMeta -d '{}' | jq
```

> **Note**: mTLS is configured with `mandatory = false`, which means unauthenticated clients can connect. However, endpoints that require attestation (like `GetAppKey`) will reject the request at the application level if no valid RA-TLS client certificate is presented.

---

## KMS RPC API (Normal Operation)

These endpoints are available after the KMS has completed onboarding and is running normally. All use `POST` method with JSON body.

### 1. GetMeta

Returns KMS instance metadata. Useful as a health check and to retrieve the KMS's CA certificate, k256 public key, and configuration info.

**Endpoint:** `POST /prpc/GetMeta`

**Request:** empty `{}`

**Example:**

```bash
curl -sk https://localhost:9201/prpc/GetMeta -d '{}' | jq
```

**Response:**

```json
{
  "ca_cert": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n",
  "allow_any_upgrade": false,
  "k256_pubkey": "<hex-encoded-secp256k1-public-key>",
  "bootstrap_info": {
    "ca_pubkey": "<hex-encoded-ca-public-key-der>",
    "k256_pubkey": "<hex-encoded-k256-public-key>",
    "attestation": "<hex-encoded-attestation>"
  },
  "is_dev": false,
  "gateway_app_id": "<hex-encoded-gateway-app-id>",
  "kms_contract_address": "0x...",
  "chain_id": "1",
  "app_auth_implementation": "..."
}
```

**Response Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `ca_cert` | string | PEM-encoded Root CA certificate of this KMS instance |
| `allow_any_upgrade` | boolean | Whether any upgrade is allowed (dev mode) |
| `k256_pubkey` | string (hex) | secp256k1 public key (SEC1 compressed format) |
| `bootstrap_info` | object | Bootstrap attestation info (CA pubkey, k256 pubkey, TDX attestation) |
| `is_dev` | boolean | Whether the KMS is running in dev mode |
| `gateway_app_id` | string | The app ID of the gateway (if configured) |
| `kms_contract_address` | string | Ethereum contract address (if using on-chain auth) |
| `chain_id` | string | Ethereum chain ID (if using on-chain auth) |
| `app_auth_implementation` | string | The auth implementation type |

**Use cases:**
- Health check / readiness probe
- Retrieve the KMS CA certificate for trust chain verification
- Get `k256_pubkey` for verifying signatures from `GetAppEnvEncryptPubKey`
- Get `bootstrap_info.ca_pubkey` to use as `key_provider_id` for app deployments

---

### 2. GetAppEnvEncryptPubKey

Returns the X25519 public key used to encrypt environment variables for a given app. The public key is deterministically derived from the KMS root CA key and the app ID, so the same app ID always yields the same key.

**Endpoint:** `POST /prpc/GetAppEnvEncryptPubKey`

**Request Parameters:**

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `app_id` | string (hex) | The application ID (32 bytes, hex-encoded) | `"a1b2c3..."` |

**Example:**

```bash
# Get the encryption public key for an app
curl -sk https://localhost:9201/prpc/GetAppEnvEncryptPubKey \
  -H 'Content-Type: application/json' \
  -d '{
    "app_id": "a1b2c3d4e5f6..."
  }' | jq
```

**Response:**

```json
{
  "public_key": "<hex-encoded-x25519-public-key>",
  "signature": "<hex-encoded-legacy-signature>",
  "timestamp": "1739290000",
  "signature_v1": "<hex-encoded-signed-with-timestamp>"
}
```

**Response Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `public_key` | string (hex) | X25519 public key (32 bytes) for encrypting env vars |
| `signature` | string (hex) | Legacy signature: `Sign(k256_key, Keccak256("dstack-env-encrypt-pubkey" + ":" + app_id + public_key))` |
| `timestamp` | string | Unix timestamp (seconds) when the response was generated |
| `signature_v1` | string (hex) | Timestamped signature: `Sign(k256_key, Keccak256("dstack-env-encrypt-pubkey" + ":" + app_id + timestamp_be_bytes + public_key))` |

**Signature verification:**
- The `signature` and `signature_v1` are signed with the KMS root `k256_key`
- You can verify them against the `k256_pubkey` obtained from `GetMeta`
- `signature_v1` includes a timestamp to prevent replay attacks

**Use case:** used by `vmm-cli.py` (or any deployment tool) to encrypt environment variables before sending them to the VMM. The corresponding private key is only accessible to the CVM after TDX attestation (via `GetAppKey`).

---

### 3. GetTempCaCert

Returns the temporary CA certificate and key, along with the root CA certificate. This is used during the onboarding process of other KMS instances to generate RA-TLS certificates for mTLS.

**Endpoint:** `POST /prpc/GetTempCaCert`

**Request:** empty `{}`

**Example:**

```bash
curl -sk https://localhost:9201/prpc/GetTempCaCert -d '{}' | jq
```

**Response:**

```json
{
  "temp_ca_cert": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n",
  "temp_ca_key": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n",
  "ca_cert": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n"
}
```

**Response Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `temp_ca_cert` | string | PEM-encoded temporary CA certificate |
| `temp_ca_key` | string | PEM-encoded temporary CA private key |
| `ca_cert` | string | PEM-encoded root CA certificate |

> **Security note:** this endpoint returns a private key (`temp_ca_key`). It is intended for KMS-to-KMS onboarding only. The temp CA is used to sign RA-TLS client certificates that allow a new KMS instance to authenticate to this KMS via mTLS.

---

### 4. ClearImageCache

Clears the cached OS image files and/or measurement cache. Requires an admin token for authentication.

**Endpoint:** `POST /prpc/ClearImageCache`

**Request Parameters:**

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `token` | string | Admin token (plaintext). Its SHA-256 hash must match `admin_token_hash` in the KMS config | `"my-secret-admin-token"` |
| `image_hash` | string | Image hash to clear, or `"all"` to clear all images | `"all"` |
| `config_hash` | string | Config/measurement hash to clear, or `"all"` to clear all | `"all"` |

**Example:**

```bash
# Clear all cached images
curl -sk https://localhost:9201/prpc/ClearImageCache \
  -H 'Content-Type: application/json' \
  -d '{
    "token": "my-secret-admin-token",
    "image_hash": "all",
    "config_hash": "all"
  }'
```

**Response:** empty on success (HTTP 200)

**Error:** returns an error if the token is invalid:
```json
{
  "error": "Invalid token"
}
```

---

## Onboard RPC API (Initial Setup Only)

These endpoints are available **only during the initial onboarding phase** — before the KMS has generated or received its cryptographic keys. Once onboarding is complete, these endpoints are no longer accessible (the onboard service shuts down and the main KMS service starts).

The onboard service also serves a **web UI** at `GET /` for interactive bootstrap/onboard.

> **Note:** if `auto_bootstrap_domain` is set in the config, onboarding happens automatically and no web UI / RPC is exposed.

### 1. Bootstrap

Generates fresh cryptographic keys (CA key, k256 key, temp CA key, RPC key) for a new KMS instance. This is used when setting up the **first** KMS in a cluster.

**Endpoint:** `POST /prpc/Bootstrap`

**Request Parameters:**

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `domain` | string | The domain name that will serve this KMS's RPC | `"kms.example.com"` |

**Example:**

```bash
# Bootstrap a new KMS (only available during onboarding phase)
curl -sk https://localhost:9201/prpc/Bootstrap \
  -H 'Content-Type: application/json' \
  -d '{
    "domain": "kms.example.com"
  }' | jq
```

**Response:**

```json
{
  "ca_pubkey": "<hex-encoded-ca-public-key-der>",
  "k256_pubkey": "<hex-encoded-k256-public-key>",
  "attestation": "<hex-encoded-tdx-attestation>"
}
```

**Response Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `ca_pubkey` | string (hex) | DER-encoded public key of the newly generated root CA |
| `k256_pubkey` | string (hex) | SEC1-encoded secp256k1 public key |
| `attestation` | string (hex) | TDX attestation over the generated keys (empty if `quote_enabled = false`) |

**Use case:** the `ca_pubkey` returned here is the **key provider ID** that should be used in `--key-provider-id` when deploying CVMs against this KMS.

---

### 2. Onboard

Imports keys from an existing KMS instance. This is used when adding a **replica** KMS to an existing cluster. The new KMS connects to the source KMS, authenticates via RA-TLS (if `quote_enabled`), and receives the root keys.

**Endpoint:** `POST /prpc/Onboard`

**Request Parameters:**

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `source_url` | string | The `/prpc` URL of the existing KMS to onboard from | `"https://kms.example.com:9201/prpc"` |
| `domain` | string | The domain name for this new KMS instance | `"kms-replica.example.com"` |

**Example:**

```bash
# Onboard from an existing KMS (only available during onboarding phase)
curl -sk https://localhost:9201/prpc/Onboard \
  -H 'Content-Type: application/json' \
  -d '{
    "source_url": "https://kms.example.com:9201/prpc",
    "domain": "kms-replica.example.com"
  }' | jq
```

**Response:** empty `{}` on success

**Flow:**
1. The new KMS calls `GetTempCaCert` on the source KMS
2. It generates an RA-TLS certificate signed by the temp CA
3. It reconnects to the source KMS with mTLS (RA-TLS client cert)
4. It calls `GetKmsKey` to receive the root keys
5. Keys are stored locally and the onboard service is ready to finish

---

### 3. Finish

Finishes the onboarding process and shuts down the onboard service. After this, the main KMS service starts automatically.

**Endpoint:** `POST /prpc/Finish`

**Request:** empty `{}`

**Example:**

```bash
# Finish onboarding (only available during onboarding phase)
curl -sk https://localhost:9201/prpc/Finish -d '{}'
```

Alternatively, you can use the HTTP shortcut:

```bash
curl -sk https://localhost:9201/finish
```

**Response:** `"OK"` (plain text)

---

### 4. Web UI

During onboarding, a web UI is served at the root URL for interactive bootstrap or onboard.

**Endpoint:** `GET /`

**Example:**

```bash
# Open in browser
open https://localhost:9201/
```

---

## CVM-Only Endpoints (Not Callable from Host)

The following endpoints exist on the KMS but **require TDX attestation** (via RA-TLS mTLS client certificate). They cannot be called with plain `curl` from the host — they are used internally by CVMs during their boot process.

| Endpoint | Purpose | Requires |
|----------|---------|----------|
| `GetAppKey` | Returns disk encryption key, env decryption key, k256 key, and CA cert for a CVM | mTLS with RA-TLS client cert + auth-simple approval |
| `GetKmsKey` | Returns root KMS keys for KMS-to-KMS onboarding | mTLS with RA-TLS client cert (if `quote_enabled`) |
| `SignCert` | Signs a certificate for a CVM (used for gateway registration) | TDX attestation embedded in the CSR + auth-simple approval |

---

## Error Responses

All endpoints may return the following HTTP status codes:

- `200 OK` — request successful
- `400 Bad Request` — invalid request parameters
- `500 Internal Server Error` — server-side error

Error responses include a JSON body:

```json
{
  "error": "error description"
}
```

## Ports Summary

| Service | CVM Port | Typical Host Port | Protocol |
|---------|----------|-------------------|----------|
| KMS RPC (main + onboard) | 8000 | 9201 | HTTPS (self-signed) |
| auth-simple | 8001 | configurable | HTTP (internal) |
| Guest Agent | 8090 | 9205 | HTTP |
