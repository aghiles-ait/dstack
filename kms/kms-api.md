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

## Guest Agent API (External — Port 8090/9205)

The Guest Agent runs inside every CVM (including the KMS CVM). It exposes an external HTTP server on port **8090** inside the CVM, typically mapped to port **9205** on the host. It provides the `Worker` RPC service and HTTP routes.

> **Note:** The Guest Agent also has an internal Unix socket API (`dstack.sock`) used by containers inside the CVM — those endpoints are not documented here as they are not accessible from the host.

### Base URL

```
http://<host-ip>:9205
```

---

### 1. Dashboard (Web UI)

Returns an HTML dashboard showing app info, containers, and system info.

**Endpoint:** `GET /`

**Example:**

```bash
curl -s http://localhost:9205/
```

**Response:** HTML page with app ID, instance ID, device ID, key provider info, running containers, and system metrics.

> **Note:** the level of detail shown depends on the `public_logs`, `public_sysinfo`, and `public_tcbinfo` flags in the app compose configuration.

---

### 2. Info

Returns application metadata: app ID, instance ID, device ID, certificates, TDX measurements, and VM configuration.

**Endpoint:** `POST /prpc/Info`

**Request:** empty `{}`

**Example:**

```bash
curl -s http://localhost:9205/prpc/Info -d '{}' | jq
```

**Response:**

```json
{
  "app_id": "<hex-encoded-app-id>",
  "instance_id": "<hex-encoded-instance-id>",
  "app_cert": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n",
  "tcb_info": "<json-string-with-mrtd-rtmrs-event-log>",
  "app_name": "kms",
  "device_id": "<hex-encoded-device-id>",
  "mr_aggregated": "<hex-encoded-mr-aggregated>",
  "os_image_hash": "<hex-encoded-os-image-hash>",
  "key_provider_info": "<key-provider-info>",
  "compose_hash": "<hex-encoded-compose-hash>",
  "vm_config": "<json-string-vm-config>",
  "cloud_vendor": "",
  "cloud_product": ""
}
```

**Response Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `app_id` | bytes (hex) | Application ID (derived from the key provider and compose hash) |
| `instance_id` | bytes (hex) | Unique instance ID for this CVM |
| `app_cert` | string | PEM-encoded app certificate (RA-TLS) |
| `tcb_info` | string (JSON) | TDX measurements (MRTD, RTMRs), event log, compose manifest — hidden if `public_tcbinfo = false` |
| `app_name` | string | Name of the deployed app |
| `device_id` | bytes (hex) | TDX device identifier |
| `mr_aggregated` | bytes (hex) | Aggregated measurement register |
| `os_image_hash` | bytes (hex) | SHA256 of the OS image's `sha256sum.txt` |
| `key_provider_info` | string | Key provider ID (KMS CA public key) |
| `compose_hash` | bytes (hex) | SHA256 of the app compose manifest |
| `vm_config` | string (JSON) | VM configuration (vCPUs, memory, image, etc.) |
| `cloud_vendor` | string | Cloud provider sys_vendor (e.g. "Google") |
| `cloud_product` | string | Cloud provider product_name (e.g. "Google Compute Engine") |

---

### 3. Version

Returns the Guest Agent version and git revision.

**Endpoint:** `POST /prpc/Version`

**Request:** empty `{}`

**Example:**

```bash
curl -s http://localhost:9205/prpc/Version -d '{}' | jq
```

**Response:**

```json
{
  "version": "0.5.6",
  "rev": "abc1234"
}
```

---

### 4. GetAttestationForAppKey

Generates a TDX quote binding the app's derived signing key (ed25519 or secp256k1) to a TDX attestation. The public key is encoded in the quote's report data using the `dip1::` format.

**Endpoint:** `POST /prpc/GetAttestationForAppKey`

**Request Parameters:**

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `algorithm` | string | Key algorithm: `"ed25519"`, `"secp256k1"`, or `"secp256k1_prehashed"` | `"ed25519"` |

**Example:**

```bash
curl -s http://localhost:9205/prpc/GetAttestationForAppKey \
  -H 'Content-Type: application/json' \
  -d '{"algorithm": "ed25519"}' | jq
```

**Response:**

```json
{
  "quote": "<hex-encoded-tdx-quote>",
  "event_log": "<json-encoded-event-log>",
  "report_data": "<hex-encoded-64-bytes-report-data>",
  "vm_config": "<json-string-vm-config>"
}
```

**Response Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `quote` | bytes (hex) | TDX quote with the derived public key in report data |
| `event_log` | string (JSON) | TDX event log (RTMR[0-2] payloads stripped, digests only) |
| `report_data` | bytes (hex) | 64 bytes of report data containing `dip1::<algo>-pk:<base64url-pubkey>` |
| `vm_config` | string (JSON) | VM configuration |

**Use case:** allows a verifier to link a derived signing key to a specific CVM's attestation. The report data format is `dip1::ed25519-pk:<base64url>` or `dip1::secp256k1c-pk:<base64url>`.

---

### 5. Metrics

Returns system metrics in Prometheus format. Only available if `public_sysinfo = true` in the app compose.

**Endpoint:** `GET /metrics`

**Example:**

```bash
curl -s http://localhost:9205/metrics
```

**Response:** Prometheus-formatted text metrics (CPU, memory, disk, etc.)

---

### 6. Container Logs

Returns container logs from the CVM's Docker engine. Only available if `public_logs = true` in the app compose.

**Endpoint:** `GET /logs/<container_name>`

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `since` | string | `0` | Start time: seconds (`"120"`), or with unit (`"5m"`, `"2h"`, `"1d"`) |
| `until` | string | `0` | End time (same format as `since`) |
| `follow` | bool | `false` | Stream logs in real time |
| `text` | bool | `false` | Return logs as UTF-8 text (otherwise base64) |
| `bare` | bool | `false` | Return raw log lines without JSON wrapping |
| `timestamps` | bool | `false` | Include Docker timestamps |
| `tail` | string | `"1000"` | Number of lines to return from the end |
| `ansi` | bool | `false` | Preserve ANSI escape codes (only with `text=true`) |

**Example:**

```bash
# Get last 100 lines of kms container logs as text
curl -s "http://localhost:9205/logs/dstack-kms-1?text=true&bare=true&tail=100"

# Stream logs in real time
curl -s "http://localhost:9205/logs/dstack-kms-1?text=true&bare=true&follow=true"

# Get logs from the last 30 minutes
curl -s "http://localhost:9205/logs/dstack-kms-1?text=true&bare=true&since=30m"
```

**Response (default JSON mode):** newline-delimited JSON objects:

```json
{"channel":"stdout","message":"<base64-encoded-log-line>"}
{"channel":"stderr","message":"<base64-encoded-log-line>"}
```

**Response (bare text mode):** raw log lines as plain text.

---

## Ports Summary

| Service | CVM Port | Typical Host Port | Protocol |
|---------|----------|-------------------|----------|
| KMS RPC (main + onboard) | 8000 | 9201 | HTTPS (self-signed) |
| auth-api (on-chain) | 8001 | configurable | HTTP (internal) |
| Guest Agent | 8090 | 9205 | HTTP |
