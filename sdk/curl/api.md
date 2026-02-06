# dstack Guest Agent API Documentation

This document describes the API endpoints for the dstack Guest Agent service.

## Overview

The dstack Guest Agent exposes two types of APIs:

1. **RPC API (prpc)**: Protocol Buffers-based RPC endpoints accessible via Unix socket or HTTP
2. **HTTP REST API**: Simple HTTP endpoints for logs, metrics, and dashboard

## Base URL

### RPC API (Unix Socket)

The dstack Guest Agent listens on a Unix domain socket at `/var/run/dstack.sock`. RPC API requests should be made to this socket using the `--unix-socket` flag with curl.

Make sure to map the Unix socket in your Docker Compose file:

```yaml
services:
  jupyter:
    image: quay.io/jupyter/base-notebook
    volumes:
      - /var/run/dstack.sock:/var/run/dstack.sock
```

### HTTP API

The Guest Agent also exposes an HTTP server on port `8090` inside the CVM. This port is typically mapped to a host port (e.g., `9206` for Gateway, `9205` for KMS) for external access.

**Note**: The HTTP API endpoints are only available if enabled in the app configuration (`public_logs`, `public_sysinfo`).

## RPC API Endpoints

The following endpoints use the prpc (Protocol Buffers) format and are accessible via Unix socket or HTTP.

### 1. Get TLS Key

Derives a cryptographic key and returns it along with its TLS certificate chain. This API can be used to generate a TLS key/certificate for RA-TLS.

**Endpoint:** `/GetTlsKey`

**Request Parameters:**

| Field | Type | Description | Example |
|-------|------|-------------|----------|
| `subject` | string | The subject name for the certificate | `"example.com"` |
| `alt_names` | array of strings | List of Subject Alternative Names (SANs) for the certificate | `["www.example.com", "api.example.com"]` |
| `usage_ra_tls` | boolean | Whether to include quote in the certificate for RA-TLS | `true` |
| `usage_server_auth` | boolean | Enable certificate for server authentication | `true` |
| `usage_client_auth` | boolean | Enable certificate for client authentication | `false` |
| `not_before` | uint64 | Certificate validity start time as seconds since UNIX epoch | `0` |
| `not_after` | uint64 | Certificate validity end time as seconds since UNIX epoch | `0` |
| `with_app_info` | boolean | Whether to include app info in the certificate | `false` |

**Example:**
```bash
curl --unix-socket /var/run/dstack.sock -X POST \
  http://dstack/GetTlsKey \
  -H 'Content-Type: application/json' \
  -d '{
    "subject": "example.com",
    "alt_names": ["www.example.com", "api.example.com"],
    "usage_ra_tls": true,
    "usage_server_auth": true,
    "usage_client_auth": false
  }'
```

**Response:**
```json
{
  "key": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----",
  "certificate_chain": [
    "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
    "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
  ]
}
```

### 2. Get Key

Generates an ECDSA key using the k256 elliptic curve, derived from the application key, and returns both the key and its signature chain. Sutable for ETH key generation.

**Endpoint:** `/GetKey`

**Request Parameters:**

| Field | Type | Description | Example |
|-------|------|-------------|----------|
| `path` | string | Path for the key | `"my/key/path"` |
| `purpose` | string | Purpose for the key. Can be any string. This is used in the signature chain. | `"signing"` | `"encryption"` |
| `algorithm` | string | Either `secp256k1` or `ed25519`. Defaults to `secp256k1` | `ed25519` |

**Example:**
```bash
curl --unix-socket /var/run/dstack.sock -X POST \
  http://dstack/GetKey \
  -H 'Content-Type: application/json' \
  -d '{
    "path": "my/key/path",
    "purpose": "signing",
    "algorithm": "ed25519"
  }'
```

Or

```bash
curl --unix-socket /var/run/dstack.sock http://dstack/GetKey?path=my/key/path&purpose=signing&algorithm=ed25519
```

**Response:**
```json
{
  "key": "<hex-encoded-key>",
  "signature_chain": [
    "<hex-encoded-signature-1>",
    "<hex-encoded-signature-2>"
  ]
}
```

### 3. Get Quote

Generates a TDX quote with given plain report data.

**Endpoint:** `/GetQuote`

**Request Parameters:**

| Field | Type | Description | Example |
|-------|------|-------------|----------|
| `report_data` | string | Report data of max length 64 bytes. Padding with 0s if less than 64 bytes. | `"1234deadbeaf"` |

**Example:**
```bash
curl --unix-socket /var/run/dstack.sock -X POST \
  http://dstack/GetQuote \
  -H 'Content-Type: application/json' \
  -d '{
    "report_data": "1234deadbeaf"
  }'
```
Or
```bash
curl --unix-socket /var/run/dstack.sock http://dstack/GetQuote?report_data=00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
```

**Response:**
```json
{
  "quote": "<hex-encoded-quote>",
  "event_log": "<json-event-log>",
  "report_data": "<hex-encoded-report-data>",
  "vm_config": "<json-vm-config-string>"
}
```

**Note on Event Log:**
The `event_log` field contains a JSON array of TDX event log entries. For RTMR 0-2 (boot-time measurements), only the digest is included; the payload is stripped to reduce response size. For RTMR3 (runtime measurements), both digest and payload are included. To verify the event log, submit it along with the quote to the [verifier service](../../verifier/README.md).

### 4. Get Info

Retrieves worker information.

**Endpoint:** `/Info`

**Example:**
```bash
curl --unix-socket /var/run/dstack.sock http://dstack/Info
```

**Response:**
```json
{
  "app_id": "<hex-encoded-app-id>",
  "instance_id": "<hex-encoded-instance-id>",
  "app_cert": "<certificate-string>",
  "tcb_info": "<tcb-info-string>",
  "app_name": "my-app",
  "device_id": "<hex-encoded-device-id>",
  "mr_aggregated": "<hex-encoded-mr-aggregated>",
  "os_image_hash": "<hex-encoded-os-image-hash>",
  "key_provider_info": "<key-provider-info-string>",
  "compose_hash": "<hex-encoded-compose-hash>",
  "vm_config": "<json-vm-config-string>"
}
```

### 5. Emit Event

Emit an event to be extended to RTMR3 on TDX platform. This API requires dstack OS 0.5.0 or later.

**Endpoint:** `/EmitEvent`

**Request Parameters:**

| Field | Type | Description | Example |
|-------|------|-------------|----------|
| `event` | string | The event name | `"custom-event"` |
| `payload` | string | Hex-encoded payload data | `"deadbeef"` |

**Example:**
```bash
curl --unix-socket /var/run/dstack.sock -X POST \
  http://dstack/EmitEvent \
  -H 'Content-Type: application/json' \
  -d '{
    "event": "custom-event",
    "payload": "deadbeef"
  }'
```

**Response:**
Empty response with HTTP 200 status code on success.

### 6. Sign (not yet released)

Signs a payload.

**Endpoint:** `/Sign`

**Request Parameters:**

| Field | Type | Description | Example |
|-------|------|-------------|----------|
| `algorithm` | string | `ed25519`, `secp256k1_prehashed` or `secp256k1`| `ed25519` |
| `data` | string | Hex-encoded payload data | `deadbeef` |

**Example:**
```bash
curl --unix-socket /var/run/dstack.sock -X POST \
  http://dstack/Sign \
  -H 'Content-Type: application/json' \
  -d '{
    "algorithm": "ed25519",
    "data": "deadbeef"
  }'
```

**Response:**
```json
{
  "signature": "<hex-encoded-signature>",
  "signature_chain": [
    "<hex-encoded-signature-1>",
    "<hex-encoded-signature-2>",
    "<hex-encoded-signature-3>"
  ]
  "public_key": "<hex-encoded-public-key>"
}
```

### 7. Verify (not yet released)

Verifies a signature.

**Endpoint:** `/Verify`

**Request Parameters:**

| Field | Type | Description | Example |
|-------|------|-------------|----------|
| `algorithm` | string | `ed25519`, `secp256k1_prehashed` or `secp256k1`| `ed25519` |
| `data` | string | Hex-encoded payload data | `deadbeef` |
| `signature` | string | Hex-encoded signature | `deadbeef` |
| `public_key` | string | Hex-encoded public key | `deadbeef` |

**Example:**
```bash
curl --unix-socket /var/run/dstack.sock -X POST \
  http://dstack/Verify \
  -H 'Content-Type: application/json' \
  -d '{
    "algorithm": "ed25519",
    "data": "deadbeef",
    "signature": "deadbeef",
    "public_key": "deadbeef"
  }'
```

**Response:**
```json
{
  "valid": "<true|false>"
}
```

### 8. Attest

Generates a versioned attestation with the given report data. Returns a dstack-defined attestation format that supports different attestation modes across platforms.
You can submit the returned `attestation` directly to the verifier `/verify` endpoint.

**Endpoint:** `/Attest`

**Request Parameters:**

| Field | Type | Description | Example |
|-------|------|-------------|----------|
| `report_data` | string | Report data of max length 64 bytes. Padding with 0s if less than 64 bytes. | `"1234deadbeaf"` |

**Example:**
```bash
curl --unix-socket /var/run/dstack.sock -X POST \
  http://dstack/Attest \
  -H 'Content-Type: application/json' \
  -d '{
    "report_data": "1234deadbeaf"
  }'
```
Or
```bash
curl --unix-socket /var/run/dstack.sock http://dstack/Attest?report_data=00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
```

**Response:**
```json
{
  "attestation": "<hex-encoded-attestation>"
}
```

## HTTP REST API Endpoints

The following endpoints are simple HTTP REST endpoints accessible via the Guest Agent's HTTP server (port 8090, typically mapped to a host port).

### 1. Get Container Logs

Retrieves logs from a Docker container running in the CVM.

**Endpoint:** `GET /logs/<container_name>`

**Query Parameters:**

| Parameter | Type | Description | Default |
|-----------|------|-------------|---------|
| `since` | string | Show logs since this time (e.g., `"1h"`, `"30m"`, `"3600"` for seconds) | `0` (all logs) |
| `until` | string | Show logs until this time | `0` (now) |
| `follow` | boolean | Follow log output (stream) | `false` |
| `text` | boolean | Return logs as text instead of base64 | `false` |
| `bare` | boolean | Return bare log lines without JSON wrapper | `false` |
| `timestamps` | boolean | Include timestamps in log output | `false` |
| `tail` | string | Number of lines to show from the end | `"1000"` |
| `ansi` | boolean | Include ANSI color codes | `false` |

**Example (from host):**
```bash
# Get last 30 lines of gateway container logs
curl "http://127.0.0.1:9206/logs/dstack-gateway-1?text&bare&timestamps&tail=30"

# Follow logs in real-time
curl "http://127.0.0.1:9206/logs/dstack-gateway-1?text&bare&timestamps&follow=true"

# Get logs from last hour
curl "http://127.0.0.1:9206/logs/dstack-gateway-1?text&bare&since=1h"
```

**Example (from inside CVM):**
```bash
curl "http://localhost:8090/logs/dstack-gateway-1?text&bare&timestamps&tail=30"
```

**Response:**
When `bare=true` and `text=true`, returns plain text log lines:
```
2026-02-05T21:51:50.454934Z  INFO dstack_gateway::config: Setting up wireguard interface
2026-02-05T21:51:50.463391Z  INFO cmd_lib::child: Device "wg-ds-gw" does not exist.
```

When `bare=false`, returns JSON-wrapped log lines:
```json
{"channel":"stdout","message":"2026-02-05T21:51:50.454934Z  INFO dstack_gateway::config: Setting up wireguard interface\n"}
```

### 2. Get Metrics

Retrieves system metrics and information (requires `public_sysinfo` to be enabled).

**Endpoint:** `GET /metrics`

**Example:**
```bash
curl "http://127.0.0.1:9206/metrics"
```

**Response:**
Returns Prometheus-formatted metrics.

### 3. Dashboard

Returns an HTML dashboard with app information and links to logs/metrics.

**Endpoint:** `GET /`

**Example:**
```bash
curl "http://127.0.0.1:9206/"
```

**Response:**
Returns HTML page with app information and navigation links.

## Error Responses

All endpoints may return the following HTTP status codes:

- `200 OK`: Request successful
- `400 Bad Request`: Invalid request parameters
- `404 Not Found`: Resource not found (e.g., container name not found)
- `500 Internal Server Error`: Server-side error

Error responses will include a JSON body with error details:
```json
{
  "error": "Error description"
}
```
