# dstack Gateway API Documentation

This document describes the Gateway API endpoints that can be called from the host machine. The Gateway runs **three separate servers** on different ports, plus the HTTPS proxy itself.

## Port Mapping

The Gateway CVM exposes the following ports, mapped to host ports by the VMM:

| Service | CVM Port | Host Port | Protocol | Auth | Purpose |
|---------|----------|-----------|----------|------|---------|
| Main RPC | 8000 | **9202** | HTTPS (mTLS) | mTLS (RA-TLS) | CVM registration, ACME info, peer sync |
| Admin RPC | 8001 | **9203** | HTTP | none | Management, monitoring, DNS/domain/cert config |
| HTTPS Proxy | 443 | **9204** | TLS | SNI-based | Reverse proxy to CVMs via WireGuard |
| Guest Agent | 8090 | **9206** | HTTP | varies | Logs, metrics, dashboard (see `sdk/curl/api.md`) |
| WireGuard | 51820 | **9202** (UDP) | UDP | WG keys | VPN tunnel for CVM traffic |
| Debug RPC | 8012 | — (not exposed) | HTTP | none | Testing (only if `insecure_enable_debug_rpc = true`) |

> **Note**: Host ports shown above are from the current deployment. They may differ depending on your `deploy-to-vmm.sh` configuration.

## Base URLs

From the host machine:

```bash
# Admin API (HTTP, no TLS — primary host interface)
# This is the most useful endpoint for operators
http://127.0.0.1:9203

# Main RPC (HTTPS with RA-TLS cert — limited host access, use -sk to skip TLS verification)
curl -sk https://127.0.0.1:9202/prpc/...

# Guest Agent — direct access on port 9206
http://127.0.0.1:9206

# Guest Agent — via VMM proxy (alternative, requires VM id)
curl -s http://127.0.0.1:9080/guest/Info -H 'Content-Type: application/json' -d '{"id":"<vm-id>"}'
```

---

## Admin RPC API (Primary Host Interface)

The Admin API is the main management interface. It runs on a separate HTTP server with **no authentication**, so it should only be exposed on trusted networks. All endpoints use `POST` with JSON body.

> **Tip**: All examples below use `?json` in the URL to get JSON-encoded responses. Without it, the Gateway returns protobuf-encoded binary data.

### 1. Status

Returns the full gateway status: node info, all registered CVM instances, WireGuard handshake times, and connection counts.

**Endpoint:** `POST /prpc/Status`

**Request:** empty `{}`

**Example:**

```bash
curl -s 'http://127.0.0.1:9203/prpc/Status?json' -d '{}' | jq
```

**Response:**

```json
{
  "id": 1,
  "url": "https://gateway-node-1:8011",
  "bootnode_url": "https://gateway-bootnode:8011",
  "uuid": "<hex-encoded-uuid>",
  "num_connections": "42",
  "hosts": [
    {
      "instance_id": "abcdef...",
      "ip": "10.0.0.2",
      "app_id": "123456...",
      "base_domain": "example.com",
      "latest_handshake": "1739290000",
      "num_connections": "5"
    }
  ],
  "nodes": [
    {
      "id": 1,
      "uuid": "<hex>",
      "url": "https://gateway-node-1:8011",
      "last_seen": "1739290000",
      "wg_public_key": "base64-key=",
      "wg_ip": "10.0.0.1/24",
      "wg_endpoint": "1.2.3.4:51820"
    }
  ]
}
```

---

### 2. GetInfo

Finds a registered CVM instance by its instance ID.

**Endpoint:** `POST /prpc/GetInfo`

**Request Parameters:**

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `id` | string | Instance ID (hex-encoded) | `"abcdef..."` |

**Example:**

```bash
curl -s 'http://127.0.0.1:9203/prpc/GetInfo?json' \
  -H 'Content-Type: application/json' \
  -d '{"id": "abcdef1234567890"}' | jq
```

**Response:**

```json
{
  "found": true,
  "info": {
    "instance_id": "abcdef1234567890",
    "ip": "10.0.0.2",
    "app_id": "123456...",
    "base_domain": "example.com",
    "latest_handshake": "1739290000",
    "num_connections": "3"
  }
}
```

---

### 3. GetMeta

Returns a summary: total registered CVMs and number currently online (handshake within last 5 minutes).

**Endpoint:** `POST /prpc/GetMeta`

**Request:** empty `{}`

**Example:**

```bash
curl -s 'http://127.0.0.1:9203/prpc/GetMeta?json' -d '{}' | jq
```

**Response:**

```json
{
  "registered": 15,
  "online": 12
}
```

---

### 4. Exit

Exits the Gateway process.

**Endpoint:** `POST /prpc/Exit`

**Request:** empty `{}`

**Example:**

```bash
curl -s 'http://127.0.0.1:9203/prpc/Exit?json' -d '{}'
```

**Response:** empty (process exits immediately)

---

### 5. RenewCert

Triggers certificate renewal for all managed ZT-Domains (force mode).

**Endpoint:** `POST /prpc/RenewCert`

**Request:** empty `{}`

**Example:**

```bash
curl -s 'http://127.0.0.1:9203/prpc/RenewCert?json' -d '{}' | jq
```

**Response:**

```json
{
  "renewed": true
}
```

---

### 6. ReloadCert

Reloads all certificates from the KvStore into memory (atomic replacement).

**Endpoint:** `POST /prpc/ReloadCert`

**Request:** empty `{}`

**Example:**

```bash
curl -s 'http://127.0.0.1:9203/prpc/ReloadCert?json' -d '{}'
```

**Response:** empty on success

---

### 7. SetNodeUrl

Updates the sync URL for a gateway node (used for dynamic peer management in multi-node clusters).

**Endpoint:** `POST /prpc/SetNodeUrl`

**Request Parameters:**

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `id` | uint32 | Node ID to update | `1` |
| `url` | string | New URL for this node | `"https://gw-node-1:8011"` |

**Example:**

```bash
curl -s 'http://127.0.0.1:9203/prpc/SetNodeUrl?json' \
  -H 'Content-Type: application/json' \
  -d '{"id": 1, "url": "https://gw-node-1:8011"}'
```

**Response:** empty on success

---

### 8. SetNodeStatus

Sets a gateway node's status to "up" or "down". A node marked "down" will not accept new CVM registrations.

**Endpoint:** `POST /prpc/SetNodeStatus`

**Request Parameters:**

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `id` | uint32 | Node ID to update | `1` |
| `status` | string | `"up"` or `"down"` | `"down"` |

**Example:**

```bash
curl -s 'http://127.0.0.1:9203/prpc/SetNodeStatus?json' \
  -H 'Content-Type: application/json' \
  -d '{"id": 1, "status": "down"}'
```

**Response:** empty on success

---

### 9. GetNodeStatuses

Returns the status ("up" or "down") for all gateway nodes.

**Endpoint:** `POST /prpc/GetNodeStatuses`

**Request:** empty `{}`

**Example:**

```bash
curl -s 'http://127.0.0.1:9203/prpc/GetNodeStatuses?json' -d '{}' | jq
```

**Response:**

```json
{
  "statuses": [
    { "node_id": 1, "status": "up" },
    { "node_id": 2, "status": "down" }
  ]
}
```

---

### 10. WaveKvStatus

Returns the WaveKV synchronization status for persistent and ephemeral stores (key counts, sync progress, peer ack status).

**Endpoint:** `POST /prpc/WaveKvStatus`

**Request:** empty `{}`

**Example:**

```bash
curl -s 'http://127.0.0.1:9203/prpc/WaveKvStatus?json' -d '{}' | jq
```

**Response:**

```json
{
  "enabled": true,
  "persistent": {
    "name": "persistent",
    "node_id": 1,
    "n_keys": "150",
    "next_seq": "320",
    "dirty": false,
    "wal_enabled": true,
    "peers": [
      {
        "id": 2,
        "local_ack": "310",
        "peer_ack": "305",
        "buffered_logs": "5",
        "last_seen": [
          { "node_id": 1, "timestamp": "1739290000" }
        ]
      }
    ]
  },
  "ephemeral": { "..." : "..." }
}
```

---

### 11. GetInstanceHandshakes

Returns WireGuard handshake observations for an instance across all gateway nodes.

**Endpoint:** `POST /prpc/GetInstanceHandshakes`

**Request Parameters:**

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `instance_id` | string | Instance ID (hex-encoded) | `"abcdef..."` |

**Example:**

```bash
curl -s 'http://127.0.0.1:9203/prpc/GetInstanceHandshakes?json' \
  -H 'Content-Type: application/json' \
  -d '{"instance_id": "abcdef1234567890"}' | jq
```

**Response:**

```json
{
  "handshakes": [
    { "observer_node_id": 1, "timestamp": "1739290000" },
    { "observer_node_id": 2, "timestamp": "1739289950" }
  ]
}
```

---

### 12. GetGlobalConnections

Returns connection statistics across all gateway nodes.

**Endpoint:** `POST /prpc/GetGlobalConnections`

**Request:** empty `{}`

**Example:**

```bash
curl -s 'http://127.0.0.1:9203/prpc/GetGlobalConnections?json' -d '{}' | jq
```

**Response:**

```json
{
  "total_connections": "42",
  "node_connections": {
    "1": "25",
    "2": "17"
  }
}
```

---

## DNS Credential Management (Admin API)

Manage DNS provider credentials used for ACME certificate issuance (DNS-01 challenge).

### 13. ListDnsCredentials

**Endpoint:** `POST /prpc/ListDnsCredentials`

**Example:**

```bash
curl -s 'http://127.0.0.1:9203/prpc/ListDnsCredentials?json' -d '{}' | jq
```

**Response:**

```json
{
  "credentials": [
    {
      "id": "18e5a1b2c3d4e5f6",
      "name": "cloudflare",
      "provider_type": "cloudflare",
      "cf_api_token": "abc...",
      "cf_api_url": "",
      "dns_txt_ttl": 60,
      "max_dns_wait": 300,
      "created_at": "1739290000",
      "updated_at": "1739290000"
    }
  ],
  "default_id": "18e5a1b2c3d4e5f6"
}
```

---

### 14. CreateDnsCredential

Creates a new DNS credential (currently only Cloudflare is supported).

**Endpoint:** `POST /prpc/CreateDnsCredential`

**Request Parameters:**

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `name` | string | Human-readable name | `"cloudflare-prod"` |
| `provider_type` | string | `"cloudflare"` | `"cloudflare"` |
| `cf_api_token` | string | Cloudflare API token | `"abc123..."` |
| `cf_zone_id` | string | Cloudflare zone ID | `"zone-id"` |
| `set_as_default` | boolean | Set as the default credential | `true` |
| `cf_api_url` | string (optional) | Custom Cloudflare API URL | |
| `dns_txt_ttl` | uint32 (optional) | DNS TXT record TTL (default: 60) | `60` |
| `max_dns_wait` | uint32 (optional) | Max DNS propagation wait in seconds (default: 300) | `300` |

**Example:**

```bash
curl -s 'http://127.0.0.1:9203/prpc/CreateDnsCredential?json' \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "cloudflare",
    "provider_type": "cloudflare",
    "cf_api_token": "your-cloudflare-api-token",
    "set_as_default": true
  }' | jq
```

---

### 15. UpdateDnsCredential

**Endpoint:** `POST /prpc/UpdateDnsCredential`

**Request Parameters:**

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Credential ID (required) |
| `name` | string (optional) | New name |
| `cf_api_token` | string (optional) | New API token |
| `cf_zone_id` | string (optional) | New zone ID |
| `cf_api_url` | string (optional) | New API URL |

**Example:**

```bash
curl -s 'http://127.0.0.1:9203/prpc/UpdateDnsCredential?json' \
  -H 'Content-Type: application/json' \
  -d '{"id": "18e5a1b2c3d4e5f6", "cf_api_token": "new-token"}' | jq
```

---

### 16. DeleteDnsCredential

Deletes a DNS credential. Cannot delete the default credential or one in use by a ZT-Domain.

**Endpoint:** `POST /prpc/DeleteDnsCredential`

**Request Parameters:**

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Credential ID |

**Example:**

```bash
curl -s 'http://127.0.0.1:9203/prpc/DeleteDnsCredential?json' \
  -H 'Content-Type: application/json' \
  -d '{"id": "18e5a1b2c3d4e5f6"}'
```

---

### 17. GetDefaultDnsCredential

**Endpoint:** `POST /prpc/GetDefaultDnsCredential`

**Example:**

```bash
curl -s 'http://127.0.0.1:9203/prpc/GetDefaultDnsCredential?json' -d '{}' | jq
```

**Response:**

```json
{
  "default_id": "18e5a1b2c3d4e5f6",
  "credential": { "..." : "..." }
}
```

---

### 18. SetDefaultDnsCredential

**Endpoint:** `POST /prpc/SetDefaultDnsCredential`

**Request Parameters:**

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Credential ID to set as default |

**Example:**

```bash
curl -s 'http://127.0.0.1:9203/prpc/SetDefaultDnsCredential?json' \
  -H 'Content-Type: application/json' \
  -d '{"id": "18e5a1b2c3d4e5f6"}'
```

---

## ZT-Domain Management (Admin API)

Manage ZT-Domain configurations (content-addressable HTTPS domains). Each ZT-Domain is a base domain (e.g., `example.com`) for which the gateway issues a wildcard certificate (`*.example.com`) and proxies requests to CVMs.

### 19. ListZtDomains

**Endpoint:** `POST /prpc/ListZtDomains`

**Example:**

```bash
curl -s 'http://127.0.0.1:9203/prpc/ListZtDomains?json' -d '{}' | jq
```

**Response:**

```json
{
  "domains": [
    {
      "config": {
        "domain": "example.com",
        "dns_cred_id": "18e5a1b2c3d4e5f6",
        "port": 443,
        "priority": 100
      },
      "cert_status": {
        "has_cert": true,
        "not_after": "1771000000",
        "issued_by": 1,
        "issued_at": "1739290000",
        "loaded_in_memory": true
      }
    }
  ]
}
```

---

### 20. AddZtDomain

Adds a new ZT-Domain configuration. Automatically triggers certificate issuance.

**Endpoint:** `POST /prpc/AddZtDomain`

**Request Parameters:**

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `domain` | string | Base domain name | `"example.com"` |
| `dns_cred_id` | string (optional) | DNS credential ID (default: use default cred) | |
| `port` | uint32 | Port this domain serves on | `443` |
| `node` | uint32 (optional) | Bind to a specific node (0 = any) | |
| `priority` | int32 | Priority for default domain selection (higher = preferred) | `100` |

**Example:**

```bash
curl -s 'http://127.0.0.1:9203/prpc/AddZtDomain?json' \
  -H 'Content-Type: application/json' \
  -d '{"domain": "example.com", "port": 443, "priority": 100}' | jq
```

---

### 21. GetZtDomain

**Endpoint:** `POST /prpc/GetZtDomain`

**Request Parameters:**

| Field | Type | Description |
|-------|------|-------------|
| `domain` | string | Domain name |

**Example:**

```bash
curl -s 'http://127.0.0.1:9203/prpc/GetZtDomain?json' \
  -H 'Content-Type: application/json' \
  -d '{"domain": "example.com"}' | jq
```

---

### 22. UpdateZtDomain

**Endpoint:** `POST /prpc/UpdateZtDomain`

Same parameters as `AddZtDomain`. The `domain` field must already exist.

**Example:**

```bash
curl -s 'http://127.0.0.1:9203/prpc/UpdateZtDomain?json' \
  -H 'Content-Type: application/json' \
  -d '{"domain": "example.com", "port": 443, "priority": 200}' | jq
```

---

### 23. DeleteZtDomain

Removes a ZT-Domain configuration. Certificate data is kept for historical purposes.

**Endpoint:** `POST /prpc/DeleteZtDomain`

**Request Parameters:**

| Field | Type | Description |
|-------|------|-------------|
| `domain` | string | Domain name |

**Example:**

```bash
curl -s 'http://127.0.0.1:9203/prpc/DeleteZtDomain?json' \
  -H 'Content-Type: application/json' \
  -d '{"domain": "example.com"}'
```

---

### 24. RenewZtDomainCert

Manually triggers certificate renewal for a specific ZT-Domain.

**Endpoint:** `POST /prpc/RenewZtDomainCert`

**Request Parameters:**

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `domain` | string | Domain name | `"example.com"` |
| `force` | boolean | Force renewal even if not near expiry | `true` |

**Example:**

```bash
curl -s 'http://127.0.0.1:9203/prpc/RenewZtDomainCert?json' \
  -H 'Content-Type: application/json' \
  -d '{"domain": "example.com", "force": true}' | jq
```

**Response:**

```json
{
  "renewed": true,
  "not_after": "1771000000"
}
```

---

### 25. ForceReleaseCertLock

Force-releases the distributed certificate renewal lock for a domain (in case a renewal got stuck).

**Endpoint:** `POST /prpc/ForceReleaseCertLock`

**Request Parameters:**

| Field | Type | Description |
|-------|------|-------------|
| `domain` | string | Domain name |

**Example:**

```bash
curl -s 'http://127.0.0.1:9203/prpc/ForceReleaseCertLock?json' \
  -H 'Content-Type: application/json' \
  -d '{"domain": "example.com"}'
```

---

### 26. ListCertAttestations

Lists TDX attestations of certificate public keys for a domain.

**Endpoint:** `POST /prpc/ListCertAttestations`

**Request Parameters:**

| Field | Type | Description |
|-------|------|-------------|
| `domain` | string | Domain name |
| `limit` | uint32 | Max attestations to return (0 = all) |

**Example:**

```bash
curl -s 'http://127.0.0.1:9203/prpc/ListCertAttestations?json' \
  -H 'Content-Type: application/json' \
  -d '{"domain": "example.com", "limit": 5}' | jq
```

**Response:**

```json
{
  "latest": {
    "public_key": "<hex-encoded-der-pubkey>",
    "quote": "<json-tdx-quote>",
    "generated_by": 1,
    "generated_at": "1739290000"
  },
  "history": [ "..." ]
}
```

---

## Certbot Configuration (Admin API)

### 27. GetCertbotConfig

Returns the global ACME/certbot configuration.

**Endpoint:** `POST /prpc/GetCertbotConfig`

**Example:**

```bash
curl -s 'http://127.0.0.1:9203/prpc/GetCertbotConfig?json' -d '{}' | jq
```

**Response:**

```json
{
  "renew_interval_secs": "3600",
  "renew_before_expiration_secs": "864000",
  "renew_timeout_secs": "300",
  "acme_url": "https://acme-v02.api.letsencrypt.org/directory"
}
```

---

### 28. SetCertbotConfig

Updates global certbot configuration. Only specified fields are updated.

**Endpoint:** `POST /prpc/SetCertbotConfig`

**Request Parameters:**

| Field | Type | Description |
|-------|------|-------------|
| `renew_interval_secs` | uint64 (optional) | Interval between renewal checks |
| `renew_before_expiration_secs` | uint64 (optional) | Time before expiration to trigger renewal |
| `renew_timeout_secs` | uint64 (optional) | Timeout for renewal operations |
| `acme_url` | string (optional) | ACME server URL (empty = Let's Encrypt production) |

**Example:**

```bash
curl -s 'http://127.0.0.1:9203/prpc/SetCertbotConfig?json' \
  -H 'Content-Type: application/json' \
  -d '{
    "acme_url": "https://acme-staging-v02.api.letsencrypt.org/directory",
    "renew_interval_secs": 3600,
    "renew_before_expiration_secs": 864000,
    "renew_timeout_secs": 300
  }'
```

---

## Admin Web Dashboard

### 29. Dashboard

Returns an HTML dashboard showing the gateway status, registered CVMs, and ACME info.

**Endpoint:** `GET /`

**Example:**

```bash
# Open in browser
open http://127.0.0.1:9203/
```

---

## Main RPC API (Host-Accessible Subset)

The main RPC server uses HTTPS with mTLS. Most endpoints require RA-TLS client certificates, but the following can be called from the host with `-sk` (skip TLS verification):

### 30. Info

Returns basic gateway info: base domain, external port, app address namespace prefix, and version.

**Endpoint:** `POST /prpc/Info`

**Example:**

```bash
curl -sk 'https://127.0.0.1:9202/prpc/Info?json' -d '{}' | jq
```

**Response:**

```json
{
  "base_domain": "example.com",
  "external_port": 443,
  "app_address_ns_prefix": "_dstack-app-address",
  "version": "0.5.5"
}
```

---

### 31. AcmeInfo

Returns ACME account URI, TDX attestations, and certificate public key history for all managed domains.

**Endpoint:** `POST /prpc/AcmeInfo`

**Example:**

```bash
curl -sk 'https://127.0.0.1:9202/prpc/AcmeInfo?json' -d '{}' | jq
```

**Response:**

```json
{
  "account_uri": "https://acme-v02.api.letsencrypt.org/acme/acct/12345",
  "account_quote": "<json-tdx-quote>",
  "account_attestation": "<hex-encoded-attestation>",
  "quoted_hist_keys": [
    {
      "public_key": "<hex-encoded-der-pubkey>",
      "quote": "<json-tdx-quote>",
      "attestation": "<hex-encoded-attestation>"
    }
  ]
}
```

---

## Debug RPC API (Optional)

Only available when `insecure_enable_debug_rpc = true` in the gateway config. Runs on a separate HTTP port (default: 8012). **Not enabled in production.**

### Debug.RegisterCvm

Registers a CVM without TDX attestation (for testing).

**Endpoint:** `POST /prpc/RegisterCvm`

**Request Parameters:**

| Field | Type | Description |
|-------|------|-------------|
| `client_public_key` | string | WireGuard public key |
| `app_id` | string | App ID (hex) |
| `instance_id` | string | Instance ID (hex) |

**Example:**

```bash
curl -s 'http://127.0.0.1:8012/prpc/RegisterCvm?json' \
  -H 'Content-Type: application/json' \
  -d '{
    "client_public_key": "base64-wg-pubkey=",
    "app_id": "abcdef...",
    "instance_id": "123456..."
  }' | jq
```

### Debug.Info

Same as Main RPC `Info`.

```bash
curl -s 'http://127.0.0.1:8012/prpc/Info?json' -d '{}' | jq
```

### Debug.GetSyncData

Returns all WaveKV sync data (peer addresses, nodes, instances).

```bash
curl -s 'http://127.0.0.1:8012/prpc/GetSyncData?json' -d '{}' | jq
```

### Debug.GetProxyState

Returns the in-memory proxy state (instances, allocated IPs).

```bash
curl -s 'http://127.0.0.1:8012/prpc/GetProxyState?json' -d '{}' | jq
```

### Health Check

Simple liveness check endpoint.

**Endpoint:** `GET /health`

```bash
curl -s http://127.0.0.1:8012/health
# Response: OK
```

---

## CVM-Only Endpoints (Not Callable from Host)

The following endpoints exist on the Main RPC server but **require mTLS with RA-TLS client certificates**. They cannot be called with plain `curl` from the host.

| Endpoint | Purpose | Requires |
|----------|---------|----------|
| `RegisterCvm` | Register a CVM and get WireGuard config + IP allocation | mTLS with RA-TLS (app attestation) |
| `GetPeers` | Get peer gateway URLs (for gateway-to-gateway sync) | mTLS from same gateway `app_id` |
| `POST /wavekv/sync/<store>` | WaveKV data synchronization between gateway nodes | mTLS from same gateway `app_id` |

---

## Guest Agent API (Port 9206)

The Guest Agent runs inside the CVM and exposes a server on port 8090 (host port **9206**). This provides direct access to the CVM's public information without going through the VMM proxy.

### Available Endpoints

#### pRPC Endpoints

| Endpoint | Description |
|----------|-------------|
| `POST /prpc/Info` | App identity: `app_id`, `instance_id`, `app_cert`, `tcb_info`, etc. |
| `POST /prpc/Version` | Guest agent version and git revision |

#### HTTP Endpoints

| Endpoint | Description | Condition |
|----------|-------------|-----------|
| `GET /` | HTML dashboard with app info, containers, system info | always |
| `GET /metrics` | Prometheus-format metrics (CPU, memory, disk) | `public_sysinfo = true` |
| `GET /logs/<container>?text=true&bare=true&tail=100` | Container logs (streaming) | `public_logs = true` |

### Examples

```bash
# Get app info (attestation, app_id, certificates)
curl -s 'http://127.0.0.1:9206/prpc/Info?json' -d '{}' | jq '{app_id, instance_id, app_name}'

# Get guest agent version
curl -s 'http://127.0.0.1:9206/prpc/Version?json' -d '{}' | jq

# Open dashboard in browser
open http://127.0.0.1:9206/

# Get Prometheus metrics
curl -s http://127.0.0.1:9206/metrics

# Stream container logs (text format, last 100 lines)
curl -s 'http://127.0.0.1:9206/logs/dstack-gateway-1?text=true&bare=true&tail=100'
```

> **Note**: The Guest Agent also serves the VMM's `/guest` proxy path (via vsock), which exposes additional endpoints like `SysInfo`, `NetworkInfo`, `ListContainers`, and `Shutdown`. These extra endpoints are **not** available on port 9206 — only through the VMM proxy at `http://127.0.0.1:9080/guest/...`.

---

## Error Responses

All endpoints may return:

- `200 OK` — request successful
- `400 Bad Request` — invalid parameters
- `500 Internal Server Error` — server error

Error responses include a JSON body:

```json
{
  "error": "error description"
}
```

## Typical Bootstrap Workflow

When deploying a new gateway, the deployment script automatically configures it via the Admin API:

```bash
ADMIN="http://127.0.0.1:9203"

# 1. Set certbot ACME URL
curl -s -X POST "$ADMIN/prpc/SetCertbotConfig?json" \
  -H 'Content-Type: application/json' \
  -d '{"acme_url":"https://acme-v02.api.letsencrypt.org/directory","renew_interval_secs":3600}'

# 2. Create Cloudflare DNS credential
curl -s -X POST "$ADMIN/prpc/CreateDnsCredential?json" \
  -H 'Content-Type: application/json' \
  -d '{"name":"cloudflare","provider_type":"cloudflare","cf_api_token":"YOUR_TOKEN","set_as_default":true}'

# 3. Add a ZT-Domain
curl -s -X POST "$ADMIN/prpc/AddZtDomain?json" \
  -H 'Content-Type: application/json' \
  -d '{"domain":"example.com","port":443,"priority":100}'

# 4. Check status
curl -s "$ADMIN/prpc/Status?json" -d '{}' | jq '.hosts | length'
```

## Ports Summary

| Service | CVM Port | Host Port | Protocol |
|---------|----------|-----------|----------|
| Main RPC | 8000 | 9202 | HTTPS (mTLS, RA-TLS) |
| Admin RPC | 8001 | 9203 | HTTP |
| HTTPS Proxy | 443 | 9204 | TLS |
| Guest Agent | 8090 | 9206 | HTTP |
| WireGuard | 51820 | 9202 (UDP) | UDP |
| Debug RPC | 8012 | — (not exposed) | HTTP |
