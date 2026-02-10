# dstack VMM API Documentation

This document describes the API endpoints for the dstack Virtual Machine Manager (VMM) service.

## Overview

The dstack VMM exposes three types of APIs:

1. **VMM RPC API (`/prpc`)**: Protocol Buffers-based RPC endpoints for CVM lifecycle management (create, start, stop, update, remove)
2. **Proxied Guest API (`/guest`)**: RPC endpoints that proxy requests to Guest Agents running inside CVMs
3. **HTTP REST API**: Simple HTTP endpoints for the web console and VM serial logs

All RPC APIs use the prpc (Protocol Buffers) format with JSON encoding.

## Base URL

The VMM listen address is configured via the `address` field in `vmm.toml`. It supports two modes:

**TCP mode** (e.g. `address = "tcp:0.0.0.0:9080"`):
```bash
curl http://127.0.0.1:9080/prpc/Status -d '{}'
```

**Unix socket mode** (e.g. `address = "unix:./vmm.sock"`):
```bash
curl --unix-socket ./vmm.sock http://localhost/prpc/Status -d '{}'
```

> **Note:** All examples in this document use TCP mode (`http://127.0.0.1:9080`). If your VMM is configured with a Unix socket, replace `http://127.0.0.1:9080` with `--unix-socket <path> http://localhost`.

## Authentication

If authentication is enabled in `vmm.toml` (`auth.enabled = true`), all RPC and REST endpoints (except the web console) require an API token.

Pass the token via the `Authorization` header:

```bash
curl -H "Authorization: Bearer <your-api-token>" \
  http://127.0.0.1:9080/prpc/CreateVm \
  -d '{...}'
```

---

## VMM RPC API (`/prpc`)

These endpoints manage the CVM fleet. They are also accessible via the legacy prefix `/prpc/Teepod.CreateVm` (the `Teepod.` prefix is stripped automatically).

### 1. Create VM

Creates and optionally starts a new CVM instance.

**Endpoint:** `POST /prpc/CreateVm`

**Request Parameters (`VmConfiguration`):**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Name of the VM (alphanumeric, `-`, `_`, `.`, ` `, `@`, `~`, `!`, `$`, `^`, `(`, `)`) |
| `image` | string | Yes | OS image name to use (see `ListImages`) |
| `compose_file` | string | Yes | JSON-encoded `app-compose.json` content |
| `vcpu` | uint32 | Yes | Number of vCPUs |
| `memory` | uint32 | Yes | Memory in MB |
| `disk_size` | uint32 | Yes | Disk size in GB |
| `ports` | array of `PortMapping` | No | Port mapping rules (requires `port_mapping.enabled` in config) |
| `encrypted_env` | bytes | No | Encrypted environment variables (hex-encoded) |
| `app_id` | string | No | App ID for upgrades. If omitted, computed from `compose_file` |
| `user_config` | string | No | User config content (placed at `/dstack/.user-config` in CVM) |
| `hugepages` | bool | No | Enable hugepages |
| `pin_numa` | bool | No | Enable NUMA pinning |
| `gpus` | `GpuConfig` | No | GPU passthrough configuration |
| `kms_urls` | array of strings | No | KMS URLs (overrides global config) |
| `gateway_urls` | array of strings | No | Gateway URLs (overrides global config) |
| `stopped` | bool | No | If `true`, create the VM but don't start it |
| `no_tee` | bool | No | Disable TEE (run as a normal VM without TDX) |
| `networking` | `NetworkingConfig` | No | Per-VM networking mode override |

**Port Mapping (`PortMapping`):**

| Field | Type | Description |
|-------|------|-------------|
| `protocol` | string | `"tcp"` or `"udp"` |
| `host_port` | uint32 | Port on the host |
| `vm_port` | uint32 | Port inside the CVM |
| `host_address` | string | Host bind address (defaults to config value) |

**GPU Config (`GpuConfig`):**

| Field | Type | Description |
|-------|------|-------------|
| `gpus` | array of `GpuSpec` | List of GPUs to attach |
| `attach_mode` | string | `"listed"` (use specified GPUs) or `"all"` (attach all NVIDIA GPUs) |

**Networking Config (`NetworkingConfig`):**

| Field | Type | Description |
|-------|------|-------------|
| `mode` | string | `"passt"`, `"bridge"`, `"user"`, or `"custom"` |

**Example:**
```bash
curl -X POST http://127.0.0.1:9080/prpc/CreateVm \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "my-app",
    "image": "dstack-0.5.0",
    "compose_file": "{\"docker_compose_file\":\"...\",\"docker_config\":{},\"features\":[],\"allowed_envs\":[\"DB_HOST\",\"DB_PASS\"]}",
    "vcpu": 2,
    "memory": 4096,
    "disk_size": 40,
    "ports": [
      {"protocol": "tcp", "host_port": 8080, "vm_port": 80}
    ],
    "encrypted_env": "<hex-encoded-encrypted-env>"
  }'
```

**Response:**
```json
{
  "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
}
```

---

### 2. Start VM

Starts a stopped or newly created CVM.

**Endpoint:** `POST /prpc/StartVm`

**Request Parameters:**

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | VM ID (UUID) |

**Example:**
```bash
curl -X POST http://127.0.0.1:9080/prpc/StartVm \
  -H 'Content-Type: application/json' \
  -d '{"id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890"}'
```

**Response:** Empty response with HTTP 200 on success.

---

### 3. Stop VM

Force-stops a running CVM (kills the QEMU process).

**Endpoint:** `POST /prpc/StopVm`

**Request Parameters:**

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | VM ID (UUID) |

**Example:**
```bash
curl -X POST http://127.0.0.1:9080/prpc/StopVm \
  -H 'Content-Type: application/json' \
  -d '{"id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890"}'
```

**Response:** Empty response with HTTP 200 on success.

---

### 4. Shutdown VM

Initiates a graceful shutdown inside the CVM via the Guest Agent.

**Endpoint:** `POST /prpc/ShutdownVm`

**Request Parameters:**

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | VM ID (UUID) |

**Example:**
```bash
curl -X POST http://127.0.0.1:9080/prpc/ShutdownVm \
  -H 'Content-Type: application/json' \
  -d '{"id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890"}'
```

**Response:** Empty response with HTTP 200 on success.

---

### 5. Remove VM

Removes a CVM and cleans up its work directory.

**Endpoint:** `POST /prpc/RemoveVm`

**Request Parameters:**

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | VM ID (UUID) |

**Example:**
```bash
curl -X POST http://127.0.0.1:9080/prpc/RemoveVm \
  -H 'Content-Type: application/json' \
  -d '{"id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890"}'
```

**Response:** Empty response with HTTP 200 on success.

---

### 6. Update VM

Updates an existing CVM's configuration. Can update the compose file, encrypted env, user config, ports, KMS/Gateway URLs, compute resources, GPU config, and TEE mode. For resource changes (vcpu, memory, disk_size, image), the VM must be stopped first.

**Endpoint:** `POST /prpc/UpdateVm`

**Request Parameters (`UpdateVmRequest`):**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | Yes | VM ID to update |
| `compose_file` | string | No | New JSON-encoded `app-compose.json` (empty = no change) |
| `encrypted_env` | bytes | No | New encrypted env vars (empty = no change) |
| `user_config` | string | No | New user config (empty = no change) |
| `update_ports` | bool | No | Whether to update port mappings |
| `ports` | array of `PortMapping` | No | New port mapping rules (only used if `update_ports` is `true`) |
| `update_kms_urls` | bool | No | Whether to update KMS URLs |
| `kms_urls` | array of strings | No | New KMS URLs (only used if `update_kms_urls` is `true`) |
| `update_gateway_urls` | bool | No | Whether to update Gateway URLs |
| `gateway_urls` | array of strings | No | New Gateway URLs (only used if `update_gateway_urls` is `true`) |
| `gpus` | `GpuConfig` | No | New GPU configuration |
| `vcpu` | uint32 | No | New vCPU count (VM must be stopped) |
| `memory` | uint32 | No | New memory in MB (VM must be stopped) |
| `disk_size` | uint32 | No | New disk size in GB (can only grow, VM must be stopped) |
| `image` | string | No | New OS image name (VM must be stopped) |
| `no_tee` | bool | No | Disable or re-enable TEE |

**Example:**
```bash
curl -X POST http://127.0.0.1:9080/prpc/UpdateVm \
  -H 'Content-Type: application/json' \
  -d '{
    "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "compose_file": "{\"docker_compose_file\":\"...\"}",
    "encrypted_env": "<new-hex-encoded-encrypted-env>"
  }'
```

**Response:**
```json
{
  "id": "<new-app-id>"
}
```

---

### 7. Status (List VMs)

Lists all CVMs with optional filtering and pagination.

**Endpoint:** `POST /prpc/Status`

**Request Parameters (`StatusRequest`):**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `ids` | array of strings | No | Filter by specific VM IDs |
| `brief` | bool | No | If `true`, exclude `configuration` from response |
| `keyword` | string | No | Filter by keyword (matches name or ID) |
| `page` | uint32 | No | Page number (0-based) |
| `page_size` | uint32 | No | Items per page (0 = return all) |

**Example:**
```bash
# List all VMs
curl -X POST http://127.0.0.1:9080/prpc/Status \
  -H 'Content-Type: application/json' \
  -d '{}'

# List specific VMs (brief mode)
curl -X POST http://127.0.0.1:9080/prpc/Status \
  -H 'Content-Type: application/json' \
  -d '{
    "ids": ["a1b2c3d4-e5f6-7890-abcd-ef1234567890"],
    "brief": true
  }'

# Search with pagination
curl -X POST http://127.0.0.1:9080/prpc/Status \
  -H 'Content-Type: application/json' \
  -d '{
    "keyword": "my-app",
    "page": 0,
    "page_size": 10
  }'
```

**Response (`StatusResponse`):**
```json
{
  "vms": [
    {
      "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
      "name": "my-app",
      "status": "running",
      "uptime": "2h 30m",
      "app_url": "http://127.0.0.1:9205/",
      "app_id": "0xabcdef1234...",
      "instance_id": "0x123456...",
      "boot_progress": "done",
      "boot_error": "",
      "shutdown_progress": "",
      "image_version": "0.5.0",
      "events": [
        {
          "event": "boot.progress",
          "body": "setting up docker",
          "timestamp": 1707500000000
        }
      ],
      "configuration": {
        "name": "my-app",
        "image": "dstack-0.5.0",
        "vcpu": 2,
        "memory": 4096,
        "disk_size": 40,
        "ports": [],
        "kms_urls": ["https://kms.example.com:9201"],
        "gateway_urls": ["https://gw.example.com:9200"]
      }
    }
  ],
  "port_mapping_enabled": true,
  "total": 1
}
```

**VM Status values:** `"running"`, `"stopped"`, `"exited"`, `"starting"`, `"unknown"`

---

### 8. Get Info

Gets detailed information about a single VM.

**Endpoint:** `POST /prpc/GetInfo`

**Request Parameters:**

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | VM ID (UUID) |

**Example:**
```bash
curl -X POST http://127.0.0.1:9080/prpc/GetInfo \
  -H 'Content-Type: application/json' \
  -d '{"id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890"}'
```

**Response (`GetInfoResponse`):**
```json
{
  "found": true,
  "info": {
    "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "name": "my-app",
    "status": "running",
    "uptime": "2h 30m",
    "app_id": "0xabcdef1234...",
    "instance_id": "0x123456..."
  }
}
```

If the VM is not found, returns `{"found": false}`.

---

### 9. Get Compose Hash

Computes the SHA-256 hash of the compose file. Useful for debugging and SDK development.

**Endpoint:** `POST /prpc/GetComposeHash`

**Request Parameters:** Same as `VmConfiguration` (only `name` and `compose_file` are used).

**Example:**
```bash
curl -X POST http://127.0.0.1:9080/prpc/GetComposeHash \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "test",
    "compose_file": "{\"docker_compose_file\":\"...\"}",
    "image": "",
    "vcpu": 0,
    "memory": 0,
    "disk_size": 0
  }'
```

**Response:**
```json
{
  "hash": "a1b2c3d4e5f6..."
}
```

---

### 10. Get App Env Encrypt Public Key

Retrieves the X25519 public key used to encrypt environment variables for a specific app. The request is proxied to the KMS.

**Endpoint:** `POST /prpc/GetAppEnvEncryptPubKey`

**Request Parameters (`AppId`):**

| Field | Type | Description |
|-------|------|-------------|
| `app_id` | bytes | The app ID (hex-encoded) |

**Example:**
```bash
curl -X POST http://127.0.0.1:9080/prpc/GetAppEnvEncryptPubKey \
  -H 'Content-Type: application/json' \
  -d '{"app_id": "abcdef1234567890..."}'
```

**Response (`PublicKeyResponse`):**
```json
{
  "public_key": "<hex-encoded-x25519-public-key>",
  "signature": "<hex-encoded-legacy-signature>",
  "timestamp": 1707500000,
  "signature_v1": "<hex-encoded-signature-with-timestamp>"
}
```

**Signature verification:**
- `signature` (legacy): `Keccak256("dstack-env-encrypt-pubkey" + ":" + app_id + public_key)`
- `signature_v1`: `Keccak256("dstack-env-encrypt-pubkey" + ":" + app_id + timestamp_be_bytes + public_key)`

---

### 11. List Images

Lists all available OS images for launching CVMs.

**Endpoint:** `POST /prpc/ListImages`

**Request:** Empty body `{}`

**Example:**
```bash
curl -X POST http://127.0.0.1:9080/prpc/ListImages \
  -H 'Content-Type: application/json' \
  -d '{}'
```

**Response (`ImageListResponse`):**
```json
{
  "images": [
    {
      "name": "dstack-0.5.0",
      "description": "{...}",
      "version": "0.5.0",
      "is_dev": false
    },
    {
      "name": "dstack-dev-0.5.0",
      "description": "{...}",
      "version": "0.5.0",
      "is_dev": true
    }
  ]
}
```

---

### 12. Version

Returns the VMM build version and git revision.

**Endpoint:** `POST /prpc/Version`

**Request:** Empty body `{}`

**Example:**
```bash
curl -X POST http://127.0.0.1:9080/prpc/Version \
  -H 'Content-Type: application/json' \
  -d '{}'
```

**Response (`VersionResponse`):**
```json
{
  "version": "0.5.0",
  "rev": "git:abc1234567890abcdefgh"
}
```

---

### 13. Get Meta

Returns aggregated metadata about the VMM configuration (KMS, Gateway, resource limits).

**Endpoint:** `POST /prpc/GetMeta`

**Request:** Empty body `{}`

**Example:**
```bash
curl -X POST http://127.0.0.1:9080/prpc/GetMeta \
  -H 'Content-Type: application/json' \
  -d '{}'
```

**Response (`GetMetaResponse`):**
```json
{
  "kms": {
    "url": "https://kms.example.com:9201",
    "urls": ["https://kms.example.com:9201"]
  },
  "gateway": {
    "url": "https://gw.example.com:9200",
    "base_domain": "example.com",
    "port": 8082,
    "agent_port": 8090,
    "urls": ["https://gw.example.com:9200"]
  },
  "resources": {
    "max_cvm_number": 1000,
    "max_allocable_vcpu": 20,
    "max_allocable_memory_in_mb": 100000
  }
}
```

---

### 14. List GPUs

Lists available GPUs on the host.

**Endpoint:** `POST /prpc/ListGpus`

**Request:** Empty body `{}`

**Example:**
```bash
curl -X POST http://127.0.0.1:9080/prpc/ListGpus \
  -H 'Content-Type: application/json' \
  -d '{}'
```

**Response (`ListGpusResponse`):**
```json
{
  "gpus": [
    {
      "slot": "0000:3b:00.0",
      "product_id": "10de:2335",
      "description": "3D controller: NVIDIA Corporation H200 [10de:2335]",
      "is_free": true
    }
  ],
  "allow_attach_all": true
}
```

---

### 15. Reload VMs

Reloads VM state from disk and syncs with the in-memory state. Useful when VM directories have been modified externally.

**Endpoint:** `POST /prpc/ReloadVms`

**Request:** Empty body `{}`

**Example:**
```bash
curl -X POST http://127.0.0.1:9080/prpc/ReloadVms \
  -H 'Content-Type: application/json' \
  -d '{}'
```

**Response (`ReloadVmsResponse`):**
```json
{
  "loaded": 5,
  "updated": 1,
  "removed": 0
}
```

---

### 16. Resize VM (Deprecated)

> **Deprecated**: Use `UpdateVm` with `vcpu`, `memory`, `disk_size`, and `image` fields instead.

Resizes compute or storage for a VM. The VM must be stopped first.

**Endpoint:** `POST /prpc/ResizeVm`

**Request Parameters (`ResizeVmRequest`):**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | Yes | VM ID |
| `vcpu` | uint32 | No | New vCPU count |
| `memory` | uint32 | No | New memory in MB |
| `disk_size` | uint32 | No | New disk size in GB (can only grow) |
| `image` | string | No | New OS image name |

**Example:**
```bash
curl -X POST http://127.0.0.1:9080/prpc/ResizeVm \
  -H 'Content-Type: application/json' \
  -d '{
    "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "vcpu": 4,
    "memory": 8192
  }'
```

**Response:** Empty response with HTTP 200 on success.

---

### 17. Upgrade App (Deprecated)

> **Deprecated**: Use `UpdateVm` instead.

Alias for `UpdateVm`.

**Endpoint:** `POST /prpc/UpgradeApp`

---

### 18. Report DHCP Lease

Reports a DHCP lease event to the VMM. Called by the host DHCP server (e.g., dnsmasq `--dhcp-script`) when a CVM obtains an IP address. The VMM maps the MAC address to a VM and reconfigures port forwarding.

**Endpoint:** `POST /prpc/ReportDhcpLease`

**Request Parameters (`DhcpLeaseRequest`):**

| Field | Type | Description |
|-------|------|-------------|
| `mac` | string | MAC address of the guest NIC (e.g. `"02:ab:cd:ef:01:23"`) |
| `ip` | string | IPv4 address assigned by DHCP (e.g. `"192.168.122.100"`) |

**Example:**
```bash
curl -X POST http://127.0.0.1:9080/prpc/ReportDhcpLease \
  -H 'Content-Type: application/json' \
  -d '{"mac": "02:ab:cd:ef:01:23", "ip": "192.168.122.100"}'
```

**Response:** Empty response with HTTP 200 on success.

---

## Proxied Guest API (`/guest`)

These endpoints proxy RPC calls to the Guest Agent running inside a specific CVM. The VMM communicates with the guest via vsock. Each request requires the VM `id` to identify which CVM to forward the request to.

### 1. Guest Info

Retrieves attestation material and identifiers from a CVM's Guest Agent.

**Endpoint:** `POST /guest/Info`

**Request Parameters:**

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | VM ID (UUID) |

**Example:**
```bash
curl -X POST http://127.0.0.1:9080/guest/Info \
  -H 'Content-Type: application/json' \
  -d '{"id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890"}'
```

**Response (`GuestInfo`):**
```json
{
  "version": "0.5.0",
  "app_id": "<hex-encoded-app-id>",
  "instance_id": "<hex-encoded-instance-id>",
  "app_cert": "-----BEGIN CERTIFICATE-----\n...",
  "tcb_info": "<tcb-info-string>",
  "device_id": "<hex-encoded-device-id>"
}
```

---

### 2. System Info

Retrieves OS, kernel, and resource metrics from a CVM.

**Endpoint:** `POST /guest/SysInfo`

**Request Parameters:**

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | VM ID (UUID) |

**Example:**
```bash
curl -X POST http://127.0.0.1:9080/guest/SysInfo \
  -H 'Content-Type: application/json' \
  -d '{"id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890"}'
```

**Response (`SystemInfo`):**
```json
{
  "os_name": "Ubuntu",
  "os_version": "24.04",
  "kernel_version": "6.8.0-1028-intel",
  "cpu_model": "Intel Xeon",
  "num_cpus": 2,
  "total_memory": 4294967296,
  "available_memory": 3221225472,
  "used_memory": 1073741824,
  "free_memory": 2147483648,
  "total_swap": 0,
  "used_swap": 0,
  "free_swap": 0,
  "uptime": 9000,
  "loadavg_one": 1,
  "loadavg_five": 2,
  "loadavg_fifteen": 1,
  "disks": [
    {
      "name": "/dev/vda1",
      "mount_point": "/",
      "total_size": 42949672960,
      "free_size": 38654705664
    }
  ]
}
```

---

### 3. Network Info

Retrieves network interface information, DNS servers, and WireGuard status from a CVM.

**Endpoint:** `POST /guest/NetworkInfo`

**Request Parameters:**

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | VM ID (UUID) |

**Example:**
```bash
curl -X POST http://127.0.0.1:9080/guest/NetworkInfo \
  -H 'Content-Type: application/json' \
  -d '{"id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890"}'
```

**Response (`NetworkInformation`):**
```json
{
  "dns_servers": ["1.1.1.1", "1.0.0.1"],
  "gateways": [{"address": "10.0.2.2"}],
  "interfaces": [
    {
      "name": "eth0",
      "addresses": [{"address": "10.0.2.10", "prefix": 24}],
      "rx_bytes": 1234567,
      "tx_bytes": 7654321,
      "rx_errors": 0,
      "tx_errors": 0
    }
  ],
  "wg_info": "interface: wg-ds-gw..."
}
```

---

### 4. List Containers

Lists Docker containers running inside a CVM.

**Endpoint:** `POST /guest/ListContainers`

**Request Parameters:**

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | VM ID (UUID) |

**Example:**
```bash
curl -X POST http://127.0.0.1:9080/guest/ListContainers \
  -H 'Content-Type: application/json' \
  -d '{"id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890"}'
```

**Response (`ListContainersResponse`):**
```json
{
  "containers": [
    {
      "id": "abc123def456...",
      "names": ["my-app-web-1"],
      "image": "nginx:latest",
      "image_id": "sha256:abc123...",
      "created": 1707500000,
      "state": "running",
      "status": "Up 2 hours"
    }
  ]
}
```

---

### 5. Shutdown (via Guest Agent)

Initiates a graceful shutdown inside a CVM via its Guest Agent.

**Endpoint:** `POST /guest/Shutdown`

**Request Parameters:**

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | VM ID (UUID) |

**Example:**
```bash
curl -X POST http://127.0.0.1:9080/guest/Shutdown \
  -H 'Content-Type: application/json' \
  -d '{"id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890"}'
```

**Response:** Empty response with HTTP 200 on success.

---

## HTTP REST API

### 1. Web Console

Serves the VMM web dashboard UI.

| Endpoint | Description |
|----------|-------------|
| `GET /` | Current console (v1) |
| `GET /v1` | Console v1 |
| `GET /beta` | Same as v1 |
| `GET /v0` | Legacy console v0 |

**Example:**
```bash
curl http://127.0.0.1:9080/
```

**Response:** HTML page.

---

### 2. VM Logs

Streams serial console, stdout, or stderr logs from a CVM.

**Endpoint:** `GET /logs`

**Query Parameters:**

| Parameter | Type | Required | Description | Default |
|-----------|------|----------|-------------|---------|
| `id` | string | Yes | VM ID (UUID) | — |
| `follow` | bool | No | Follow log output (streaming) | `false` |
| `ansi` | bool | No | Keep ANSI escape codes in output | `false` |
| `lines` | uint | No | Number of lines to show from the end | `10000` |
| `ch` | string | No | Log channel: `"serial"`, `"stdout"`, or `"stderr"` | `"serial"` |

**Requires:** API token authentication.

**Example:**
```bash
# Get last 100 lines of serial console
curl -H "Authorization: Bearer <token>" \
  "http://127.0.0.1:9080/logs?id=a1b2c3d4-e5f6-7890-abcd-ef1234567890&lines=100"

# Follow serial logs in real-time
curl -H "Authorization: Bearer <token>" \
  "http://127.0.0.1:9080/logs?id=a1b2c3d4-e5f6-7890-abcd-ef1234567890&follow=true"

# Get stdout logs with ANSI colors
curl -H "Authorization: Bearer <token>" \
  "http://127.0.0.1:9080/logs?id=a1b2c3d4-e5f6-7890-abcd-ef1234567890&ch=stdout&ansi=true"
```

**Response:** Plain text stream of log lines.

---

### 3. OpenAPI Documentation

Auto-generated Swagger UI for exploring the VMM APIs interactively.

**Endpoint:** `GET /api-docs/`

**Example:**
```bash
# Open in browser
curl http://127.0.0.1:9080/api-docs/
```

---

## Host API (vsock, internal)

The VMM also exposes a **Host API** over vsock (default port `10000`) for communication with CVMs. This API is **not** accessible via HTTP — it is only reachable from guest VMs via the vsock transport.

| Endpoint | Description |
|----------|-------------|
| `Info` | Returns VMM host info (name, version) |
| `Notify` | Receives event notifications from CVM (boot progress, errors) |
| `GetSealingKey` | Returns a sealing key from the local SGX Key Provider (requires `key_provider.enabled`) |

These endpoints are used internally by `dstack-util` running inside CVMs and are not intended for direct user interaction.

---

## Error Responses

All RPC endpoints may return an error with the following format:

```json
{
  "message": "error description"
}
```

Common HTTP status codes:

| Code | Description |
|------|-------------|
| `200` | Success |
| `400` | Invalid request (bad parameters, invalid compose file, etc.) |
| `404` | VM not found |
| `500` | Internal server error |
