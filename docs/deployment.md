# Deploying dstack

This guide covers deploying dstack on bare metal TDX hosts.

## Overview

dstack can be deployed in two ways:

- **Dev Deployment**: All components run directly on the host. For local development and testing only - no security guarantees.
- **Production Deployment**: KMS and Gateway run as CVMs with hardware-rooted security. Uses auth server for authorization and OS image whitelisting. Required for any deployment where security matters.

## Prerequisites

**Hardware:**
- Bare metal TDX server ([setup guide](https://github.com/canonical/tdx))
- At least 16GB RAM, 100GB free disk space
- Public IPv4 address
- Optional: NVIDIA H100 or Blackwell GPU for [Confidential Computing](https://www.nvidia.com/en-us/data-center/solutions/confidential-computing/) workloads

**Network:**
- Domain with DNS access (for Gateway TLS)

> **Note:** See [Hardware Requirements](https://docs.phala.network/dstack/hardware-requirements) for server recommendations.

---

## Dev Deployment

This approach runs all components directly on the host for local development and testing.

> **Warning:** Dev deployment uses KMS in dev mode with no security guarantees. Do NOT use for production.

### Install Dependencies

```bash
# Ubuntu 24.04
sudo apt install -y build-essential chrpath diffstat lz4 wireguard-tools xorriso

# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

### Build Configuration

```bash
git clone https://github.com/Dstack-TEE/meta-dstack.git --recursive
cd meta-dstack/
mkdir build && cd build
../build.sh hostcfg
```

Edit the generated `build-config.sh` for your environment. The minimal required changes are:

| Variable | Description |
|----------|-------------|
| `KMS_DOMAIN` | DNS domain for KMS RPC (e.g., `kms.ovh-tdx-dev.iex.ec`) |
| `GATEWAY_DOMAIN` | DNS domain for Gateway RPC (e.g., `gateway.ovh-tdx-dev.iex.ec`) |
| `GATEWAY_PUBLIC_DOMAIN` | Public base domain for app routing (e.g., `apps.ovh-tdx-dev.iex.ec`) |

**TLS Certificates:**

The Gateway requires TLS certificates. Configure Certbot with Cloudflare:

```bash
CERTBOT_ENABLED=true
CF_API_TOKEN=<your-cloudflare-token>
```

The certificates will be obtained automatically via ACME DNS-01 challenge. The KMS auto-generates its own certificates during bootstrap.

Other variables like ports and CID pool settings have sensible defaults.

```bash
vim ./build-config.sh
../build.sh hostcfg
```

### Download Guest Image

```bash
../build.sh dl 0.5.5
```

### Configure Gateway for Debug Mode

The generated `gateway.toml` needs to be modified to skip attestation (since there's no guest agent in dev mode). Add the debug section with `key_file = ""` to skip debug certificate generation:

```bash
# Add to gateway.toml under [core] section:
cat >> gateway.toml << 'EOF'

[core.debug]
insecure_skip_attestation = true
key_file = ""
EOF
```

> **Note:** Setting `key_file = ""` is required because the default config includes `key_file = "debug_key.json"`, which would cause the Gateway to fail if the file doesn't exist.

### Configure Network Bindings for External Access

If you need to access KMS and Gateway from external machines (not just localhost), update the address bindings in the generated config files. The default `build.sh` generates configs with `127.0.0.1`, which only allows local access.

**For KMS (`kms.toml`):**

```bash
# Edit kms.toml and change:
[rpc]
address = "0.0.0.0"  # Change from "127.0.0.1" to allow external access

[core.onboard]
address = "0.0.0.0"  # Change from "127.0.0.1" to allow external access
```

**For Gateway (`gateway.toml`):**

```bash
# Edit gateway.toml and change:
address = "0.0.0.0"  # Change from "127.0.0.1" to allow external access
```

> **Note:** Binding to `0.0.0.0` allows access from any network interface. For production, consider using firewall rules to restrict access. The proxy `listen_addr` is already set to `0.0.0.0` by default.

### Create Self-Signed Gateway RPC certificate

The certificate CN must match the `rpc_domain` configured in `gateway.toml`:

```bash
# Get the rpc_domain from gateway.toml (e.g., gateway.ovh-tdx-dev.iex.ec)
RPC_DOMAIN=$(grep "^rpc_domain" gateway.toml | cut -d'"' -f2)

openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout certs/gateway-rpc.key \
  -out certs/gateway-rpc.cert \
  -subj "/CN=${RPC_DOMAIN}"

# Use KMS root CA as Gateway CA (created when KMS starts)
# This will be created automatically when you first run KMS
```

### Run Components

### Start Components

Start KMS first (it generates `certs/root-ca.crt`):

```bash
./dstack-kms -c kms.toml
```

Copy the KMS CA cert for Gateway (in another terminal):

```bash
cp certs/root-ca.crt certs/gateway-ca.cert
```

Then start Gateway and VMM:

```bash
sudo ./dstack-gateway -c gateway.toml
sudo ./dstack-vmm -c vmm.toml
```

> **Note:** This deployment uses KMS in dev mode without an auth server. For production deployments with proper security, see [Production Deployment](#production-deployment) below.

### Access the Services

| Service | URL | Notes |
|---------|-----|-------|
| VMM Dashboard | `http://localhost:<VMM_PORT>` | Web UI for deploying CVMs |
| KMS | `https://localhost:<KMS_PORT>` | Use `-k` with curl (self-signed) |
| Gateway | `https://localhost:<GATEWAY_PORT>` | Use `-k` with curl (self-signed) |

**Note:** Browsers will show certificate warnings for self-signed certs. Click "Advanced" → "Proceed" to continue.

### Accessing Deployed Applications

Once your application is deployed in a CVM, you can access it through the dstack Gateway using the following URL format:

```
https://<app_id>[-<port>][<suffix>].<base_domain>:<gateway_port>
```

**URL Format Components:**

- **`<app_id>`**: The application identifier (hexadecimal hash, e.g., `ebe1e087afff39e018e17a0a42f0be8622390782`)
- **`<port>`**: Optional port number (defaults to 80 for HTTP, 443 for HTTPS)
- **`<suffix>`**: Optional suffix flags:
  - `s`: Enable TLS passthrough (proxy passes encrypted traffic directly to backend)
  - `g`: Enable HTTP/2 (gRPC) support
- **`<base_domain>`**: The base domain configured for the Gateway (e.g., `apps.ovh-tdx-dev.iex.ec`)
- **`<gateway_port>`**: The **TLS proxy port** where the Gateway listens for application traffic (configured in `gateway.toml` under `[core.proxy] listen_port`, e.g., `13644` in dev mode, `443` in production). This is different from the Gateway RPC port (used for inter-service communication) and the WireGuard port (used for VPN tunnels).

**Examples:**

```bash
# Basic HTTP access (port 80)
curl -k https://ebe1e087afff39e018e17a0a42f0be8622390782.apps.ovh-tdx-dev.iex.ec:13644/

# Custom port (e.g., 8080)
curl -k https://ebe1e087afff39e018e17a0a42f0be8622390782-8080.apps.ovh-tdx-dev.iex.ec:13644/

# TLS passthrough
curl -k https://ebe1e087afff39e018e17a0a42f0be8622390782-443s.apps.ovh-tdx-dev.iex.ec:13644/

# HTTP/2 (gRPC)
curl -k https://ebe1e087afff39e018e17a0a42f0be8622390782-8080g.apps.ovh-tdx-dev.iex.ec:13644/
```

**Finding Your App ID:**

The app ID is generated when you deploy your application. You can find it:
- In the VMM dashboard after deployment
- In the Gateway logs when the app registers: `grep RegisterCvm gateway.log`
- Via the VMM API: `curl http://localhost:<vmm_port>/vm`

**Notes:**

- Use `-k` flag with curl to skip certificate verification (required for self-signed certificates in dev mode)
- The Gateway automatically routes traffic to the correct CVM instance based on the app ID
- Multiple instances of the same app are load-balanced automatically

For more details, see the [Usage Guide](./usage.md).

---

## Production Deployment

For production, deploy KMS and Gateway as CVMs with hardware-rooted security. Production deployments require:
- KMS running in a CVM (not on the host)
- Auth server for authorization (webhook mode)

### Production Checklist

**Required:**

1. Set up TDX host with dstack-vmm
2. Deploy KMS as CVM (with auth server)
3. Deploy Gateway as CVM

**Optional Add-ons:**

4. [Zero Trust HTTPS](#4-zero-trust-https-optional)
5. [Certificate Transparency monitoring](#5-certificate-transparency-monitoring-optional)
6. [Multi-node deployment](#6-multi-node-deployment-optional)
7. [On-chain governance](./onchain-governance.md) - Smart contract-based authorization

---

### 1. Set Up TDX Host

Clone and build dstack-vmm:

```bash
git clone https://github.com/Dstack-TEE/dstack
cd dstack
cargo build --release -p dstack-vmm -p supervisor
mkdir -p vmm-data
cp target/release/dstack-vmm vmm-data/
cp target/release/supervisor vmm-data/
cd vmm-data/
```

Create `vmm.toml`:

```toml
address = "tcp:0.0.0.0:9080"
reuse = true
image_path = "./images"
run_path = "./run/vm"

[cvm]
kms_urls = []
gateway_urls = []
cid_start = 30000
cid_pool_size = 1000

[cvm.port_mapping]
enabled = true
address = "127.0.0.1"
range = [
    { protocol = "tcp", from = 1, to = 20000 },
    { protocol = "udp", from = 1, to = 20000 },
]

[host_api]
address = "vsock:2"
port = 10000

[key_provider]
enabled = true
address = "127.0.0.1"
port = 3443
```

Download guest images from [meta-dstack releases](https://github.com/Dstack-TEE/meta-dstack/releases) and extract to `./images/`.

> For reproducible builds and verification, see the [Security Model](./security/security-model.md).

Start VMM:

```bash
./dstack-vmm -c vmm.toml
```

---

### 2. Deploy KMS as CVM

Production KMS requires:
- **KMS**: The key management service inside a CVM
- **Auth server**: Webhook server that validates boot requests and returns authorization decisions

#### Auth Server Options

| Server | Use Case | Configuration |
|--------|----------|---------------|
| [auth-simple](../kms/auth-simple/) | Config-file-based whitelisting | JSON config file |
| [auth-eth](../kms/auth-eth/) | On-chain governance via smart contracts | Ethereum RPC + contract |
| Custom | Your own authorization logic | Implement webhook interface |

All auth servers implement the same webhook interface:
- `GET /` - Health check
- `POST /bootAuth/app` - App boot authorization
- `POST /bootAuth/kms` - KMS boot authorization

#### Using auth-simple (Config-Based)

auth-simple validates boot requests against a JSON config file.

Create `auth-config.json` for initial KMS deployment:

```json
{
  "osImages": ["0x<os-image-hash>"],
  "kms": { "allowAnyDevice": true },
  "apps": {}
}
```

Run auth-simple:

```bash
cd kms/auth-simple
bun install
PORT=3001 AUTH_CONFIG_PATH=/home/aghiles/dstack/kms/auth-simple/auth-config.json bun run start
```

For adding Gateway, apps, and other config fields, see [auth-simple Operations Guide](./auth-simple-operations.md).

#### Using auth-eth (On-Chain)

For decentralized governance via smart contracts, see [On-Chain Governance](./onchain-governance.md).

#### Getting OS Image Hash

The OS image hash is in the `digest.txt` file inside the guest image tarball:

```bash
# Extract hash from release tarball
tar -xzf dstack-0.5.5.tar.gz
cat dstack-0.5.5/digest.txt
# Output: 0b327bcd642788b0517de3ff46d31ebd3847b6c64ea40bacde268bb9f1c8ec83
```

Add `0x` prefix for auth-simple config: `0x0b327bcd...`

#### Start SGX Key Provider

**Important:** The KMS CVM uses a local SGX Key Provider to obtain its sealing keys. This service must be running before deploying KMS.

The Key Provider is an SGX enclave that:
- Derives sealing keys from SGX hardware measurements
- Provides keys to CVMs after validating their TDX quotes
- Runs on port 3443

**Start the Key Provider:**

```bash
cd dstack/key-provider-build/
docker compose up -d
```

**Verify it's running:**

```bash
docker ps | grep key-provider
# Should show: gramine-sealing-key-provider
```

> **Note:** The Key Provider requires SGX hardware (`/dev/sgx_enclave`, `/dev/sgx_provision`). Verify SGX is available with `ls /dev/sgx*`.

#### Deploy KMS CVM

Choose the deployment script based on your auth server:

**For auth-simple (external webhook):**

auth-simple runs on your infrastructure, outside the CVM.

```bash
cd dstack/kms/dstack-app/
```

Edit `.env.simple`:

```bash
VMM_RPC=http://127.0.0.1:9080
AUTH_WEBHOOK_URL=http://10.0.2.2:3001 # Auth server address (address of the qemu gateway since we use user mode (slirp) connection)
KMS_RPC_ADDR=0.0.0.0:9201
GUEST_AGENT_ADDR=127.0.0.1:9205
OS_IMAGE=dstack-dev-0.5.5
IMAGE_DOWNLOAD_URL=https://github.com/Dstack-TEE/meta-dstack/releases/download/v0.5.5/dstack-dev-0.5.5.tar.gz
VERIFY_IMAGE=false # Bug to diagnose
KMS_IMAGE=dstacktee/dstack-kms@sha256:11ac59f524a22462ccd2152219b0bec48a28ceb734e32500152d4abefab7a62a
```

Then run:

```bash
./deploy-simple.sh
```

**For auth-eth (on-chain governance):**

> See [On-Chain Governance Guide](./onchain-governance.md) for deploying KMS with smart contract-based authorization.

**Monitor startup:**

```bash
tail -f ../../vmm-data/run/vm/<vm-id>/serial.log
```

Wait for `[  OK  ] Finished App Compose Service.`

#### Bootstrap KMS

Open `http://127.0.0.1:9201/` in your browser.

1. Click **Bootstrap**
2. Enter the domain for your KMS (e.g., `kms.example.com`)
3. Click **Finish setup**

![KMS Bootstrap](assets/kms-bootstrap.png)

The KMS will display its public key and TDX quote:

![KMS Bootstrap Result](assets/kms-bootstrap-result.png)

---

### 3. Deploy Gateway as CVM

#### Prerequisites

Before deploying Gateway:
1. Register the Gateway app in your auth server config (add to `apps` section in `auth-config.json`)
2. Note the App ID you assign - you'll need it for the `.env` file

For on-chain governance, see [On-Chain Governance](./onchain-governance.md#register-gateway-app) for registration steps.

#### Deploy Gateway CVM

```bash
cd dstack/gateway/dstack-app/
./deploy-to-vmm.sh
```

Edit `.env` with required variables:

```bash
# VMM connection (use TCP if VMM is on same host, or remote URL)
VMM_RPC=http://127.0.0.1:9080

# Optional: Cloudflare API token for Let's Encrypt DNS-01 challenge
# If not set, Gateway will use self-signed certificates
# CF_API_TOKEN=your_cloudflare_api_token

# Domain configuration
SRV_DOMAIN=ovh-tdx-dev.iex.ec
PUBLIC_IP=$(curl -s ifconfig.me)

# Gateway app ID (from registration above)
GATEWAY_APP_ID=32467b43BFa67273FC7dDda0999Ee9A12F2AaA08

# KMS URL (the KMS must be running and accessible)
KMS_URL=https://127.0.0.1:9201

# Gateway URLs
MY_URL=https://gateway.example.com:9202
BOOTNODE_URL=https://gateway.example.com:9202

# WireGuard (uses same port as RPC)
WG_ADDR=0.0.0.0:9202

# Network settings
SUBNET_INDEX=0
ACME_STAGING=no  # Set to 'yes' for testing
OS_IMAGE=dstack-0.5.5
```

**Note on hex formats:**
- Gateway `.env` file: Use raw hex without `0x` prefix (e.g., `GATEWAY_APP_ID=32467b43...`)
- auth-simple config: Use `0x` prefix (e.g., `"0x32467b43..."`). The server normalizes both formats.

Run the script again:

```bash
./deploy-to-vmm.sh
```

The script will display the compose file and compose hash, then prompt for confirmation:

```
Docker compose file:
...
Compose hash: 0x700a50336df7c07c82457b116e144f526c29f6d8...
Configuration:
...
Continue? [y/N]
```

**Before pressing 'y'**, add the compose hash to your auth server whitelist:
- For auth-simple: Add to `composeHashes` array in `auth-config.json`
- For auth-eth: Use `app:add-hash` (see [On-Chain Governance](./onchain-governance.md#register-gateway-app))

Then return to the first terminal and press 'y' to deploy.

#### Update VMM Configuration

After Gateway is running, update `vmm.toml` with KMS and Gateway URLs:

```toml
[cvm]
kms_urls = ["https://kms.ovh-tdx-dev.iex.ec:9201"]
gateway_urls = ["https://gateway.ovh-tdx-dev.iex.ec:9202"]
```

Restart dstack-vmm to apply changes.

---

### 4. Zero Trust HTTPS (Optional)

Generate TLS certificates inside the TEE with automatic CAA record management.

Configure in `build-config.sh`:

```bash
GATEWAY_CERT=${CERTBOT_WORKDIR}/live/cert.pem
GATEWAY_KEY=${CERTBOT_WORKDIR}/live/key.pem
CF_API_TOKEN=<your-cloudflare-token>
ACME_URL=https://acme-v02.api.letsencrypt.org/directory
```

Run certbot:

```bash
RUST_LOG=info,certbot=debug ./certbot renew -c certbot.toml
```

This will:
- Create an ACME account
- Set CAA DNS records on Cloudflare
- Request and auto-renew certificates

---

### 5. Certificate Transparency Monitoring (Optional)

Monitor for unauthorized certificates issued to your domain.

```bash
cargo build --release -p ct_monitor
./target/release/ct_monitor \
  --gateway-uri https://<gateway-domain> \
  --domain <your-domain>
```

**How it works:**
1. Fetches known public keys from Gateway (`/acme-info` endpoint)
2. Queries crt.sh for certificates issued to your domain
3. Verifies each certificate's public key matches the known keys
4. Logs errors (❌) when certificates are issued to unknown public keys

The monitor runs in a loop, checking every 60 seconds. Integrate with your alerting system by monitoring stderr for error messages.

---

### 6. Multi-Node Deployment (Optional)

Scale by adding VMM nodes and KMS replicas for high availability.

#### Adding VMM Nodes

On each additional TDX host:
1. Set up dstack-vmm (see step 1)
2. Configure `vmm.toml` with existing KMS/Gateway URLs
3. Start VMM

```toml
[cvm]
kms_urls = ["https://kms.example.com:9201"]
gateway_urls = ["https://gateway.example.com:9202"]
```

#### Adding KMS Replicas (Onboarding)

Additional KMS instances can onboard from an existing KMS to share the same root keys. This enables:
- High availability (multiple KMS nodes)
- Geographic distribution
- Load balancing

**How it works:**

1. New KMS starts in onboard mode (empty `auto_bootstrap_domain`)
2. New KMS calls `GetTempCaCert` on source KMS
3. New KMS generates RA-TLS certificate with TDX quote
4. New KMS calls `GetKmsKey` with mTLS authentication
5. Source KMS verifies attestation via `bootAuth/kms` webhook
6. If approved, source KMS returns root keys
7. Both KMS instances now derive identical keys

**Configure new KMS for onboarding:**

```toml
[core.onboard]
enabled = true
auto_bootstrap_domain = ""   # Empty = onboard mode
quote_enabled = true         # Require TDX attestation
address = "0.0.0.0"
port = 9203                  # HTTP port for onboard UI
```

**Trigger onboard via API:**

```bash
curl -X POST http://<new-kms>:9203/prpc/Onboard.Onboard?json \
  -H "Content-Type: application/json" \
  -d '{"source_url": "https://<existing-kms>:9201/prpc", "domain": "kms2.example.com"}'
```

**Finish and restart:**

```bash
curl http://<new-kms>:9203/finish
# Restart KMS - it will now serve as a full KMS with shared keys
```

> **Note:** For KMS onboarding with `quote_enabled = true`, add the KMS mrAggregated hash to your auth server's `kms.mrAggregated` whitelist.

---

## Deploying Apps

After setup, deploy apps via the VMM dashboard or CLI.

### Register App

Before deploying, register your app in your auth server:
- For auth-simple: See [auth-simple Operations Guide](./auth-simple-operations.md#adding-an-app)
- For auth-eth: See [On-Chain Governance](./onchain-governance.md#register-apps-on-chain)

### Deploy via UI

Open `http://localhost:9080`:

![App Deploy](assets/app-deploy.png)

- Select the OS image
- Enter the App ID (from registration above)
- Upload your `docker-compose.yaml`

After startup, click **Dashboard** to view:

![App Board](assets/app-board.png)

---

## Troubleshooting

### Error: vhost-vsock: unable to set guest cid: Address already in use

The CID range conflicts with existing VMs.

1. Find used CIDs: `ps aux | grep 'guest-cid='`
2. Update `vmm.toml`:
   ```toml
   [cvm]
   cid_start = 33000
   cid_pool_size = 1000
   ```

### High-concurrency deployments: conntrack table full

When running Gateway with many concurrent connections (>100K), the host's conntrack table may fill up, causing silent packet drops:

```
dmesg: nf_conntrack: table full, dropping packet
```

Each proxied connection creates multiple conntrack entries (client→gateway, gateway→WireGuard→backend). The default `nf_conntrack_max` (typically 262,144) is insufficient for high-concurrency gateways.

**Fix:**

```bash
# Check current limit
sysctl net.netfilter.nf_conntrack_max

# Increase for production (persistent)
echo "net.netfilter.nf_conntrack_max = 1048576" >> /etc/sysctl.d/99-dstack.conf
echo "net.netfilter.nf_conntrack_buckets = 262144" >> /etc/sysctl.d/99-dstack.conf
sysctl -p /etc/sysctl.d/99-dstack.conf
```

Also increase inside bridge-mode CVMs if they handle many connections:

```bash
sysctl -w net.netfilter.nf_conntrack_max=524288
```

**Sizing rule of thumb:** Set `nf_conntrack_max` to at least 4× your target concurrent connection count (each connection may use 2-3 conntrack entries across NAT/bridge layers).

### Error: Operation not permitted when building guest image

Ubuntu 23.10+ restricts unprivileged user namespaces:

```bash
sudo sysctl kernel.apparmor_restrict_unprivileged_userns=0
```
