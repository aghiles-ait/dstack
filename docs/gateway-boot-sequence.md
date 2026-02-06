# Gateway Boot Sequence Diagram

## Sequence: Gateway CVM Boot and Key Provisioning

```mermaid
sequenceDiagram
    participant VMM as VMM (Host)
    participant CVM as Gateway CVM
    participant Prep as dstack-prepare.sh
    participant KMS as KMS (CVM)
    participant Auth as auth-simple (Host)
    participant App as Gateway Container
    participant GuestAgent as Guest Agent

    Note over VMM,App: Phase 1: CVM Boot
    VMM->>CVM: Start CVM (TDX)
    CVM->>CVM: Boot OS Image
    CVM->>Prep: Execute dstack-prepare.sh
    
    Note over Prep: Measure App Info
    Prep->>Prep: measure_app_info()<br/>- app_id<br/>- compose_hash<br/>- device_id<br/>- MRs (measurements)
    
    Note over Prep,KMS: Phase 2: Request App Keys
    Prep->>KMS: GetTempCaCert()<br/>(Initial RA-TLS setup)
    KMS-->>Prep: temp_ca_cert + temp_ca_key
    
    Prep->>Prep: Generate RA-TLS client cert<br/>with TDX quote<br/>(for KMS communication)
    
    Prep->>KMS: GetAppKey(vm_config)<br/>+ RA-TLS cert with TDX quote
    
    Note over KMS: Verify TDX Quote
    KMS->>KMS: verify_with_ra_pubkey()<br/>Verify TDX attestation
    
    Note over KMS,Auth: Phase 3: Authorization Check
    KMS->>Auth: POST /bootAuth/app<br/>{boot_info, device_id}
    
    Auth->>Auth: Check compose_hash<br/>in auth-config.json
    Auth->>Auth: Check device_id<br/>(if allowAnyDevice=false)
    
    alt Authorized
        Auth-->>KMS: {isAllowed: true}
        KMS->>KMS: Derive app keys<br/>- disk_crypt_key<br/>- env_encrypt_key<br/>- k256_key
        KMS-->>Prep: AppKeyResponse<br/>(keys + gateway_app_id)
    else Not Authorized
        Auth-->>KMS: {isAllowed: false, reason: "..."}
        KMS-->>Prep: Error: "App not allowed"
        Prep->>CVM: Reboot/Shutdown
    end
    
    Note over Prep,App: Phase 4: Mount Disk & Start App
    Prep->>Prep: Mount encrypted disk<br/>using disk_crypt_key
    Prep->>Prep: Save app keys to /data
    Prep->>App: Start docker-compose<br/>(Gateway container)
    
    Note over App: Phase 5: Gateway Initialization
    App->>App: Generate WireGuard keys
    App->>App: Request RPC RA-TLS cert<br/>(via Guest Agent)
    App->>GuestAgent: GetTlsKey()<br/>(with TDX quote)
    GuestAgent->>GuestAgent: Generate CSR<br/>with TDX quote
    GuestAgent->>KMS: SignCert(CSR + quote)
    KMS->>KMS: Verify TDX quote<br/>Sign CSR
    KMS-->>GuestAgent: Signed certificate chain
    GuestAgent-->>App: RPC RA-TLS cert<br/>(signed by KMS)
    App->>App: Check for proxy certs<br/>in KvStore
    
    alt No Proxy Certs Found
        App->>App: Generate self-signed<br/>wildcard cert<br/>(*.apps.ovh-tdx-dev.iex.ec)
        App->>App: Save to KvStore
    end
    
    App->>App: Start Gateway services<br/>- RPC (9202)<br/>- Admin (9203)<br/>- Proxy (9204)
    
    Note over VMM,App: Gateway Ready!
```

## Key Points

1. **dstack-prepare.sh**: A bash script included in the OS image that runs as a systemd service (`dstack-prepare.service`) at CVM boot. It prepares the environment (TDX setup, disk mounting) and calls `dstack-util setup` which performs the actual app key provisioning.

2. **GetAppKey is automatic**: Called during CVM boot by `dstack-util setup` (invoked by `dstack-prepare.sh`) in the `setup_fs()` phase.

3. **Attestation happens first**: KMS verifies TDX quote before calling auth-simple.

4. **auth-simple is a webhook**: KMS calls it via HTTP POST to `/bootAuth/app`.

5. **Keys are derived**: KMS derives app-specific keys from root keys using app_id.

6. **Disk encryption**: The `disk_crypt_key` is used to mount the encrypted data disk.

7. **Two types of RA-TLS certificates**:
   - **Boot-time RA-TLS**: Used during `GetAppKey` to authenticate the CVM to KMS (Phase 2)
   - **RPC RA-TLS**: Gateway's RPC server certificate signed by KMS after container startup (Phase 5)

## Endpoints Reference

- **KMS RPC**: `https://kms.ovh-tdx-dev.iex.ec:9201/prpc`
- **auth-simple**: `http://127.0.0.1:3001/bootAuth/app` (from KMS CVM perspective: `http://10.0.2.2:3001`)
- **Guest Agent logs**: `http://127.0.0.1:9206/logs/<container-name>` (Gateway) or `http://127.0.0.1:9205/logs/<container-name>` (KMS)
