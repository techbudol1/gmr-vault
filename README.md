# GMR Vault

GMR Vault is the self-hosted signing service used by GMR Engine. It creates and stores encrypted EVM keys, performs authorized signing in process memory, and returns signatures or signed transactions—not private keys.

## Security model

- Private keys are generated inside Vault.
- Key material is encrypted with AES-256-GCM before storage in Memgraph.
- The master key is supplied at runtime through `GMR_VAULT_MASTER_KEY` and must never be committed.
- Every wallet creation and signing operation is audited.
- GMR Engine should reach Vault through a private network with a dedicated internal credential.

Vault is encrypted server-side custody for the current testnet architecture; it is not an enclave, MPC, or HSM implementation.

## Local development

```bash
cp .env.gmr-vault.example .env.gmr-vault
docker compose up -d gmr-vault-memgraph
go run ./cmd/api
```

Required configuration:

```env
GMR_VAULT_ADDR=:8091
GMR_VAULT_INTERNAL_API_KEY=replace-with-a-strong-internal-key
GMR_VAULT_MASTER_KEY=replace-with-a-strong-master-key
GMR_VAULT_MEMGRAPH_URI=bolt://localhost:7690
```

## Internal API

All `/v1` endpoints require `X-GMR-Vault-Key`. GMR Engine uses Vault to create project wallets and request message, typed-data, or transaction signatures. The API never returns raw private keys.

## Production requirements

- Place the master key in a managed KMS/HSM or equivalent secret-management system.
- Isolate Vault on a private network and use mTLS or equivalent service authentication.
- Enforce per-wallet signing policies, approval controls, monitoring, backup, and key-rotation procedures.
- Do not expose Vault directly to browsers or public internet traffic.
