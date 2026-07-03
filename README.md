# GMR Vault

GMR Vault is the self-hosted custody service for GMR Engine.

It stores encrypted EVM private keys, signs requests in memory, and returns only signatures or signed raw transactions. It does not expose private keys through any API.

## Local Setup

Start the Vault graph:

```bash
docker compose up -d gmr-vault-memgraph
```

Required environment:

```bash
GMR_VAULT_ADDR=:8091
GMR_VAULT_INTERNAL_API_KEY=replace-with-32-plus-character-internal-key
GMR_VAULT_MASTER_KEY=replace-with-32-plus-character-master-key
GMR_VAULT_MEMGRAPH_URI=bolt://localhost:7690
```

Run:

```bash
cd gmr-vault
go run ./cmd/api
```

## API

All `/v1` endpoints require:

```text
X-GMR-Vault-Key: <GMR_VAULT_INTERNAL_API_KEY>
```

### Create Wallet

```http
POST /v1/wallets
```

```json
{
  "projectId": "project-id",
  "walletType": "server_admin",
  "metadata": "{}"
}
```

Returns the wallet address and metadata, never the private key.

### Sign Message

```http
POST /v1/sign-message
```

```json
{
  "walletId": "vault-wallet-id",
  "message": "hello",
  "format": "text"
}
```

### Sign Typed Data

```http
POST /v1/sign-typed-data
```

```json
{
  "walletId": "vault-wallet-id",
  "typedData": {
    "types": {},
    "primaryType": "Permit",
    "domain": {},
    "message": {}
  }
}
```

### Sign Transaction

```http
POST /v1/sign-transaction
```

```json
{
  "walletId": "vault-wallet-id",
  "transaction": {
    "chainId": "421614",
    "nonce": 0,
    "to": "0x...",
    "value": "0",
    "data": "0x",
    "gasLimit": 21000,
    "maxFeePerGas": "100000000",
    "maxPriorityFeePerGas": "100000000"
  }
}
```

Returns `rawTransaction` and `transactionHash`.

## Security Model

- Private keys are generated inside Vault.
- Keys are encrypted with AES-256-GCM before Memgraph storage.
- The master key comes from `GMR_VAULT_MASTER_KEY` and must never be committed.
- Signing decrypts only in process memory.
- Every wallet creation and signing action writes an audit log.
- GMR Engine should call Vault over a private network in production.

## Current Limits

This MVP is encrypted self-custody, not enclave custody. To harden further:

- Move `GMR_VAULT_MASTER_KEY` into KMS/HSM.
- Deploy Vault in an isolated private subnet.
- Add mTLS between Engine and Vault.
- Add per-wallet policy checks and approval workflows.
- Add key rotation and envelope re-encryption.
