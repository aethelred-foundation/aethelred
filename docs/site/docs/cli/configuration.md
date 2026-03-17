# CLI Configuration

The Aethelred CLI reads configuration from a TOML file and environment variables. The default config path is `~/.config/aethelred/config.toml` (or the OS-appropriate config directory).

## Configuration File

Generate a default configuration:

```bash
aethelred init --network testnet
```

### Full `config.toml` Reference

```toml
# Network to connect to: mainnet, testnet, devnet, local
network = "testnet"

# RPC and API endpoints (auto-set when you switch networks)
rpc_endpoint = "https://testnet-rpc.aethelred.io"
api_endpoint = "https://testnet-api.aethelred.io"

# Chain identifier
chain_id = "aethelred-testnet-1"

# Output format: text, json, yaml, table
output_format = "text"

# Keyring backend: os, file, test
keyring_backend = "os"

# Default account for signing transactions
default_account = "my-validator"

# Gas configuration
[gas]
limit = 200000
price = "0.025uaethel"
adjustment = 1.3
```

## Environment Variables

Every config key can be overridden with an environment variable prefixed by `AETHELRED_`:

| Variable | Config Key | Example |
|----------|-----------|---------|
| `AETHELRED_NETWORK` | `network` | `mainnet` |
| `AETHELRED_RPC_ENDPOINT` | `rpc_endpoint` | `https://rpc.aethelred.io` |
| `AETHELRED_API_ENDPOINT` | `api_endpoint` | `https://api.aethelred.io` |
| `AETHELRED_CHAIN_ID` | `chain_id` | `aethelred-mainnet-1` |
| `AETHELRED_OUTPUT_FORMAT` | `output_format` | `json` |
| `AETHELRED_KEYRING_BACKEND` | `keyring_backend` | `file` |
| `AETHELRED_GAS_LIMIT` | `gas.limit` | `300000` |
| `AETHELRED_GAS_PRICE` | `gas.price` | `0.05uaethel` |

Environment variables take precedence over the config file. CLI flags take precedence over both.

## Network Profiles

The CLI ships with four built-in network profiles:

| Network | RPC Endpoint | Chain ID | Explorer |
|---------|-------------|----------|----------|
| `mainnet` | `https://rpc.aethelred.io` | `aethelred-mainnet-1` | [explorer.aethelred.io](https://explorer.aethelred.io) |
| `testnet` | `https://testnet-rpc.aethelred.io` | `aethelred-testnet-1` | [testnet.explorer.aethelred.io](https://testnet.explorer.aethelred.io) |
| `devnet` | `https://devnet-rpc.aethelred.io` | `aethelred-devnet-1` | [devnet.explorer.aethelred.io](https://devnet.explorer.aethelred.io) |
| `local` | `http://localhost:26657` | `aethelred-local-1` | `http://localhost:8080` |

Switch networks on the fly:

```bash
# Via CLI flag (per-command)
aethelred --network mainnet status

# Via config command (persistent)
aethelred config set network mainnet
```

Testnet and devnet include a faucet at `https://faucet.aethelred.io` and `https://devnet-faucet.aethelred.io` respectively.

## Keyring Setup

The CLI supports three keyring backends:

| Backend | Storage | Use Case |
|---------|---------|----------|
| `os` | macOS Keychain / Linux Secret Service / Windows Credential Manager | **Recommended** for workstations |
| `file` | Encrypted file at `~/.aethelred/keyring/` | Servers without a desktop keyring |
| `test` | Plaintext (unencrypted) | **Development only** |

```bash
# Set keyring backend
aethelred config set keyring_backend os

# Create a new account (stored in the active keyring)
aethelred account create --name my-validator

# Set as default signing account
aethelred account use my-validator
```

## Managing Config

```bash
# Show full current config
aethelred config show

# Get a single value
aethelred config get network

# Set a value
aethelred config set gas.limit 300000

# Reset config to defaults
aethelred config reset

# Open config file in $EDITOR
aethelred config edit

# Export / import
aethelred config export ./backup-config.toml
aethelred config import ./backup-config.toml
```

## Proxy Configuration

For environments behind a corporate proxy, set standard environment variables:

```bash
export HTTPS_PROXY="http://proxy.corp.example:8080"
export NO_PROXY="localhost,127.0.0.1"
```

The CLI uses `reqwest` with `rustls-tls`, so these variables are respected automatically.

## Custom Config Path

Override the default config location with the `--config` flag or `AETHELRED_CONFIG` variable:

```bash
aethelred --config /etc/aethelred/validator.toml status
```

## Further Reading

- [Commands Reference](/cli/commands) - All available commands and flags
- [Shell Completions](/cli/completions) - Set up tab completion
- [Installation](/cli/installation) - Install or upgrade the CLI
