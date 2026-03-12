<h1 align="center">aethelred-cli</h1>

<p align="center">
  <strong>The official command-line interface for the Aethelred blockchain</strong><br/>
  Submit AI jobs · Verify Digital Seals · Manage validators · Query on-chain state
</p>

<p align="center">
  <a href="https://github.com/AethelredFoundation/aethelred-cli/actions"><img src="https://img.shields.io/github/actions/workflow/status/AethelredFoundation/aethelred-cli/cli-ci.yml?branch=main&style=flat-square&label=CI" alt="CI"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue?style=flat-square" alt="License"></a>
  <img src="https://img.shields.io/badge/built_with-Rust-orange?style=flat-square&logo=rust" alt="Rust">
  <a href="https://docs.aethelred.io/cli"><img src="https://img.shields.io/badge/docs-cli-orange?style=flat-square" alt="Docs"></a>
</p>

---

## Install

**macOS / Linux (Homebrew):**
```bash
brew install AethelredFoundation/tap/aeth
```

**Cargo:**
```bash
cargo install aeth
```

**Download binary** from [Releases](https://github.com/AethelredFoundation/aethelred-cli/releases):
```bash
curl -sSL https://install.aethelred.io | bash
```

---

## Quick Start

```bash
# Configure network
aeth config set --network testnet
aeth config set --rpc https://rpc.testnet.aethelred.io

# Create / import a wallet
aeth wallet create --name mykey
aeth wallet import --mnemonic "your twelve word mnemonic..."

# Check balance
aeth bank balance --address aeth1abc...

# Submit an AI compute job
aeth pouw submit-job \
  --model-hash abc123... \
  --input ./my_prompt.json \
  --verification-type hybrid \
  --from mykey

# Query a Digital Seal
aeth seal get --job-id <job-id>

# Verify a seal
aeth seal verify --seal-id <seal-id>
```

---

## Command Reference

| Command | Description |
|---|---|
| `aeth config` | Manage CLI configuration (network, RPC, keyring) |
| `aeth wallet` | Create, import, list, and export wallets |
| `aeth bank` | Token transfers and balance queries |
| `aeth pouw submit-job` | Submit an AI compute job |
| `aeth pouw list-jobs` | List your submitted jobs |
| `aeth pouw rewards` | Query your validator rewards |
| `aeth seal get` | Get a Digital Seal by job ID or seal ID |
| `aeth seal verify` | Verify a Digital Seal's authenticity |
| `aeth seal list` | List recent Digital Seals |
| `aeth model register` | Register an AI model on-chain |
| `aeth model list` | List registered models |
| `aeth validator list` | List active validators |
| `aeth gov propose` | Submit a governance proposal |
| `aeth gov vote` | Vote on a governance proposal |
| `aeth status` | Node health and chain status |
| `aeth version` | Print CLI version |

---

## Tools

This repo also contains:

| Tool | Description |
|---|---|
| `seal-verifier` | Standalone seal verification binary |
| `model-registry` | Model registration CLI tool |

---

## Development

```bash
# Build
cargo build --workspace

# Test
cargo test --workspace

# Lint
cargo clippy -- -D warnings

# Run locally
cargo run --bin aeth -- --help
```

---

## Related

- [AethelredFoundation/aethelred](https://github.com/AethelredFoundation/aethelred) - Core node
- [AethelredFoundation/aethelred-sdk-rs](https://github.com/AethelredFoundation/aethelred-sdk-rs) - Rust SDK (used internally)
- [Docs](https://docs.aethelred.io/cli)
