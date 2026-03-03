# CLI Commands Reference

## Installation

```bash
cargo install aethelred-cli
```

## Global Options

| Flag | Description |
|------|-------------|
| `--config <PATH>` | Config file path (default: `~/.aethelred/config.toml`) |
| `--network <NETWORK>` | Network to connect to: `mainnet`, `testnet`, `devnet`, `local` |
| `--verbose` / `-v` | Enable verbose output |
| `--json` | Output in JSON format |
| `--help` / `-h` | Show help |
| `--version` / `-V` | Show version |

## Commands

### `aethelred init`

Initialize a new Aethelred configuration.

```bash
aethelred init --network testnet
```

### `aethelred status`

Show network and node status.

```bash
aethelred status --json
```

### `aethelred key`

Key management operations.

```bash
aethelred key generate              # Generate new keypair
aethelred key import <FILE>         # Import existing key
aethelred key export --format pem   # Export public key
aethelred key list                  # List all keys
```

### `aethelred seal`

Digital seal operations.

```bash
aethelred seal create --model <HASH> --input <HASH>
aethelred seal verify <SEAL_ID>
aethelred seal list --limit 10
aethelred seal inspect <SEAL_ID>
```

### `aethelred node`

Node management.

```bash
aethelred node start
aethelred node stop
aethelred node info
```

### `aethelred validator`

Validator operations.

```bash
aethelred validator register --stake 1000
aethelred validator status
aethelred validator list
aethelred validator slash-history
```

### `aethelred benchmark`

Run performance benchmarks.

```bash
aethelred benchmark crypto           # Crypto benchmarks
aethelred benchmark inference        # Inference benchmarks
aethelred benchmark --output report.json
```

### `aethelred completions`

Generate shell completion scripts.

```bash
# Bash
aethelred completions bash > ~/.bash_completion.d/aethelred

# Zsh
aethelred completions zsh > /usr/local/share/zsh/site-functions/_aethelred

# Fish
aethelred completions fish > ~/.config/fish/completions/aethelred.fish
```
