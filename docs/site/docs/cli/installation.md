# CLI Installation

Install the `aethelred` CLI to interact with the Aethelred AI Blockchain from your terminal.

## Requirements

- **Rust 1.75+** (for building from source)
- **OpenSSL 1.1+** or **rustls** (TLS support)
- **Linux**, **macOS**, or **Windows** (x86_64 / aarch64)

## Cargo Install (Recommended)

```bash
cargo install aethelred-cli
```

This installs the latest release from [crates.io](https://crates.io/crates/aethelred-cli) and places the `aethelred` binary in `~/.cargo/bin/`.

## Pre-built Binaries

Download a pre-built binary from the [GitHub Releases](https://github.com/aethelred-foundation/aethelred-cli/releases) page:

```bash
# Linux (x86_64)
curl -LO https://github.com/aethelred-foundation/aethelred-cli/releases/latest/download/aethelred-linux-amd64.tar.gz
tar xzf aethelred-linux-amd64.tar.gz
sudo mv aethelred /usr/local/bin/

# macOS (Apple Silicon)
curl -LO https://github.com/aethelred-foundation/aethelred-cli/releases/latest/download/aethelred-darwin-arm64.tar.gz
tar xzf aethelred-darwin-arm64.tar.gz
sudo mv aethelred /usr/local/bin/

# macOS (Intel)
curl -LO https://github.com/aethelred-foundation/aethelred-cli/releases/latest/download/aethelred-darwin-amd64.tar.gz
tar xzf aethelred-darwin-amd64.tar.gz
sudo mv aethelred /usr/local/bin/
```

## Docker

```bash
docker pull ghcr.io/aethelred-foundation/aethelred-cli:latest

# Run commands via Docker
docker run --rm -v ~/.aethelred:/root/.aethelred \
  ghcr.io/aethelred-foundation/aethelred-cli:latest status --json
```

For persistent use, create a shell alias:

```bash
alias aethelred='docker run --rm -v ~/.aethelred:/root/.aethelred ghcr.io/aethelred-foundation/aethelred-cli:latest'
```

## Building from Source

```bash
git clone https://github.com/aethelred-foundation/aethelred-cli.git
cd aethelred-cli

# Release build with LTO (recommended for production)
cargo build --release

# The binary is at target/release/aethelred
sudo cp target/release/aethelred /usr/local/bin/
```

To enable HSM support, build with the `hsm` feature flag:

```bash
cargo build --release --features hsm
```

## Verifying Your Installation

```bash
# Check version and build info
aethelred --version

# Full version details including SDK version, git SHA, and Rust version
aethelred version

# Initialize default configuration
aethelred init --network testnet

# Verify network connectivity
aethelred status --json
```

Expected output from `aethelred version`:

```
  CLI Version: 2.0.0
  SDK Version: 0.4.0
  API Version: v1
  Build:       eee245e1
  Rust:        1.82.0
```

## Verifying Binary Integrity

All release binaries are signed. Verify with:

```bash
# Download the signature file
curl -LO https://github.com/aethelred-foundation/aethelred-cli/releases/latest/download/checksums.sha256

# Verify checksum
sha256sum -c checksums.sha256
```

## Upgrading

```bash
# Via cargo
cargo install aethelred-cli --force

# Or download the latest binary and replace the existing one
```

## Next Steps

- [Configuration](/cli/configuration) - Set up networks, keyring, and gas settings
- [Commands Reference](/cli/commands) - Full command documentation
- [Shell Completions](/cli/completions) - Enable tab completion
