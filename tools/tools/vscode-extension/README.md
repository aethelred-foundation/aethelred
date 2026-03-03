# Aethelred Sovereign Copilot

<p align="center">
  <img src="assets/icons/shield.svg" alt="Aethelred Shield" width="120"/>
</p>

**Enterprise-grade compliance linting and sovereignty enforcement for AI development.**

The Aethelred Sovereign Copilot moves compliance checks left, allowing developers to see regulatory violations as they type—not after deployment.

## Features

### Real-Time Compliance Linting

<img src="docs/linting-demo.gif" alt="Linting Demo" width="600"/>

- **Red Squiggly Lines** for data sovereignty violations
- **Quick Fixes** with one-click remediation
- **Multi-regulation support**: GDPR, HIPAA, UAE-DPL, PIPL, and more

### Cost Estimation

<img src="docs/hover-demo.gif" alt="Hover Demo" width="500"/>

Hover over `@sovereign` decorators to see:
- Estimated execution cost in AETHEL tokens
- Power consumption
- Hardware requirements
- Compliance status

### Status Bar Integration

<img src="docs/statusbar-demo.png" alt="Status Bar" width="400"/>

- Current jurisdiction indicator with flag
- Live violation count
- Network connection status
- One-click access to settings

### Code Lens

<img src="docs/codelens-demo.png" alt="Code Lens" width="500"/>

Inline annotations for sovereign functions showing:
- Compliance status
- Target hardware
- Jurisdiction
- Quick actions

### Helix Language Support

Full syntax highlighting and IntelliSense for the Helix DSL:
- Sovereign function decorators
- Neural network definitions
- ZK-provable operations
- Pipeline definitions

Reference docs:
- `$AETHELRED_REPO_ROOT/docs/sdk/helix-dsl.md`
- `$AETHELRED_REPO_ROOT/docs/guides/helix-tooling.md`

## Installation

### From VS Code Marketplace

1. Open VS Code
2. Press `Ctrl+Shift+X` (or `Cmd+Shift+X` on Mac)
3. Search for "Aethelred Sovereign Copilot"
4. Click Install

### From VSIX

```bash
code --install-extension aethelred-sovereign-copilot-2.0.0.vsix
```

### Prerequisites

The extension requires the Aethelred CLI (`aethel`) for full functionality:

```bash
# Install via cargo
cargo install aethelred-cli

# Or download from releases
curl -sSL https://get.aethelred.io | sh
```

## Usage

### Quick Start

1. Open a Python, Rust, or Helix file
2. Add the `@sovereign` decorator to a function
3. Save the file to trigger compliance check
4. Hover over violations for explanations and fixes

### Setting Jurisdiction

```
Ctrl+Shift+A (Cmd+Shift+A on Mac)
```

Or use the Command Palette:
- `Aethelred: Set Active Jurisdiction`

### Running Full Scan

```
Ctrl+Shift+A (Cmd+Shift+A on Mac)
```

Or use the Command Palette:
- `Aethelred: Run Full Compliance Scan`

### TEE Simulator

For development without real TEE hardware:

1. Open Command Palette
2. Run `Aethelred: Boot Local TEE Simulator`
3. Select hardware type (SGX, TDX, SEV, Nitro)

## Configuration

### Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `aethelred.jurisdiction` | `Global` | Active legal jurisdiction |
| `aethelred.compliance.regulations` | `["GDPR"]` | Active regulations |
| `aethelred.linting.enabled` | `true` | Enable real-time linting |
| `aethelred.linting.onSave` | `true` | Lint on file save |
| `aethelred.linting.onType` | `false` | Lint while typing |
| `aethelred.hardware.target` | `auto` | Target hardware |
| `aethelred.network.chain` | `testnet` | Network to connect to |

### Keybindings

| Command | Windows/Linux | Mac |
|---------|---------------|-----|
| Run Compliance Scan | `Ctrl+Shift+A` | `Cmd+Shift+A` |
| Check Current File | `Ctrl+Alt+A` | `Cmd+Alt+A` |
| Quick Fix | `Ctrl+.` | `Cmd+.` |

## Snippets

### Python

| Prefix | Description |
|--------|-------------|
| `@sovereign` | Create sovereign function |
| `sov-data` | Create SovereignData |
| `sov-tensor` | Create SovereignTensor |
| `aethel-import` | Import Aethelred modules |
| `uae-finance` | UAE finance template |
| `hipaa-template` | HIPAA healthcare template |

### Rust

| Prefix | Description |
|--------|-------------|
| `#[sovereign]` | Create sovereign function |
| `sov-data` | Create SovereignData |
| `aethel-use` | Import Aethelred types |
| `aethel-ctx` | Create ExecutionContext |

### Helix

| Prefix | Description |
|--------|-------------|
| `sovereign` | Create sovereign function |
| `neural` | Define neural network |
| `pipeline` | Create data pipeline |
| `model` | Define ML model |

## Supported Languages

- Python (`.py`)
- Rust (`.rs`)
- TypeScript (`.ts`, `.tsx`)
- JavaScript (`.js`, `.jsx`)
- Helix (`.helix`, `.hlx`)

## Compliance Regulations

| Regulation | Jurisdictions | Description |
|------------|---------------|-------------|
| GDPR | EU, UK | General Data Protection Regulation |
| HIPAA | US | Health Insurance Portability and Accountability |
| UAE-DPL | UAE | UAE Data Protection Law |
| CCPA | US-CA | California Consumer Privacy Act |
| PIPL | China | Personal Information Protection Law |
| PDPA | Singapore | Personal Data Protection Act |
| PCI-DSS | Global | Payment Card Industry Data Security |
| SOX | US | Sarbanes-Oxley Act |

## Architecture

The extension uses the `aethel` CLI as its brain:

```
┌─────────────────────────────────────────────────────────────┐
│                    VS Code Extension                         │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐        │
│  │ Linter  │  │ Hover   │  │CodeLens │  │StatusBar│        │
│  └────┬────┘  └────┬────┘  └────┬────┘  └────┬────┘        │
│       │            │            │            │              │
│       └────────────┴────────────┴────────────┘              │
│                           │                                  │
│                    ┌──────┴──────┐                          │
│                    │  CLI Service │                          │
│                    └──────┬──────┘                          │
└───────────────────────────┼─────────────────────────────────┘
                            │
                    ┌───────┴───────┐
                    │   aethel CLI    │
                    │  (Rust Core)  │
                    └───────────────┘
```

## Troubleshooting

### CLI Not Found

If you see "Aethelred CLI not found":

1. Check if `aethel` is in your PATH: `which aethel`
2. Set custom path in settings: `aethelred.cli.path`
3. Install CLI: `cargo install aethelred-cli`

### Linting Not Working

1. Ensure linting is enabled: `aethelred.linting.enabled`
2. Check output panel for errors
3. Verify file language is supported
4. Try `Aethelred: Refresh Compliance View`

### Performance Issues

If on-type linting is slow:
1. Disable on-type linting: `aethelred.linting.onType: false`
2. Increase debounce: `aethelred.linting.debounceMs: 1000`
3. Use on-save linting only

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup.

## License

Apache-2.0 - See [LICENSE](LICENSE) for details.

## Links

- [Documentation](https://docs.aethelred.io)
- [GitHub Repository](https://github.com/aethelred/vscode-extension)
- [Issue Tracker](https://github.com/aethelred/vscode-extension/issues)
- [Aethelred Website](https://aethelred.io)
