<h1 align="center">vscode-aethelred</h1>

<p align="center">
  <strong>The official VS Code extension for Aethelred blockchain development</strong><br/>
  The only Layer 1 blockchain with a native IDE extension.
</p>

<p align="center">
  <a href="https://marketplace.visualstudio.com/items?itemName=aethelred.vscode-aethelred"><img src="https://img.shields.io/visual-studio-marketplace/v/aethelred.vscode-aethelred?style=flat-square&logo=visualstudiocode" alt="VS Marketplace"></a>
  <a href="https://marketplace.visualstudio.com/items?itemName=aethelred.vscode-aethelred"><img src="https://img.shields.io/visual-studio-marketplace/i/aethelred.vscode-aethelred?style=flat-square&label=installs" alt="Installs"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue?style=flat-square" alt="License"></a>
</p>

---

## Install

Search **"Aethelred"** in VS Code Extensions, or:

```bash
code --install-extension aethelred.vscode-aethelred
```

---

## Features

### 🌐 Node Status Bar
Real-time connection status, block height, and TPS in the status bar.

### 📝 AIP Syntax Highlighting
Full syntax highlighting for `.aip` Aethelred Improvement Proposal files.

### 🔬 Seal Verification
Right-click any job ID in your code to verify its Digital Seal directly in VS Code.

### 🚀 One-Click Devnet
Start and stop the local Aethelred testnet (Docker) from the command palette:
- `Aethelred: Start Local Devnet`
- `Aethelred: Stop Local Devnet`

### 💼 Job Submission
Submit compute jobs to any network without leaving your editor:
- `Aethelred: Submit Compute Job`

---

## Commands

| Command | Description |
|---|---|
| `Aethelred: Submit Compute Job` | Submit a PoUW compute job |
| `Aethelred: Verify Digital Seal` | Verify a job's Digital Seal |
| `Aethelred: Start Local Devnet` | Start Docker-based local testnet |
| `Aethelred: Stop Local Devnet` | Stop local testnet |
| `Aethelred: Show Node Status` | Display node health in output panel |

---

## Configuration

```json
{
  "aethelred.rpcUrl": "http://localhost:26657",
  "aethelred.network": "local",
  "aethelred.autoStartDevnet": false
}
```

---

## Development

```bash
npm install
npm run compile
# Press F5 in VS Code to launch Extension Development Host
```

---

## Why This Is Unique

No other Layer 1 blockchain (Ethereum, Solana, Aptos, Sui, Celestia, Cosmos Hub) ships an official, feature-complete VS Code extension. This puts Aethelred **years ahead** in developer UX.
