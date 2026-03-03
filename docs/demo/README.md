# Aethelred Demo Suite

This directory contains everything you need to showcase Aethelred's capabilities to investors, developers, and enterprise customers **without requiring a live testnet**.

## Quick Start

### Option 1: Interactive Web Dashboard (Recommended for Investors)

```bash
# Start the demo dashboard
cd demo/dashboard
npm install && npm start

# Open http://localhost:3000
```

### Option 2: CLI Demo (Quick & Impressive)

```bash
# Trade Finance Demo (2-5 minutes)
./demo/run-demo.sh falcon-lion --mode presentation

# Drug Discovery Demo (3-7 minutes)
./demo/run-demo.sh helix-guard --mode presentation

# Both demos with live metrics
./demo/run-demo.sh all --with-dashboard
```

### Option 3: Local DevNet (Technical Deep Dive)

```bash
# Full local network with 3 validators
./deploy/scripts/setup-devnet.sh --clean --build

# Endpoints available:
# - Block Explorer: http://localhost:3000
# - RPC: http://localhost:26657
# - Faucet: http://localhost:8888
# - Grafana Metrics: http://localhost:3001
```

---

## Demo Scenarios

### 1. Falcon-Lion: Cross-Border Trade Finance
**Use Case:** UAE company (Falcon Trading) sends goods to Singapore (Lion Logistics)
**Duration:** 2-7 minutes (configurable)
**Key Features Demonstrated:**
- Sovereign data compliance at each border
- TEE-enclosed verification of trade documents
- Letter of Credit (LC) minting as Digital Seal
- Multi-jurisdiction regulatory compliance
- Real-time audit trail generation

### 2. Helix-Guard: Sovereign Drug Discovery
**Use Case:** M42 Health (UAE) + AstraZeneca (UK) collaborate on drug discovery
**Duration:** 3-10 minutes (configurable)
**Key Features Demonstrated:**
- Blind computation (neither party sees raw data)
- zkML proof of computation correctness
- Sovereign data never leaves jurisdiction
- Royalty calculation and AETHEL settlement
- HIPAA + UAE DPL compliance

### 3. Credit Scoring (SDK Demo)
**Use Case:** Privacy-preserving credit assessment
**Duration:** 1-2 minutes
**Key Features Demonstrated:**
- TypeScript SDK usage
- Job submission and verification
- Digital Seal creation
- Multiple verification methods (TEE + zkML)

---

## Demo Modes

| Mode | Duration | Best For |
|------|----------|----------|
| `--mode fast` | 30 seconds | Quick testing |
| `--mode realistic` | 2-5 minutes | Technical demos |
| `--mode presentation` | 5-10 minutes | Investor pitches |

---

## What Works Without Testnet

| Feature | Status | Notes |
|---------|--------|-------|
| TEE Verification | Simulated | Realistic timing, mock attestations |
| zkML Proofs | Simulated | Shows proof generation flow |
| Digital Seals | Full | Creates real seal structures |
| Compliance Engine | Full | Real regulatory rule evaluation |
| Audit Trails | Full | Complete audit log generation |
| Metrics & Monitoring | Full | Prometheus + Grafana available |
| SDK Operations | Full | All SDK functions work |
| VS Code Extension | Full | Linting, snippets, completion |

---

## Directory Structure

```
demo/
├── README.md                 # This file
├── run-demo.sh              # Universal demo runner
├── dashboard/               # Interactive web dashboard
│   ├── src/
│   └── package.json
├── scenarios/               # Pre-configured demo scenarios
│   ├── investor-pitch.json
│   ├── developer-onboard.json
│   └── enterprise-eval.json
├── exports/                 # Demo output files
│   ├── reports/            # PDF reports
│   └── recordings/         # Demo recordings
└── assets/                  # Presentation assets
    ├── slides/
    └── diagrams/
```

---

## Tips for Effective Demos

### For Investors
1. Start with the **problem statement** (data sovereignty, compliance costs)
2. Run **Falcon-Lion** in presentation mode
3. Highlight the **audit trail** and **regulatory compliance**
4. Show the **Digital Seal** as cryptographic proof
5. End with **token economics** (AETHEL settlement)

### For Developers
1. Start with **VS Code Extension** demo
2. Show **SDK examples** (TypeScript credit scoring)
3. Run **local devnet** for hands-on exploration
4. Walk through **job submission → verification → seal** flow
5. Point to **documentation** and **GitHub**

### For Enterprise
1. Lead with **regulatory compliance** (GDPR, HIPAA, UAE DPL)
2. Show **Helix-Guard** for cross-border data collaboration
3. Emphasize **audit trails** and **cryptographic proofs**
4. Discuss **integration patterns** (REST API, SDK)
5. Provide **performance benchmarks**

---

## Generating Demo Reports

```bash
# Generate PDF report after demo
./demo/run-demo.sh falcon-lion --output demo-report --format pdf

# Generate all formats
./demo/run-demo.sh all --output demo-report --format all
```

---

## Troubleshooting

**Demo won't start:**
```bash
# Ensure dependencies are installed
cd demo/dashboard && npm install
cd crates/demo/falcon-lion && cargo build --release
```

**Slow performance:**
```bash
# Use fast mode for quick iterations
./demo/run-demo.sh falcon-lion --mode fast
```

**Need help:**
- Check logs in `demo/exports/logs/`
- Run with `--verbose` flag
- Contact: team@aethelred.ai
