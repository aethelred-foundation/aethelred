# Aethelred Demo Quick Start

## TL;DR - Run a Demo in 30 Seconds

```bash
# Option 1: CLI Demo (no setup required)
./demo/run-demo.sh falcon-lion --mode presentation

# Option 2: Web Dashboard (requires npm)
cd demo/dashboard && npm install && npm start
# Open http://localhost:3000
```

---

## What Can You Demo WITHOUT a Testnet?

| Feature | Works Offline? | Notes |
|---------|---------------|-------|
| Trade Finance Demo | ✅ Yes | Full Falcon-Lion simulation |
| Drug Discovery Demo | ✅ Yes | Full Helix-Guard simulation |
| Credit Scoring Demo | ✅ Yes | TypeScript SDK example |
| TEE Verification | ✅ Simulated | Realistic timing and flow |
| zkML Proofs | ✅ Simulated | Shows proof generation |
| Digital Seals | ✅ Yes | Real seal structures |
| Compliance Engine | ✅ Yes | Real rule evaluation |
| VS Code Extension | ✅ Yes | Full linting and snippets |
| Local DevNet | ✅ Yes | 3-node local network |
| Metrics Dashboard | ✅ Yes | Grafana + Prometheus |

---

## Demo Options by Audience

### For Investors (5-7 minutes)
```bash
./demo/run-demo.sh all --scenario investor
```
**Key Points:**
- $500B compliance market opportunity
- Live cross-border trade finance demo
- Sovereign drug discovery collaboration
- Token economics and settlement

### For Developers (10-15 minutes)
```bash
# Start local devnet
./deploy/scripts/setup-devnet.sh --clean --build

# Run SDK demo
cd sdk/typescript && npx ts-node examples/credit-scoring-demo.ts
```
**Key Points:**
- 4 SDKs (Python, TypeScript, Rust, Go)
- VS Code extension with linting
- Local devnet in Docker
- Job submission → Seal verification flow

### For Enterprise (30-45 minutes)
```bash
./demo/run-demo.sh all --scenario enterprise --with-dashboard
```
**Key Points:**
- GDPR, HIPAA, UAE DPL compliance
- Security architecture deep dive
- Integration patterns
- Deployment options

---

## Pre-Demo Checklist

- [ ] Ensure Node.js 18+ installed (for dashboard)
- [ ] Ensure Docker running (for devnet)
- [ ] Test run: `./demo/run-demo.sh falcon-lion --mode fast`
- [ ] Open scenarios JSON for talking points
- [ ] Have browser ready for dashboard

---

## Common Demo Flows

### 1. Quick Impressive Demo
```bash
# Shows both demos with visual output
./demo/run-demo.sh all --mode presentation
```

### 2. Interactive Web Demo
```bash
cd demo/dashboard
npm install
npm start
# Click "Run Demo" on each card
```

### 3. Full Local Network
```bash
# Start everything
./deploy/scripts/setup-devnet.sh --clean --build

# Open these URLs:
# - Block Explorer: http://localhost:3000
# - Grafana Metrics: http://localhost:3001
# - Faucet: http://localhost:8888
# - RPC: http://localhost:26657
```

### 4. SDK Code Walkthrough
```bash
# TypeScript
cd sdk/typescript
cat examples/credit-scoring-demo.ts
npx ts-node examples/credit-scoring-demo.ts

# Python
cd sdk/python
cat examples/basic_usage.py
python examples/basic_usage.py
```

---

## Troubleshooting

**"Command not found"**
```bash
chmod +x demo/run-demo.sh
```

**"npm not found"**
```bash
# Install Node.js from https://nodejs.org
```

**"Docker not running"**
```bash
# Start Docker Desktop or:
sudo systemctl start docker
```

**"Demo too slow"**
```bash
./demo/run-demo.sh falcon-lion --mode fast
```

---

## Resources

- **Full Demo Guide:** `demo/README.md`
- **Investor Scenario:** `demo/scenarios/investor-pitch.json`
- **Developer Scenario:** `demo/scenarios/developer-onboard.json`
- **Enterprise Scenario:** `demo/scenarios/enterprise-eval.json`
- **SDK Examples:** `sdk/typescript/examples/`
- **VS Code Extension:** `tools/vscode-extension/`

---

## Need Help?

- Documentation: https://docs.aethelred.ai
- GitHub: https://github.com/aethelred
- Discord: https://discord.gg/aethelred
- Email: team@aethelred.ai
