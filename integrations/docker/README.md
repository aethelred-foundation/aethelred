# Aethelred Local Development Environment

## Quick Start

```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f aethelred-node

# Stop all services
docker-compose down
```

## Services

| Service | Port | Description |
|---------|------|-------------|
| Aethelred Node | 26657, 1317, 9090 | Main blockchain node |
| TEE Worker | 8545 | TEE execution worker (fails closed unless backend/sim enabled) |
| zkML Prover | 8546 | zkML proving service (fails closed unless backend/sim enabled) |
| Explorer | 3000 | Web-based blockchain explorer |
| Faucet | 8000 | Test token faucet |
| Prometheus | 9092 | Metrics collection |
| Grafana | 3001 | Metrics dashboard |

## Configuration

Environment variables can be set in `.env` file:

```env
AETHELRED_CHAIN_ID=aethelred-local
AETHELRED_LOG_LEVEL=debug
AETHELRED_ALLOW_SIMULATED=true
AETHELRED_TEE_LISTEN_ADDR=:8545
AETHELRED_ZKML_LISTEN_ADDR=:8546
```

## Testing

```bash
# Get test tokens from faucet
curl -X POST http://localhost:8000/faucet \
  -H "Content-Type: application/json" \
  -d '{"address": "aethel1..."}'

# Check node status
curl http://localhost:26657/status

# Query jobs
curl http://localhost:1317/aethelred/pouw/v1/jobs
```
