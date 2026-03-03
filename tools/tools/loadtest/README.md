# Aethelred Load Tester

The load test tool supports two execution modes:

1. `simulation` (default): synthetic consensus/job pipeline stress tests.
2. `node`: integration load tests against a live RPC/API endpoint.

## Simulation Mode

```bash
go run ./cmd/aethelred-loadtest \
  --mode simulation \
  --validators 100 \
  --jobs 5000 \
  --blocks 80 \
  --duration 20m
```

## Node Integration Mode

```bash
go run ./cmd/aethelred-loadtest \
  --mode node \
  --rpc-endpoint http://localhost:26657 \
  --api-endpoint http://localhost:1317 \
  --concurrency 32 \
  --duration 10m
```

Node mode continuously probes:

- `GET {rpc-endpoint}/status`
- `GET {api-endpoint}/v1/status`
- `GET {api-endpoint}/cosmos/base/tendermint/v1beta1/node_info`

It records latency, error rate, throughput, and observed block-height progression in the standard report format.
