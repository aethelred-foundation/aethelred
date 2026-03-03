# `model-registry`

Local-first model registry CLI for Aethelred developer workflows.

Features:

- register local model artifacts with metadata
- deterministic SHA-256 hashing
- metadata updates
- verification against local files
- export/import registry snapshots
- zkML conversion plan generation (deterministic planning, no prover execution)

## Usage

```bash
model-registry register --name fraud-detector --file ./fraud.onnx --category financial
model-registry list
model-registry verify 0x... --file ./fraud.onnx
model-registry export -o ./registry.json
```

