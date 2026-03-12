# Cross-SDK Interoperability Tests

This directory contains tests that verify cryptographic operations produce
consistent results across all Aethelred SDK implementations.

## Purpose

Ensure that:
1. A signature created with the **Rust SDK** can be verified by the **Go SDK** and vice versa
2. Public key serialization is identical across all SDKs
3. Seal structures are wire-compatible across language bindings
4. KAT test vectors produce identical outputs in every SDK

## Test Vectors

Shared test vectors are stored in `vectors/` as JSON files:

- `hybrid_signatures.json` - Pre-computed hybrid signatures with known keys
- `kyber_kem.json` - KEM encapsulation/decapsulation pairs
- `seal_roundtrip.json` - Serialized digital seals for cross-SDK parsing

## Running

```bash
# Run all interop tests
make test-all

# Individual SDKs
make test-rust
make test-go
make test-python
make test-typescript
```

## Adding New Vectors

1. Generate the test vector in the Rust SDK (canonical implementation)
2. Export as JSON to `vectors/`
3. Add corresponding test cases in each SDK's test file
