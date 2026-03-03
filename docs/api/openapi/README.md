# OpenAPI Spec

This directory holds the generated OpenAPI (Swagger) specification for Aethelred.

## Generate

Run:

```bash
make openapi
```

## Output Files

```
docs/api/openapi/aethelred.swagger.json
docs/api/openapi/aethelred.openapi.yaml
```

## Generation Modes

1. **Proto-first (preferred)**: If `protoc` and `protoc-gen-openapiv2` (or `protoc-gen-swagger`) are available, JSON is generated directly from `proto/**/*.proto`.
2. **Canonical fallback**: If those tools are unavailable, generation falls back to the checked-in canonical spec at `sdk/spec/openapi.yaml` (and `sdk/spec/openapi.json` when present).

This keeps `make openapi` functional in constrained environments while preserving a deterministic API artifact.
