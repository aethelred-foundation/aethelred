# OpenAPI Spec

This directory holds the generated OpenAPI (Swagger) specification for Aethelred.

## Generate

Run:

```bash
make openapi
```

## Output Files

```
docs/api/openapi/aethelred.swagger.json           # Swagger JSON
docs/api/openapi/aethelred.openapi.yaml            # OpenAPI 3.1.0 YAML
docs/api/openapi/aethelred.postman_collection.json # Postman collection
docs/api/openapi/index.html                        # Interactive Swagger UI
```

## Interactive API Explorer

Open `index.html` in a browser to explore the API interactively:

```bash
npx serve docs/api/openapi
# Then open http://localhost:3000
```

## Postman Collection

Import `aethelred.postman_collection.json` into Postman or Bruno for quick API testing. Regenerate from the OpenAPI spec:

```bash
npx openapi-to-postmanv2 -s aethelred.openapi.yaml -o aethelred.postman_collection.json -p
```

## Generation Modes

1. **Proto-first (preferred)**: If `protoc` and `protoc-gen-openapiv2` (or `protoc-gen-swagger`) are available, JSON is generated directly from `proto/**/*.proto`.
2. **Canonical fallback**: If those tools are unavailable, generation falls back to the checked-in canonical spec at `sdk/spec/openapi.yaml` (and `sdk/spec/openapi.json` when present).

This keeps `make openapi` functional in constrained environments while preserving a deterministic API artifact.
