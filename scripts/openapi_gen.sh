#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROTO_DIR="$ROOT/proto"
OUT_DIR="$ROOT/docs/api/openapi"
CANONICAL_YAML="$ROOT/sdk/spec/openapi.yaml"
CANONICAL_JSON="$ROOT/sdk/spec/openapi.json"
OUT_JSON="$OUT_DIR/aethelred.swagger.json"
OUT_YAML="$OUT_DIR/aethelred.openapi.yaml"

emit_canonical_spec() {
  if [[ ! -f "$CANONICAL_YAML" ]]; then
    echo "Canonical OpenAPI YAML missing: $CANONICAL_YAML" >&2
    exit 1
  fi
  mkdir -p "$OUT_DIR"
  cp "$CANONICAL_YAML" "$OUT_YAML"
  if [[ -f "$CANONICAL_JSON" ]]; then
    cp "$CANONICAL_JSON" "$OUT_JSON"
  fi
  if [[ -f "$OUT_JSON" ]]; then
    jq . "$OUT_JSON" >/dev/null
  fi
  echo "OpenAPI generation complete (canonical fallback)."
  echo "  YAML: $OUT_YAML"
  if [[ -f "$OUT_JSON" ]]; then
    echo "  JSON: $OUT_JSON"
  fi
}

if ! command -v protoc >/dev/null 2>&1; then
  echo "protoc not found; using canonical OpenAPI spec fallback."
  emit_canonical_spec
  exit 0
fi

if command -v go >/dev/null 2>&1; then
  GOPATH="$(go env GOPATH 2>/dev/null || true)"
  if [[ -n "${GOPATH}" ]]; then
    export PATH="${GOPATH}/bin:${PATH}"
  fi
fi

PLUGIN="openapiv2"
if ! command -v protoc-gen-openapiv2 >/dev/null 2>&1; then
  if command -v protoc-gen-swagger >/dev/null 2>&1; then
    PLUGIN="swagger"
  else
    echo "protoc plugin missing; using canonical OpenAPI spec fallback."
    emit_canonical_spec
    exit 0
  fi
fi

PROTO_FILES=$(find "$PROTO_DIR" -type f -name "*.proto")
if [[ -z "${PROTO_FILES}" ]]; then
  echo "No .proto files found under ${PROTO_DIR}" >&2
  exit 1
fi

INCLUDES=("-I" "$PROTO_DIR")

# Add standard protobuf include paths if present.
for d in /usr/local/include /opt/homebrew/include /usr/include; do
  if [[ -d "$d/google/protobuf" ]]; then
    INCLUDES+=("-I" "$d")
    break
  fi
done

# Optional vendor/third-party proto roots.
if [[ -d "$ROOT/third_party/proto" ]]; then
  INCLUDES+=("-I" "$ROOT/third_party/proto")
fi
if [[ -d "$ROOT/third_party" ]]; then
  INCLUDES+=("-I" "$ROOT/third_party")
fi
if [[ -d "$ROOT/sdk/proto" ]]; then
  INCLUDES+=("-I" "$ROOT/sdk/proto")
fi

# Try to locate Cosmos SDK/IBC protos in the Go module cache if Go is installed.
if command -v go >/dev/null 2>&1; then
  GOMODCACHE="$(go env GOMODCACHE 2>/dev/null || true)"
  if [[ -n "${GOMODCACHE}" ]]; then
    COSMOS_DIR="$(ls -d "${GOMODCACHE}"/github.com/cosmos/cosmos-sdk@* 2>/dev/null | head -n 1 || true)"
    if [[ -n "${COSMOS_DIR}" && -d "${COSMOS_DIR}/proto" ]]; then
      INCLUDES+=("-I" "${COSMOS_DIR}/proto")
    fi
    IBC_DIR="$(ls -d "${GOMODCACHE}"/github.com/cosmos/ibc-go@* 2>/dev/null | head -n 1 || true)"
    if [[ -n "${IBC_DIR}" && -d "${IBC_DIR}/proto" ]]; then
      INCLUDES+=("-I" "${IBC_DIR}/proto")
    fi
  fi
fi

mkdir -p "$OUT_DIR"

OPENAPI_OPTS="logtostderr=true,allow_merge=true,merge_file_name=aethelred,json_names_for_fields=true"

if [[ "${PLUGIN}" == "openapiv2" ]]; then
  protoc \
    "${INCLUDES[@]}" \
    --openapiv2_out="${OPENAPI_OPTS}:${OUT_DIR}" \
    $PROTO_FILES
else
  protoc \
    "${INCLUDES[@]}" \
    --swagger_out="${OPENAPI_OPTS}:${OUT_DIR}" \
    $PROTO_FILES
fi

jq . "$OUT_JSON" >/dev/null
cp "$CANONICAL_YAML" "$OUT_YAML"
echo "OpenAPI generation complete (proto source)."
echo "  JSON: $OUT_JSON"
echo "  YAML: $OUT_YAML"
