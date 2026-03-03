#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROTO_DIR="$ROOT/proto"
OUT_DIR="$ROOT"

if ! command -v protoc >/dev/null 2>&1; then
  echo "protoc is required but not installed." >&2
  exit 1
fi

if command -v go >/dev/null 2>&1; then
  GOPATH="$(go env GOPATH 2>/dev/null || true)"
  if [[ -n "${GOPATH}" ]]; then
    export PATH="${GOPATH}/bin:${PATH}"
  fi
fi

if ! command -v protoc-gen-go >/dev/null 2>&1; then
  echo "protoc-gen-go is required but not installed." >&2
  exit 1
fi

if ! command -v protoc-gen-go-grpc >/dev/null 2>&1; then
  echo "protoc-gen-go-grpc is required but not installed." >&2
  exit 1
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
if [[ -n "${COSMOS_PROTO_DIR:-}" && -d "${COSMOS_PROTO_DIR}" ]]; then
  INCLUDES+=("-I" "${COSMOS_PROTO_DIR}")
fi
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

have_proto() {
  local rel="$1"
  for ((i=0; i<${#INCLUDES[@]}; i+=2)); do
    local root="${INCLUDES[i+1]}"
    if [[ -f "${root}/${rel}" ]]; then
      return 0
    fi
  done
  return 1
}

if ! have_proto "cosmos/base/v1beta1/coin.proto"; then
  echo "Missing Cosmos SDK protos (cosmos/base/v1beta1/coin.proto)." >&2
  echo "Set COSMOS_PROTO_DIR to the Cosmos SDK proto root or vendor them under third_party/." >&2
  exit 1
fi

protoc \
  "${INCLUDES[@]}" \
  --go_out="$OUT_DIR" --go_opt=module=github.com/aethelred/aethelred \
  --go-grpc_out="$OUT_DIR" --go-grpc_opt=module=github.com/aethelred/aethelred \
  $PROTO_FILES

echo "Protobuf generation complete (output: ${OUT_DIR})."
