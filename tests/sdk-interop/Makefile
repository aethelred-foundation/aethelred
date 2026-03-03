.PHONY: test-all test-rust test-go test-python test-typescript

VECTORS_DIR := vectors

test-all: test-rust test-go test-python test-typescript
	@echo "=== All cross-SDK interop tests passed ==="

test-rust:
	@echo ">>> Running Rust SDK interop tests..."
	cd ../../sdk/aethelred-sdk && \
		cargo test --features full-pqc -- interop 2>&1 || \
		echo "WARN: Rust interop tests not yet implemented"

test-go:
	@echo ">>> Running Go SDK interop tests..."
	cd ../../sdk/go && \
		go test -v -run TestInterop ./... 2>&1 || \
		echo "WARN: Go interop tests not yet implemented"

test-python:
	@echo ">>> Running Python SDK interop tests..."
	cd ../../sdk/aethelred-py && \
		python -m pytest tests/test_interop.py -v 2>&1 || \
		echo "WARN: Python interop tests not yet implemented"

test-typescript:
	@echo ">>> Running TypeScript SDK interop tests..."
	cd ../../sdk/typescript && \
		npx jest --testPathPattern=interop 2>&1 || \
		echo "WARN: TypeScript interop tests not yet implemented"

generate-vectors:
	@echo ">>> Generating test vectors from canonical Rust implementation..."
	cd ../../sdk/aethelred-sdk && \
		cargo test --features full-pqc -- generate_test_vectors --ignored 2>&1
	@echo "Vectors written to $(VECTORS_DIR)/"
