#!/usr/bin/env python3
"""
Model Registration Example

This example demonstrates how to register, list, and inspect AI models
on the Aethelred network using the Python SDK.

Registered models receive an on-chain hash that links every subsequent
compute job back to a specific model version, enabling full auditability.

Prerequisites:
    pip install aethelred

Usage:
    export AETHELRED_API_KEY="your-api-key"
    python model_registration.py
"""

import json
import logging
import os

from aethelred import (
    AethelredClient,
    Config,
    sha256_hex,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def compute_model_hash(model_name: str, version: str, framework: str) -> str:
    """Compute a deterministic hash for a model artifact.

    In production you would hash the actual model binary; here we hash the
    identifying metadata for demonstration purposes.
    """
    payload = f"{model_name}:{version}:{framework}".encode()
    return sha256_hex(payload)


# ---------------------------------------------------------------------------
# Examples
# ---------------------------------------------------------------------------

def register_pytorch_model(client: AethelredClient) -> None:
    """Register a PyTorch image-classification model."""
    print("\n" + "=" * 50)
    print("1. Register a PyTorch Model")
    print("=" * 50)

    model_hash = compute_model_hash("resnet50-imagenet", "1.0.0", "pytorch")

    print(f"   Model  : ResNet-50 (ImageNet)")
    print(f"   Version: 1.0.0")
    print(f"   Hash   : {model_hash[:16]}...")

    try:
        response = client.models.register(
            model_hash=model_hash,
            metadata={
                "name": "resnet50-imagenet",
                "version": "1.0.0",
                "framework": "pytorch",
                "input_shape": "(1, 3, 224, 224)",
                "output_shape": "(1, 1000)",
                "quantization_bits": 8,
                "description": "ResNet-50 trained on ImageNet for image classification",
            },
        )
        print(f"   Registered! Model ID: {response.model_id}")
        print(f"   TX Hash: {response.tx_hash}")

    except Exception as exc:
        logger.info("Network unavailable, simulating: %s", exc)
        print("   [Simulated] Model ID: model_resnet50_abc123")
        print("   [Simulated] TX Hash : 0xabc...def")


def register_xgboost_model(client: AethelredClient) -> None:
    """Register an XGBoost credit-scoring model."""
    print("\n" + "=" * 50)
    print("2. Register an XGBoost Model")
    print("=" * 50)

    model_hash = compute_model_hash("credit-scorer", "2.1.0", "xgboost")

    print(f"   Model  : Credit Scorer")
    print(f"   Version: 2.1.0")
    print(f"   Hash   : {model_hash[:16]}...")

    try:
        response = client.models.register(
            model_hash=model_hash,
            metadata={
                "name": "credit-scorer",
                "version": "2.1.0",
                "framework": "xgboost",
                "input_shape": "(1, 64)",
                "output_shape": "(1, 1)",
                "description": "XGBoost credit scoring model for loan approvals",
                "compliance": ["SOC2", "GDPR", "PCI_DSS"],
            },
        )
        print(f"   Registered! Model ID: {response.model_id}")
        print(f"   TX Hash: {response.tx_hash}")

    except Exception as exc:
        logger.info("Network unavailable, simulating: %s", exc)
        print("   [Simulated] Model ID: model_credit_def456")
        print("   [Simulated] TX Hash : 0xdef...789")


def list_models(client: AethelredClient) -> None:
    """List all registered models."""
    print("\n" + "=" * 50)
    print("3. List Registered Models")
    print("=" * 50)

    try:
        models = client.models.list()
        if not models:
            print("   No models registered yet.")
            return

        for i, model in enumerate(models, 1):
            print(f"\n   [{i}] {model.model_hash[:16]}...")
            if hasattr(model, "metadata") and model.metadata:
                name = model.metadata.get("name", "unknown")
                version = model.metadata.get("version", "?")
                framework = model.metadata.get("framework", "?")
                print(f"       Name     : {name}")
                print(f"       Version  : {version}")
                print(f"       Framework: {framework}")

    except Exception as exc:
        logger.info("Network unavailable, simulating: %s", exc)
        print("   [Simulated] 2 models found:")
        print("   [1] resnet50-imagenet v1.0.0 (pytorch)")
        print("   [2] credit-scorer    v2.1.0 (xgboost)")


def get_model_details(client: AethelredClient) -> None:
    """Fetch details for a specific model by hash."""
    print("\n" + "=" * 50)
    print("4. Get Model Details")
    print("=" * 50)

    model_hash = compute_model_hash("resnet50-imagenet", "1.0.0", "pytorch")

    try:
        model = client.models.get(model_hash)
        print(f"   Hash    : {model.model_hash}")
        if hasattr(model, "metadata") and model.metadata:
            print(f"   Metadata: {json.dumps(model.metadata, indent=4)}")

    except Exception as exc:
        logger.info("Network unavailable, simulating: %s", exc)
        simulated = {
            "name": "resnet50-imagenet",
            "version": "1.0.0",
            "framework": "pytorch",
            "input_shape": "(1, 3, 224, 224)",
            "output_shape": "(1, 1000)",
            "quantization_bits": 8,
            "description": "ResNet-50 trained on ImageNet for image classification",
        }
        print(f"   [Simulated] Hash    : {model_hash[:16]}...")
        print(f"   [Simulated] Metadata:\n{json.dumps(simulated, indent=4)}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    """Run all model registration examples."""
    print("=" * 60)
    print("Aethelred Model Registration Examples")
    print("=" * 60)

    api_key = os.environ.get("AETHELRED_API_KEY", "YOUR_API_KEY_HERE")
    config = Config.testnet(api_key=api_key)
    client = AethelredClient(config)

    print(f"\nNetwork : {config.network.value}")
    print(f"Endpoint: {config.rpc_url}")

    register_pytorch_model(client)
    register_xgboost_model(client)
    list_models(client)
    get_model_details(client)

    print("\n" + "=" * 60)
    print("Examples Complete")
    print("=" * 60)
    print("\nFor more information, see:")
    print("  - Documentation: https://docs.aethelred.io/sdk/python/models")
    print("  - API Reference: https://docs.aethelred.io/api/models")


if __name__ == "__main__":
    main()
