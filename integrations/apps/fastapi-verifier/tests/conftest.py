"""Shared fixtures for FastAPI verifier negative-path tests."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture()
def client() -> TestClient:
    """Provide a synchronous test client for the FastAPI app."""
    return TestClient(app)
