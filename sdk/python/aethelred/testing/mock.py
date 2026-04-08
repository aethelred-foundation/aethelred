"""
Mock transport for Aethelred SDK offline development and testing.

Provides a deterministic, in-memory HTTP transport compatible with
``httpx`` that returns canned responses for common Aethelred API
endpoints.  No network connection is required.

Usage::

    from aethelred.core.config import Config
    from aethelred.testing import MockTransport

    config = Config.mock()
    transport = MockTransport()

    import httpx
    client = httpx.Client(transport=transport)
    resp = client.get("http://127.0.0.1:26657/health")
    assert resp.json() == {"status": "ok"}

Customise responses by mutating :data:`mock_responses` before creating
the transport, or pass your own mapping to the constructor.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, Optional, Tuple

import httpx

# ------------------------------------------------------------------ #
# Default mock response payloads
# ------------------------------------------------------------------ #

mock_responses: Dict[Tuple[str, str], Dict[str, Any]] = {
    # Health check
    ("GET", "/health"): {
        "status": "ok",
    },
    # Node information
    ("GET", "/cosmos/base/tendermint/v1beta1/node_info"): {
        "default_node_info": {
            "protocol_version": {"p2p": "8", "block": "11", "app": "0"},
            "default_node_id": "mock-node-0000000000000000000000000000000000000000",
            "listen_addr": "tcp://0.0.0.0:26656",
            "network": "aethelred-mock-1",
            "version": "0.37.0",
            "channels": "40202122233038606100",
            "moniker": "mock-validator",
            "other": {"tx_index": "on", "rpc_address": "tcp://127.0.0.1:26657"},
        },
        "application_version": {
            "name": "aethelred",
            "app_name": "aethelredd",
            "version": "1.0.0-mock",
            "git_commit": "0000000000000000000000000000000000000000",
            "go_version": "go1.22.0",
            "cosmos_sdk_version": "v0.50.0",
        },
    },
    # Latest block
    ("GET", "/cosmos/base/tendermint/v1beta1/blocks/latest"): {
        "block_id": {
            "hash": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "part_set_header": {"total": 1, "hash": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="},
        },
        "block": {
            "header": {
                "version": {"block": "11"},
                "chain_id": "aethelred-mock-1",
                "height": "1000",
                "time": "2025-01-01T00:00:00.000000000Z",
                "last_block_id": {
                    "hash": "",
                    "part_set_header": {"total": 0, "hash": ""},
                },
                "proposer_address": "AAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            },
            "data": {"txs": []},
        },
    },
    # Submit a PoUW job
    ("POST", "/aethelred/pouw/v1/jobs"): {
        "job_id": "mock-job-001",
        "status": "SUBMITTED",
        "created_at": "2025-01-01T00:00:00Z",
        "tx_hash": "0" * 64,
    },
    # Retrieve job details (pattern-matched separately)
    ("GET", "/aethelred/pouw/v1/jobs/mock-job-001"): {
        "job": {
            "job_id": "mock-job-001",
            "status": "COMPLETED",
            "model_cid": "QmMockModelCID000000000000000000000000000000",
            "result_cid": "QmMockResultCID00000000000000000000000000000",
            "creator": "aethelred1mockaddress000000000000000000000000",
            "created_at": "2025-01-01T00:00:00Z",
            "completed_at": "2025-01-01T00:01:00Z",
        },
    },
    # Retrieve seal details (pattern-matched separately)
    ("GET", "/aethelred/seal/v1/seals/mock-seal-001"): {
        "seal": {
            "seal_id": "mock-seal-001",
            "job_id": "mock-job-001",
            "attestation": "0" * 128,
            "validator": "aethelredvaloper1mockvalidator0000000000000000000",
            "created_at": "2025-01-01T00:01:30Z",
        },
    },
    # Verify a seal
    ("POST", "/aethelred/seal/v1/seals/mock-seal-001/verify"): {
        "valid": True,
        "seal_id": "mock-seal-001",
        "verified_at": "2025-01-01T00:02:00Z",
    },
}


# ------------------------------------------------------------------ #
# Pattern-based route matching
# ------------------------------------------------------------------ #

_ROUTE_PATTERNS: list[Tuple[str, re.Pattern[str], Dict[str, Any]]] = [
    # GET /aethelred/pouw/v1/jobs/<job_id>
    (
        "GET",
        re.compile(r"^/aethelred/pouw/v1/jobs/(?P<job_id>[^/]+)$"),
        {
            "job": {
                "job_id": "{job_id}",
                "status": "COMPLETED",
                "model_cid": "QmMockModelCID000000000000000000000000000000",
                "result_cid": "QmMockResultCID00000000000000000000000000000",
                "creator": "aethelred1mockaddress000000000000000000000000",
                "created_at": "2025-01-01T00:00:00Z",
                "completed_at": "2025-01-01T00:01:00Z",
            },
        },
    ),
    # GET /aethelred/seal/v1/seals/<seal_id>
    (
        "GET",
        re.compile(r"^/aethelred/seal/v1/seals/(?P<seal_id>[^/]+)$"),
        {
            "seal": {
                "seal_id": "{seal_id}",
                "job_id": "mock-job-001",
                "attestation": "0" * 128,
                "validator": "aethelredvaloper1mockvalidator0000000000000000000",
                "created_at": "2025-01-01T00:01:30Z",
            },
        },
    ),
    # POST /aethelred/seal/v1/seals/<seal_id>/verify
    (
        "POST",
        re.compile(r"^/aethelred/seal/v1/seals/(?P<seal_id>[^/]+)/verify$"),
        {
            "valid": True,
            "seal_id": "{seal_id}",
            "verified_at": "2025-01-01T00:02:00Z",
        },
    ),
]


def _interpolate(template: Any, params: Dict[str, str]) -> Any:
    """Recursively replace ``{key}`` placeholders in a nested structure."""
    if isinstance(template, str):
        for key, value in params.items():
            template = template.replace(f"{{{key}}}", value)
        return template
    if isinstance(template, dict):
        return {k: _interpolate(v, params) for k, v in template.items()}
    if isinstance(template, list):
        return [_interpolate(item, params) for item in template]
    return template


def _match_route(
    method: str, path: str
) -> Optional[Dict[str, Any]]:
    """Try pattern-based routes and return an interpolated body, or *None*."""
    for route_method, pattern, body_template in _ROUTE_PATTERNS:
        if method != route_method:
            continue
        m = pattern.match(path)
        if m:
            return _interpolate(body_template, m.groupdict())
    return None


# ------------------------------------------------------------------ #
# MockTransport
# ------------------------------------------------------------------ #

class MockTransport(httpx.BaseTransport):
    """A synchronous ``httpx`` transport that serves deterministic responses.

    Parameters
    ----------
    responses:
        Optional mapping of ``(METHOD, path)`` to JSON-serialisable
        response bodies.  Falls back to the module-level
        :data:`mock_responses` for any key not found.
    default_status:
        HTTP status code returned for matched routes (default ``200``).
    """

    def __init__(
        self,
        responses: Optional[Dict[Tuple[str, str], Dict[str, Any]]] = None,
        *,
        default_status: int = 200,
    ) -> None:
        self._responses = responses if responses is not None else mock_responses
        self._default_status = default_status

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        method = request.method.upper()
        path = request.url.raw_path.decode("ascii").split("?")[0]

        # 1. Exact match in the user-supplied / default table.
        key = (method, path)
        body = self._responses.get(key)

        # 2. Pattern-based fallback.
        if body is None:
            body = _match_route(method, path)

        # 3. Not found.
        if body is None:
            return httpx.Response(
                status_code=404,
                json={"error": f"mock: no response configured for {method} {path}"},
            )

        return httpx.Response(
            status_code=self._default_status,
            json=body,
        )
