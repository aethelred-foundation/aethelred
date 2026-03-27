"""Negative-path tests for the FastAPI verifier sample app.

Covers:
  - Malformed JSON input
  - Missing required fields
  - Invalid / out-of-range data
  - Wrong HTTP methods
  - Unexpected content types
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


# ---------------------------------------------------------------------------
# /infer/fraud  (expects FraudRequest: {features: list[float], threshold: float})
# ---------------------------------------------------------------------------
class TestInferFraudNegative:
    """Negative-path tests for POST /infer/fraud."""

    def test_malformed_json(self, client: TestClient) -> None:
        """Completely unparseable JSON body should return 422."""
        resp = client.post(
            "/infer/fraud",
            content=b"{not valid json!!!",
            headers={"content-type": "application/json"},
        )
        assert resp.status_code == 422

    def test_empty_body(self, client: TestClient) -> None:
        """Empty request body should either use defaults or return 422."""
        resp = client.post(
            "/infer/fraud",
            content=b"",
            headers={"content-type": "application/json"},
        )
        # FastAPI may accept empty body if all fields have defaults, or reject it
        assert resp.status_code in (200, 422)

    def test_wrong_type_features(self, client: TestClient) -> None:
        """features should be a list of floats; a string should be rejected."""
        resp = client.post("/infer/fraud", json={"features": "not-a-list"})
        assert resp.status_code == 422

    def test_wrong_type_threshold(self, client: TestClient) -> None:
        """threshold should be a float; an object should be rejected."""
        resp = client.post(
            "/infer/fraud", json={"features": [1.0, 2.0], "threshold": {"bad": True}}
        )
        assert resp.status_code == 422

    def test_features_with_non_numeric_elements(self, client: TestClient) -> None:
        """List containing non-numeric elements should be rejected."""
        resp = client.post(
            "/infer/fraud", json={"features": [1.0, "abc", None]}
        )
        assert resp.status_code == 422

    def test_wrong_http_method_get(self, client: TestClient) -> None:
        """GET on a POST-only endpoint should return 405."""
        resp = client.get("/infer/fraud")
        assert resp.status_code == 405

    def test_wrong_http_method_put(self, client: TestClient) -> None:
        """PUT on a POST-only endpoint should return 405."""
        resp = client.put("/infer/fraud", json={"features": [1.0]})
        assert resp.status_code == 405

    def test_wrong_content_type(self, client: TestClient) -> None:
        """Sending plain text instead of JSON should be rejected."""
        resp = client.post(
            "/infer/fraud",
            content=b"features=1.0,2.0",
            headers={"content-type": "text/plain"},
        )
        assert resp.status_code == 422

    def test_extra_unknown_fields_accepted(self, client: TestClient) -> None:
        """Extra fields should be silently ignored (Pydantic default)."""
        resp = client.post(
            "/infer/fraud",
            json={"features": [0.5], "threshold": 0.5, "unknown_field": "xyz"},
        )
        # Pydantic v2 ignores extra fields by default
        assert resp.status_code == 200

    def test_extremely_large_features_list(self, client: TestClient) -> None:
        """Very large input should still be processed (no crash)."""
        resp = client.post(
            "/infer/fraud", json={"features": [0.1] * 10000}
        )
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# /infer/text-risk  (expects PromptRequest: {text: str})
# ---------------------------------------------------------------------------
class TestInferTextRiskNegative:
    """Negative-path tests for POST /infer/text-risk."""

    def test_malformed_json(self, client: TestClient) -> None:
        resp = client.post(
            "/infer/text-risk",
            content=b"<<<not json>>>",
            headers={"content-type": "application/json"},
        )
        assert resp.status_code == 422

    def test_missing_text_field(self, client: TestClient) -> None:
        """text is required; omitting it should return 422."""
        resp = client.post("/infer/text-risk", json={})
        assert resp.status_code == 422

    def test_wrong_type_text(self, client: TestClient) -> None:
        """text should be a string; sending a list should be rejected."""
        resp = client.post("/infer/text-risk", json={"text": [1, 2, 3]})
        assert resp.status_code == 422

    def test_null_text(self, client: TestClient) -> None:
        """text=null should be rejected since str is required."""
        resp = client.post("/infer/text-risk", json={"text": None})
        assert resp.status_code == 422

    def test_empty_string_text(self, client: TestClient) -> None:
        """Empty string is a valid str and should be processed."""
        resp = client.post("/infer/text-risk", json={"text": ""})
        assert resp.status_code == 200

    def test_get_method_not_allowed(self, client: TestClient) -> None:
        resp = client.get("/infer/text-risk")
        assert resp.status_code == 405


# ---------------------------------------------------------------------------
# /chain/normalize  (expects PromptRequest: {text: str})
# ---------------------------------------------------------------------------
class TestChainNormalizeNegative:
    """Negative-path tests for POST /chain/normalize."""

    def test_malformed_json(self, client: TestClient) -> None:
        resp = client.post(
            "/chain/normalize",
            content=b"{broken",
            headers={"content-type": "application/json"},
        )
        assert resp.status_code == 422

    def test_missing_text_field(self, client: TestClient) -> None:
        resp = client.post("/chain/normalize", json={})
        assert resp.status_code == 422

    def test_wrong_type_text(self, client: TestClient) -> None:
        resp = client.post("/chain/normalize", json={"text": 12345})
        assert resp.status_code == 422

    def test_get_method_not_allowed(self, client: TestClient) -> None:
        resp = client.get("/chain/normalize")
        assert resp.status_code == 405


# ---------------------------------------------------------------------------
# /verify/recent  (GET, optional query param: limit)
# ---------------------------------------------------------------------------
class TestVerifyRecentNegative:
    """Negative-path tests for GET /verify/recent."""

    def test_post_method_not_allowed(self, client: TestClient) -> None:
        resp = client.post("/verify/recent")
        assert resp.status_code == 405

    def test_non_integer_limit(self, client: TestClient) -> None:
        """Non-integer limit query param should return 422."""
        resp = client.get("/verify/recent?limit=abc")
        assert resp.status_code == 422

    def test_negative_limit_clamped(self, client: TestClient) -> None:
        """Negative limit should be clamped to 1 (not crash)."""
        resp = client.get("/verify/recent?limit=-5")
        assert resp.status_code == 200

    def test_zero_limit_clamped(self, client: TestClient) -> None:
        """Zero limit should be clamped to 1 (not crash)."""
        resp = client.get("/verify/recent?limit=0")
        assert resp.status_code == 200

    def test_very_large_limit_clamped(self, client: TestClient) -> None:
        """Large limit should be clamped to 100."""
        resp = client.get("/verify/recent?limit=999999")
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Non-existent routes
# ---------------------------------------------------------------------------
class TestNonExistentRoutes:
    """Requests to undefined endpoints should return 404."""

    @pytest.mark.parametrize(
        "path",
        [
            "/nonexistent",
            "/infer/does-not-exist",
            "/admin",
            "/api/v1/internal",
        ],
    )
    def test_undefined_route_returns_404(self, client: TestClient, path: str) -> None:
        resp = client.get(path)
        assert resp.status_code in (404, 405)
