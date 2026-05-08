//! Framework-agnostic REST API surface.
//!
//! Until v0.2.3, sandbox-core was Rust-library-only. Real enterprise
//! deployments need HTTP/JSON for Python / TypeScript / Java / .NET / curl
//! clients. This module ships the **dispatch layer** without committing
//! to a specific HTTP framework — callers wire it into axum, hyper,
//! actix, warp, rocket, or even a tiny std-only TCP loop.
//!
//! ## Why framework-agnostic
//!
//! Pulling axum/hyper into sandbox-core would force a TLS stack, async
//! runtime, and tower middleware tree on every consumer. Instead we
//! define:
//!
//! - [`HttpRequest`] / [`HttpResponse`] — plain data types.
//! - [`HttpHandler`] — trait you implement once, then mount on any
//!   framework via a 5-line adapter.
//! - [`SandboxApi`] — the canonical handler implementing all REST
//!   endpoints.
//! - [`Endpoint`] — discriminator for telemetry / RBAC / docs.
//!
//! ## REST surface
//!
//! | Method | Path                          | Endpoint                      |
//! | ------ | ----------------------------- | ----------------------------- |
//! | GET    | `/v1/health`                  | `Endpoint::Health`            |
//! | GET    | `/v1/version`                 | `Endpoint::Version`           |
//! | GET    | `/v1/metrics`                 | `Endpoint::Metrics`           |
//! | POST   | `/v1/seals`                   | `Endpoint::SealAppend`        |
//! | GET    | `/v1/seals/{id}`              | `Endpoint::SealGet`           |
//! | GET    | `/v1/seals/{id}/proof`        | `Endpoint::SealProof`         |
//! | POST   | `/v1/seals/verify`            | `Endpoint::SealVerify`        |
//! | GET    | `/v1/evidence/bundle`         | `Endpoint::EvidenceBundle`    |
//! | GET    | `/v1/evidence/root`           | `Endpoint::EvidenceRoot`      |
//! | POST   | `/v1/evidence/query`          | `Endpoint::EvidenceQuery`     |
//! | POST   | `/v1/scan`                    | `Endpoint::Scan`              |
//! | GET    | `/v1/audit`                   | `Endpoint::AuditTrail`        |
//! | POST   | `/v1/anchor`                  | `Endpoint::Anchor`            |
//! | GET    | `/v1/openapi.json`            | `Endpoint::OpenApiSpec`       |
//!
//! ## Adapter recipe (axum)
//!
//! ```ignore
//! async fn dispatch(State(api): State<Arc<SandboxApi>>, req: Request<Body>) -> Response {
//!     let r = HttpRequest::from_axum(req).await?;
//!     let resp = api.handle(&r);
//!     resp.into_axum()
//! }
//! ```

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Arc;

// =============================================================================
// HttpRequest / HttpResponse
// =============================================================================

/// HTTP method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum HttpMethod {
    /// GET.
    Get,
    /// POST.
    Post,
    /// PUT.
    Put,
    /// DELETE.
    Delete,
    /// PATCH.
    Patch,
    /// HEAD.
    Head,
    /// OPTIONS.
    Options,
}

impl HttpMethod {
    /// String form (uppercase).
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Delete => "DELETE",
            Self::Patch => "PATCH",
            Self::Head => "HEAD",
            Self::Options => "OPTIONS",
        }
    }
    /// Parse from a case-insensitive string.
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_uppercase().as_str() {
            "GET" => Some(Self::Get),
            "POST" => Some(Self::Post),
            "PUT" => Some(Self::Put),
            "DELETE" => Some(Self::Delete),
            "PATCH" => Some(Self::Patch),
            "HEAD" => Some(Self::Head),
            "OPTIONS" => Some(Self::Options),
            _ => None,
        }
    }
}

/// Plain HTTP request — adapters convert their framework's request type
/// into this and back.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpRequest {
    /// Method.
    pub method: HttpMethod,
    /// URL path (e.g., `/v1/seals`).
    pub path: String,
    /// Query string (k=v pairs).
    pub query: BTreeMap<String, String>,
    /// Headers (lower-cased keys).
    pub headers: BTreeMap<String, String>,
    /// Raw body bytes.
    pub body: Vec<u8>,
}

impl HttpRequest {
    /// New empty request.
    pub fn new(method: HttpMethod, path: impl Into<String>) -> Self {
        Self {
            method,
            path: path.into(),
            query: BTreeMap::new(),
            headers: BTreeMap::new(),
            body: Vec::new(),
        }
    }
    /// Add a header.
    pub fn with_header(mut self, k: impl Into<String>, v: impl Into<String>) -> Self {
        self.headers.insert(k.into().to_lowercase(), v.into());
        self
    }
    /// Add a query param.
    pub fn with_query(mut self, k: impl Into<String>, v: impl Into<String>) -> Self {
        self.query.insert(k.into(), v.into());
        self
    }
    /// Set body.
    pub fn with_body(mut self, body: Vec<u8>) -> Self {
        self.body = body;
        self
    }
    /// Set body to a JSON-serialised value.
    pub fn with_json_body<T: Serialize>(mut self, v: &T) -> Result<Self, String> {
        self.body = serde_json::to_vec(v).map_err(|e| format!("serialise: {e}"))?;
        self.headers
            .insert("content-type".into(), "application/json".into());
        Ok(self)
    }
}

/// Plain HTTP response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpResponse {
    /// Status code (e.g., 200, 404, 500).
    pub status: u16,
    /// Headers (lower-cased keys).
    pub headers: BTreeMap<String, String>,
    /// Body bytes.
    pub body: Vec<u8>,
}

impl HttpResponse {
    /// New response with status only.
    pub fn new(status: u16) -> Self {
        Self {
            status,
            headers: BTreeMap::new(),
            body: Vec::new(),
        }
    }
    /// 200 OK with a JSON body.
    pub fn ok_json<T: Serialize>(value: &T) -> Self {
        let body = serde_json::to_vec(value).unwrap_or_else(|_| b"{}".to_vec());
        let mut headers = BTreeMap::new();
        headers.insert("content-type".into(), "application/json".into());
        headers.insert("content-length".into(), body.len().to_string());
        Self {
            status: 200,
            headers,
            body,
        }
    }
    /// 200 OK with a plain-text body.
    pub fn ok_text(text: impl Into<String>) -> Self {
        let body = text.into().into_bytes();
        let mut headers = BTreeMap::new();
        headers.insert("content-type".into(), "text/plain; charset=utf-8".into());
        headers.insert("content-length".into(), body.len().to_string());
        Self {
            status: 200,
            headers,
            body,
        }
    }
    /// 4xx/5xx with a JSON `{"error":"..."}` body.
    pub fn error(status: u16, message: impl Into<String>) -> Self {
        let payload = serde_json::json!({"error": message.into(), "status": status});
        Self::ok_json(&payload).with_status(status)
    }
    /// 404.
    pub fn not_found(reason: impl Into<String>) -> Self {
        Self::error(404, reason)
    }
    /// 400.
    pub fn bad_request(reason: impl Into<String>) -> Self {
        Self::error(400, reason)
    }
    /// 405.
    pub fn method_not_allowed(method: HttpMethod, path: &str) -> Self {
        Self::error(405, format!("method {} not allowed on {}", method.as_str(), path))
    }
    /// 500.
    pub fn server_error(reason: impl Into<String>) -> Self {
        Self::error(500, reason)
    }
    /// Set status.
    pub fn with_status(mut self, status: u16) -> Self {
        self.status = status;
        self
    }
    /// Add a header.
    pub fn with_header(mut self, k: impl Into<String>, v: impl Into<String>) -> Self {
        self.headers.insert(k.into().to_lowercase(), v.into());
        self
    }
    /// `true` if status is 2xx.
    pub fn is_success(&self) -> bool {
        self.status >= 200 && self.status < 300
    }
    /// `true` if status is 4xx/5xx.
    pub fn is_error(&self) -> bool {
        self.status >= 400
    }
}

// =============================================================================
// Endpoint discriminator
// =============================================================================

/// Endpoint id (used for telemetry / RBAC / OpenAPI doc generation).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Endpoint {
    /// GET /v1/health.
    Health,
    /// GET /v1/version.
    Version,
    /// GET /v1/metrics (Prometheus text-format).
    Metrics,
    /// POST /v1/seals.
    SealAppend,
    /// GET /v1/seals/{id}.
    SealGet,
    /// GET /v1/seals/{id}/proof.
    SealProof,
    /// POST /v1/seals/verify.
    SealVerify,
    /// GET /v1/evidence/bundle.
    EvidenceBundle,
    /// GET /v1/evidence/root.
    EvidenceRoot,
    /// POST /v1/evidence/query.
    EvidenceQuery,
    /// POST /v1/scan.
    Scan,
    /// GET /v1/audit.
    AuditTrail,
    /// POST /v1/anchor.
    Anchor,
    /// GET /v1/openapi.json.
    OpenApiSpec,
    /// Anything not matched.
    NotFound,
}

impl Endpoint {
    /// Stable string id.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Health => "health",
            Self::Version => "version",
            Self::Metrics => "metrics",
            Self::SealAppend => "seal_append",
            Self::SealGet => "seal_get",
            Self::SealProof => "seal_proof",
            Self::SealVerify => "seal_verify",
            Self::EvidenceBundle => "evidence_bundle",
            Self::EvidenceRoot => "evidence_root",
            Self::EvidenceQuery => "evidence_query",
            Self::Scan => "scan",
            Self::AuditTrail => "audit_trail",
            Self::Anchor => "anchor",
            Self::OpenApiSpec => "openapi_spec",
            Self::NotFound => "not_found",
        }
    }
    /// Resolve from `(method, path)` (path uses `{id}` for parameter slots).
    pub fn route(method: HttpMethod, path: &str) -> Self {
        match (method, path) {
            (HttpMethod::Get, "/v1/health") => Self::Health,
            (HttpMethod::Get, "/v1/version") => Self::Version,
            (HttpMethod::Get, "/v1/metrics") => Self::Metrics,
            (HttpMethod::Post, "/v1/seals") => Self::SealAppend,
            (HttpMethod::Post, "/v1/seals/verify") => Self::SealVerify,
            (HttpMethod::Get, "/v1/evidence/bundle") => Self::EvidenceBundle,
            (HttpMethod::Get, "/v1/evidence/root") => Self::EvidenceRoot,
            (HttpMethod::Post, "/v1/evidence/query") => Self::EvidenceQuery,
            (HttpMethod::Post, "/v1/scan") => Self::Scan,
            (HttpMethod::Get, "/v1/audit") => Self::AuditTrail,
            (HttpMethod::Post, "/v1/anchor") => Self::Anchor,
            (HttpMethod::Get, "/v1/openapi.json") => Self::OpenApiSpec,
            (HttpMethod::Get, p) if p.starts_with("/v1/seals/") && p.ends_with("/proof") => {
                Self::SealProof
            }
            (HttpMethod::Get, p) if p.starts_with("/v1/seals/") => Self::SealGet,
            _ => Self::NotFound,
        }
    }
}

// =============================================================================
// HttpHandler trait
// =============================================================================

/// Pluggable handler — any object that turns a request into a response.
pub trait HttpHandler: Send + Sync {
    /// Handle a request. Implementations should be cheap to call concurrently.
    fn handle(&self, request: &HttpRequest) -> HttpResponse;
}

// =============================================================================
// SandboxApi — canonical implementation
// =============================================================================

/// The canonical [`HttpHandler`] for sandbox-core.
///
/// Wraps an evidence log + a verifier + a scanner. Production deployments
/// extend this with sector-specific routes by composition.
pub struct SandboxApi {
    /// Tenant id this API serves.
    pub tenant_id: String,
    /// Sector.
    pub sector: crate::Sector,
    /// Evidence log.
    pub evidence: Arc<crate::evidence::EvidenceLog>,
    /// Default scanner.
    pub scanner: crate::scanner::Scanner,
    /// Crate version.
    pub version: String,
    /// Health probe state.
    pub healthy: std::sync::atomic::AtomicBool,
}

impl SandboxApi {
    /// New API with a fresh evidence log.
    pub fn new(tenant_id: impl Into<String>, sector: crate::Sector) -> Self {
        Self {
            tenant_id: tenant_id.into(),
            sector,
            evidence: Arc::new(crate::evidence::EvidenceLog::new()),
            scanner: crate::scanner::Scanner::new(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            healthy: std::sync::atomic::AtomicBool::new(true),
        }
    }

    /// Mark unhealthy (causes /v1/health to return 503).
    pub fn mark_unhealthy(&self) {
        self.healthy
            .store(false, std::sync::atomic::Ordering::SeqCst);
    }

    /// Mark healthy.
    pub fn mark_healthy(&self) {
        self.healthy
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// `true` if currently healthy.
    pub fn is_healthy(&self) -> bool {
        self.healthy.load(std::sync::atomic::Ordering::SeqCst)
    }

    fn route_seal_get(&self, path: &str) -> HttpResponse {
        // Strip prefix and optional /proof suffix.
        let id_part = match path.strip_prefix("/v1/seals/") {
            Some(rest) => rest,
            None => return HttpResponse::not_found("malformed path"),
        };
        let (id_str, want_proof) = if let Some(stripped) = id_part.strip_suffix("/proof") {
            (stripped, true)
        } else {
            (id_part, false)
        };
        let bundle = match self.evidence.export(&self.tenant_id, self.sector) {
            Ok(b) => b,
            Err(e) => return HttpResponse::server_error(format!("export: {e}")),
        };
        let entry = bundle
            .entries
            .iter()
            .find(|e| e.seal.seal_id.to_string() == id_str || e.index.to_string() == id_str);
        match entry {
            None => HttpResponse::not_found(format!("seal {id_str} not found")),
            Some(e) if want_proof => {
                let proof = match self.evidence.proof(e.index) {
                    Ok(p) => p,
                    Err(err) => return HttpResponse::server_error(format!("proof: {err}")),
                };
                HttpResponse::ok_json(&proof)
            }
            Some(e) => HttpResponse::ok_json(&e.seal),
        }
    }

    fn handle_seal_append(&self, body: &[u8]) -> HttpResponse {
        match serde_json::from_slice::<crate::seal::DigitalSeal>(body) {
            Ok(seal) => match self.evidence.append(seal) {
                Ok(entry) => HttpResponse::ok_json(&entry).with_status(201),
                Err(e) => HttpResponse::server_error(format!("append: {e}")),
            },
            Err(e) => HttpResponse::bad_request(format!("parse seal: {e}")),
        }
    }

    fn handle_evidence_query(&self, body: &[u8]) -> HttpResponse {
        match serde_json::from_slice::<crate::time_query::TimeQuery>(body) {
            Ok(q) => {
                let bundle = match self.evidence.export(&self.tenant_id, self.sector) {
                    Ok(b) => b,
                    Err(e) => return HttpResponse::server_error(format!("export: {e}")),
                };
                match q.run(&bundle.entries) {
                    Ok(results) => HttpResponse::ok_json(&results),
                    Err(e) => HttpResponse::bad_request(format!("query: {e}")),
                }
            }
            Err(e) => HttpResponse::bad_request(format!("parse query: {e}")),
        }
    }

    fn handle_scan(&self, body: &[u8]) -> HttpResponse {
        let payload: serde_json::Value = match serde_json::from_slice(body) {
            Ok(v) => v,
            Err(e) => return HttpResponse::bad_request(format!("parse: {e}")),
        };
        let text = match payload.get("text").and_then(|v| v.as_str()) {
            Some(t) => t.to_string(),
            None => return HttpResponse::bad_request("missing 'text' field"),
        };
        let findings = self.scanner.scan(&text);
        let summary = self.scanner.summary(&text);
        HttpResponse::ok_json(&serde_json::json!({
            "summary": summary,
            "findings": findings,
        }))
    }

    fn openapi_spec(&self) -> serde_json::Value {
        serde_json::json!({
            "openapi": "3.0.3",
            "info": {
                "title": "Aethelred Sandbox API",
                "version": self.version,
                "description": "Tamper-evident AI-event sealing API.",
            },
            "servers": [{"url": "/v1"}],
            "paths": {
                "/health": {"get": {"summary": "Liveness probe", "responses": {"200": {"description": "OK"}}}},
                "/version": {"get": {"summary": "Crate version"}},
                "/metrics": {"get": {"summary": "Prometheus metrics"}},
                "/seals": {"post": {"summary": "Append a seal"}},
                "/seals/{id}": {"get": {"summary": "Get a seal"}},
                "/seals/{id}/proof": {"get": {"summary": "Merkle proof"}},
                "/seals/verify": {"post": {"summary": "Verify a SealEnvelope"}},
                "/evidence/bundle": {"get": {"summary": "Export bundle"}},
                "/evidence/root": {"get": {"summary": "Current Merkle root"}},
                "/evidence/query": {"post": {"summary": "Time-window query"}},
                "/scan": {"post": {"summary": "PII/PHI/PCI scan"}},
                "/audit": {"get": {"summary": "Audit trail"}},
                "/anchor": {"post": {"summary": "Anchor Merkle root"}},
            },
        })
    }
}

impl HttpHandler for SandboxApi {
    fn handle(&self, request: &HttpRequest) -> HttpResponse {
        let endpoint = Endpoint::route(request.method, &request.path);
        match endpoint {
            Endpoint::Health => {
                if self.is_healthy() {
                    HttpResponse::ok_json(&serde_json::json!({"status": "ok"}))
                } else {
                    HttpResponse::error(503, "service unavailable")
                }
            }
            Endpoint::Version => HttpResponse::ok_json(&serde_json::json!({
                "version": self.version,
                "tenant_id": self.tenant_id,
                "sector": format!("{:?}", self.sector),
            })),
            Endpoint::Metrics => {
                use crate::metrics::MetricsRecorder;
                let m = crate::metrics::SandboxMetrics::new();
                m.set_evidence_log_size(&self.tenant_id, self.evidence.len() as u64);
                HttpResponse::ok_text(m.export_prometheus())
                    .with_header("content-type", "text/plain; version=0.0.4")
            }
            Endpoint::SealAppend => self.handle_seal_append(&request.body),
            Endpoint::SealGet | Endpoint::SealProof => self.route_seal_get(&request.path),
            Endpoint::SealVerify => match serde_json::from_slice::<crate::seal::SealEnvelope>(&request.body) {
                Ok(env) => {
                    let v = crate::verify::Verifier::default();
                    match v.verify_envelope_internal(&env) {
                        Ok(report) => HttpResponse::ok_json(&report),
                        Err(e) => HttpResponse::server_error(format!("verify: {e}")),
                    }
                }
                Err(e) => HttpResponse::bad_request(format!("parse envelope: {e}")),
            },
            Endpoint::EvidenceBundle => {
                match self.evidence.export(&self.tenant_id, self.sector) {
                    Ok(b) => HttpResponse::ok_json(&b),
                    Err(e) => HttpResponse::server_error(format!("export: {e}")),
                }
            }
            Endpoint::EvidenceRoot => match self.evidence.root() {
                Ok(r) => HttpResponse::ok_json(&serde_json::json!({"merkle_root": r.to_hex()})),
                Err(e) => HttpResponse::server_error(format!("root: {e}")),
            },
            Endpoint::EvidenceQuery => self.handle_evidence_query(&request.body),
            Endpoint::Scan => self.handle_scan(&request.body),
            Endpoint::AuditTrail => match self.evidence.export(&self.tenant_id, self.sector) {
                Ok(b) => {
                    let trail = crate::audit::AuditTrail::from_bundle(&b);
                    HttpResponse::ok_json(&trail)
                }
                Err(e) => HttpResponse::server_error(format!("export: {e}")),
            },
            Endpoint::Anchor => {
                // For now, only mock-anchor is wired; production deployments
                // mount their real anchor service.
                HttpResponse::error(501, "anchor endpoint requires a wired AnchorService")
            }
            Endpoint::OpenApiSpec => HttpResponse::ok_json(&self.openapi_spec()),
            Endpoint::NotFound => HttpResponse::not_found(format!(
                "no route for {} {}",
                request.method.as_str(),
                request.path
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Sector;

    fn api() -> SandboxApi {
        SandboxApi::new("FAB", Sector::Finance)
    }

    #[test]
    fn http_method_string_round_trip() {
        for m in [
            HttpMethod::Get,
            HttpMethod::Post,
            HttpMethod::Put,
            HttpMethod::Delete,
            HttpMethod::Patch,
            HttpMethod::Head,
            HttpMethod::Options,
        ] {
            let s = m.as_str();
            assert_eq!(HttpMethod::parse(s), Some(m));
            assert_eq!(HttpMethod::parse(&s.to_lowercase()), Some(m));
        }
    }

    #[test]
    fn http_method_parse_unknown_returns_none() {
        assert!(HttpMethod::parse("FOOBAR").is_none());
    }

    #[test]
    fn endpoint_route_known_paths() {
        assert_eq!(
            Endpoint::route(HttpMethod::Get, "/v1/health"),
            Endpoint::Health
        );
        assert_eq!(
            Endpoint::route(HttpMethod::Post, "/v1/seals"),
            Endpoint::SealAppend
        );
        assert_eq!(
            Endpoint::route(HttpMethod::Post, "/v1/seals/verify"),
            Endpoint::SealVerify
        );
        assert_eq!(
            Endpoint::route(HttpMethod::Get, "/v1/seals/abc"),
            Endpoint::SealGet
        );
        assert_eq!(
            Endpoint::route(HttpMethod::Get, "/v1/seals/abc/proof"),
            Endpoint::SealProof
        );
    }

    #[test]
    fn endpoint_route_unknown_returns_not_found() {
        assert_eq!(
            Endpoint::route(HttpMethod::Get, "/nope"),
            Endpoint::NotFound
        );
    }

    #[test]
    fn health_returns_200_when_healthy() {
        let a = api();
        let r = a.handle(&HttpRequest::new(HttpMethod::Get, "/v1/health"));
        assert_eq!(r.status, 200);
    }

    #[test]
    fn health_returns_503_when_unhealthy() {
        let a = api();
        a.mark_unhealthy();
        let r = a.handle(&HttpRequest::new(HttpMethod::Get, "/v1/health"));
        assert_eq!(r.status, 503);
    }

    #[test]
    fn version_returns_200_with_version() {
        let a = api();
        let r = a.handle(&HttpRequest::new(HttpMethod::Get, "/v1/version"));
        assert_eq!(r.status, 200);
        let body: serde_json::Value = serde_json::from_slice(&r.body).unwrap();
        assert!(body.get("version").is_some());
    }

    #[test]
    fn metrics_returns_prometheus_text() {
        let a = api();
        let r = a.handle(&HttpRequest::new(HttpMethod::Get, "/v1/metrics"));
        assert_eq!(r.status, 200);
        let body_str = String::from_utf8(r.body).unwrap();
        assert!(body_str.contains("# HELP"));
    }

    #[test]
    fn seal_append_creates_seal() {
        use crate::seal::*;
        use std::collections::BTreeMap;
        use uuid::Uuid;
        let a = api();
        let seal = DigitalSeal {
            schema_version: SealVersion::V1,
            seal_id: Uuid::now_v7(),
            timestamp: time::OffsetDateTime::now_utc(),
            sector: Sector::Finance,
            event_type: "x".into(),
            event_hash: crate::Hasher::sha256(b"e"),
            model: ModelReference::new("m", crate::Hasher::sha256(b"w")),
            policy_id: "po".into(),
            input_hash: crate::Hasher::sha256(b"i"),
            output_hash: crate::Hasher::sha256(b"o"),
            approvals: vec![],
            attestation: None,
            zk_proof: None,
            tenant_id: "FAB".into(),
            workflow_id: "wf".into(),
            jurisdiction_tag: "AE".into(),
            retention: RetentionClass::SevenYears,
            prior_seal_hash: None,
            sector_extension: BTreeMap::new(),
            validator_signature_hex: None,
        };
        let req = HttpRequest::new(HttpMethod::Post, "/v1/seals")
            .with_json_body(&seal)
            .unwrap();
        let r = a.handle(&req);
        assert_eq!(r.status, 201);
    }

    #[test]
    fn seal_append_bad_json_returns_400() {
        let a = api();
        let req = HttpRequest::new(HttpMethod::Post, "/v1/seals").with_body(b"not json".to_vec());
        let r = a.handle(&req);
        assert_eq!(r.status, 400);
    }

    #[test]
    fn seal_get_unknown_id_returns_404() {
        let a = api();
        let r = a.handle(&HttpRequest::new(HttpMethod::Get, "/v1/seals/abc"));
        assert_eq!(r.status, 404);
    }

    #[test]
    fn evidence_root_returns_root() {
        let a = api();
        let r = a.handle(&HttpRequest::new(HttpMethod::Get, "/v1/evidence/root"));
        assert_eq!(r.status, 200);
        let body: serde_json::Value = serde_json::from_slice(&r.body).unwrap();
        assert!(body.get("merkle_root").is_some());
    }

    #[test]
    fn evidence_bundle_returns_bundle() {
        let a = api();
        let r = a.handle(&HttpRequest::new(HttpMethod::Get, "/v1/evidence/bundle"));
        assert_eq!(r.status, 200);
    }

    #[test]
    fn scan_endpoint_returns_findings() {
        let a = api();
        let req = HttpRequest::new(HttpMethod::Post, "/v1/scan")
            .with_json_body(&serde_json::json!({"text": "user@example.com"}))
            .unwrap();
        let r = a.handle(&req);
        assert_eq!(r.status, 200);
        let body: serde_json::Value = serde_json::from_slice(&r.body).unwrap();
        let findings = body.get("findings").unwrap().as_array().unwrap();
        assert!(!findings.is_empty());
    }

    #[test]
    fn scan_endpoint_missing_text_returns_400() {
        let a = api();
        let req = HttpRequest::new(HttpMethod::Post, "/v1/scan")
            .with_json_body(&serde_json::json!({}))
            .unwrap();
        let r = a.handle(&req);
        assert_eq!(r.status, 400);
    }

    #[test]
    fn audit_endpoint_returns_trail() {
        let a = api();
        let r = a.handle(&HttpRequest::new(HttpMethod::Get, "/v1/audit"));
        assert_eq!(r.status, 200);
    }

    #[test]
    fn unknown_path_returns_404() {
        let a = api();
        let r = a.handle(&HttpRequest::new(HttpMethod::Get, "/v1/unknown"));
        assert_eq!(r.status, 404);
    }

    #[test]
    fn anchor_endpoint_returns_501() {
        let a = api();
        let r = a.handle(&HttpRequest::new(HttpMethod::Post, "/v1/anchor"));
        assert_eq!(r.status, 501);
    }

    #[test]
    fn openapi_spec_endpoint_returns_spec() {
        let a = api();
        let r = a.handle(&HttpRequest::new(HttpMethod::Get, "/v1/openapi.json"));
        assert_eq!(r.status, 200);
        let body: serde_json::Value = serde_json::from_slice(&r.body).unwrap();
        assert_eq!(body.get("openapi").and_then(|v| v.as_str()), Some("3.0.3"));
    }

    #[test]
    fn http_response_ok_json_sets_content_type() {
        let r = HttpResponse::ok_json(&serde_json::json!({}));
        assert_eq!(
            r.headers.get("content-type").map(String::as_str),
            Some("application/json")
        );
    }

    #[test]
    fn http_response_is_success_and_is_error() {
        assert!(HttpResponse::ok_json(&()).is_success());
        assert!(HttpResponse::not_found("x").is_error());
        assert!(HttpResponse::server_error("x").is_error());
    }

    #[test]
    fn http_request_with_header_lowercases() {
        let r = HttpRequest::new(HttpMethod::Get, "/x").with_header("X-Trace", "abc");
        assert_eq!(r.headers.get("x-trace").map(String::as_str), Some("abc"));
    }

    #[test]
    fn endpoint_string_ids_unique() {
        let all = [
            Endpoint::Health,
            Endpoint::Version,
            Endpoint::Metrics,
            Endpoint::SealAppend,
            Endpoint::SealGet,
            Endpoint::SealProof,
            Endpoint::SealVerify,
            Endpoint::EvidenceBundle,
            Endpoint::EvidenceRoot,
            Endpoint::EvidenceQuery,
            Endpoint::Scan,
            Endpoint::AuditTrail,
            Endpoint::Anchor,
            Endpoint::OpenApiSpec,
            Endpoint::NotFound,
        ];
        let mut ids: Vec<&str> = all.iter().map(|e| e.as_str()).collect();
        ids.sort_unstable();
        let n = ids.len();
        ids.dedup();
        assert_eq!(ids.len(), n);
    }

    #[test]
    fn evidence_query_endpoint_works() {
        let a = api();
        // Send a default `TimeQuery` (all fields populated) — match the
        // serde-deserialize contract.
        let q = crate::time_query::TimeQuery::new().tenant("FAB");
        let req = HttpRequest::new(HttpMethod::Post, "/v1/evidence/query")
            .with_json_body(&q)
            .unwrap();
        let r = a.handle(&req);
        assert_eq!(r.status, 200);
    }

    #[test]
    fn http_request_with_query_param() {
        let r = HttpRequest::new(HttpMethod::Get, "/x").with_query("k", "v");
        assert_eq!(r.query.get("k").map(String::as_str), Some("v"));
    }

    #[test]
    fn method_not_allowed_helper() {
        let r = HttpResponse::method_not_allowed(HttpMethod::Delete, "/v1/seals");
        assert_eq!(r.status, 405);
    }
}
