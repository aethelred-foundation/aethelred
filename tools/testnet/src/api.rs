//! Testnet API and SDK Integration for Aethelred
//!
//! World-class API infrastructure:
//! - RESTful API endpoints for all testnet features
//! - WebSocket subscriptions for real-time updates
//! - gRPC support for high-performance integrations
//! - Rate limiting and authentication
//! - SDK integration helpers
//! - API versioning and deprecation management

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use serde::{Deserialize, Serialize};

// ============ API Configuration ============

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiConfig {
    /// API version
    pub version: ApiVersion,

    /// Enable REST API
    pub rest_enabled: bool,

    /// Enable WebSocket API
    pub websocket_enabled: bool,

    /// Enable gRPC API
    pub grpc_enabled: bool,

    /// Rate limiting configuration
    pub rate_limits: RateLimitConfig,

    /// Authentication configuration
    pub auth: AuthConfig,

    /// CORS configuration
    pub cors: CorsConfig,

    /// Request timeout (ms)
    pub request_timeout_ms: u64,

    /// Maximum request body size (bytes)
    pub max_body_size: usize,

    /// Enable request logging
    pub logging_enabled: bool,

    /// Enable metrics collection
    pub metrics_enabled: bool,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            version: ApiVersion::V1,
            rest_enabled: true,
            websocket_enabled: true,
            grpc_enabled: true,
            rate_limits: RateLimitConfig::default(),
            auth: AuthConfig::default(),
            cors: CorsConfig::default(),
            request_timeout_ms: 30000,
            max_body_size: 10 * 1024 * 1024, // 10 MB
            logging_enabled: true,
            metrics_enabled: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ApiVersion {
    V1,
    V2,
}

impl ApiVersion {
    pub fn as_str(&self) -> &str {
        match self {
            Self::V1 => "v1",
            Self::V2 => "v2",
        }
    }

    pub fn path_prefix(&self) -> String {
        format!("/api/{}", self.as_str())
    }
}

// ============ Rate Limiting ============

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Default requests per minute
    pub default_rpm: u32,

    /// Requests per minute for authenticated users
    pub authenticated_rpm: u32,

    /// Requests per minute for premium users
    pub premium_rpm: u32,

    /// Burst allowance
    pub burst_multiplier: f64,

    /// Rate limit by endpoint
    pub endpoint_limits: HashMap<String, u32>,

    /// Enable adaptive rate limiting
    pub adaptive_enabled: bool,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        let mut endpoint_limits = HashMap::new();
        endpoint_limits.insert("/faucet/request".to_string(), 10);
        endpoint_limits.insert("/jobs/submit".to_string(), 100);
        endpoint_limits.insert("/seals/create".to_string(), 50);

        Self {
            default_rpm: 60,
            authenticated_rpm: 300,
            premium_rpm: 1000,
            burst_multiplier: 2.0,
            endpoint_limits,
            adaptive_enabled: true,
        }
    }
}

pub struct RateLimiter {
    config: RateLimitConfig,
    buckets: HashMap<String, TokenBucket>,
    metrics: RateLimitMetrics,
}

#[derive(Debug, Clone)]
struct TokenBucket {
    tokens: f64,
    max_tokens: f64,
    refill_rate: f64, // tokens per second
    last_refill: Instant,
}

impl TokenBucket {
    fn new(max_tokens: f64, refill_rate: f64) -> Self {
        Self {
            tokens: max_tokens,
            max_tokens,
            refill_rate,
            last_refill: Instant::now(),
        }
    }

    fn try_consume(&mut self, tokens: f64) -> bool {
        self.refill();
        if self.tokens >= tokens {
            self.tokens -= tokens;
            true
        } else {
            false
        }
    }

    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.max_tokens);
        self.last_refill = now;
    }

    fn tokens_remaining(&self) -> f64 {
        self.tokens
    }
}

#[derive(Debug, Clone, Default)]
pub struct RateLimitMetrics {
    pub total_requests: u64,
    pub rate_limited_requests: u64,
    pub by_endpoint: HashMap<String, EndpointMetrics>,
}

#[derive(Debug, Clone, Default)]
pub struct EndpointMetrics {
    pub requests: u64,
    pub rate_limited: u64,
    pub avg_response_time_ms: f64,
}

impl RateLimiter {
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            config,
            buckets: HashMap::new(),
            metrics: RateLimitMetrics::default(),
        }
    }

    /// Check if request should be allowed
    pub fn check(&mut self, key: &str, endpoint: &str, tier: ApiTier) -> RateLimitResult {
        self.metrics.total_requests += 1;

        // Get rate limit for this tier and endpoint
        let rpm = self.get_rate_limit(endpoint, tier);
        let bucket_key = format!("{}:{}", key, endpoint);

        // Get or create bucket
        let bucket = self.buckets.entry(bucket_key).or_insert_with(|| {
            TokenBucket::new(
                rpm as f64 * self.config.burst_multiplier,
                rpm as f64 / 60.0,
            )
        });

        if bucket.try_consume(1.0) {
            RateLimitResult::Allowed {
                remaining: bucket.tokens_remaining() as u32,
                reset_at: current_timestamp() + 60,
            }
        } else {
            self.metrics.rate_limited_requests += 1;

            RateLimitResult::Limited {
                retry_after_ms: (1000.0 / bucket.refill_rate) as u64,
                limit: rpm,
            }
        }
    }

    fn get_rate_limit(&self, endpoint: &str, tier: ApiTier) -> u32 {
        // Check endpoint-specific limits first
        if let Some(&limit) = self.config.endpoint_limits.get(endpoint) {
            return limit;
        }

        // Fall back to tier-based limits
        match tier {
            ApiTier::Anonymous => self.config.default_rpm,
            ApiTier::Basic => self.config.authenticated_rpm,
            ApiTier::Premium => self.config.premium_rpm,
            ApiTier::Enterprise => self.config.premium_rpm * 10,
        }
    }

    pub fn metrics(&self) -> &RateLimitMetrics {
        &self.metrics
    }
}

#[derive(Debug, Clone)]
pub enum RateLimitResult {
    Allowed { remaining: u32, reset_at: u64 },
    Limited { retry_after_ms: u64, limit: u32 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiTier {
    Anonymous,
    Basic,
    Premium,
    Enterprise,
}

// ============ Authentication ============

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    /// Enable API key authentication
    pub api_key_enabled: bool,

    /// Enable JWT authentication
    pub jwt_enabled: bool,

    /// Enable OAuth2
    pub oauth2_enabled: bool,

    /// API key header name
    pub api_key_header: String,

    /// JWT secret (in production, use env var)
    pub jwt_secret: String,

    /// JWT expiration (seconds)
    pub jwt_expiration_seconds: u64,

    /// Allowed OAuth2 providers
    pub oauth2_providers: Vec<OAuth2Provider>,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            api_key_enabled: true,
            jwt_enabled: true,
            oauth2_enabled: true,
            api_key_header: "X-Api-Key".to_string(),
            jwt_secret: "testnet-jwt-secret".to_string(),
            jwt_expiration_seconds: 86400,
            oauth2_providers: vec![
                OAuth2Provider::GitHub,
                OAuth2Provider::Google,
            ],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OAuth2Provider {
    GitHub,
    Google,
    Discord,
    Twitter,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKey {
    pub id: String,
    pub key_hash: String,
    pub owner: String,
    pub name: String,
    pub tier: String,
    pub permissions: Vec<Permission>,
    pub created_at: u64,
    pub expires_at: Option<u64>,
    pub last_used_at: Option<u64>,
    pub usage_count: u64,
    pub active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Permission {
    Read,
    Write,
    Admin,
    FaucetRequest,
    SealCreate,
    JobSubmit,
    WebhookManage,
    ValidatorManage,
    Custom(String),
}

pub struct ApiKeyManager {
    keys: HashMap<String, ApiKey>,
    key_by_hash: HashMap<String, String>,
}

impl ApiKeyManager {
    pub fn new() -> Self {
        Self {
            keys: HashMap::new(),
            key_by_hash: HashMap::new(),
        }
    }

    /// Create new API key
    pub fn create_key(&mut self, owner: &str, name: &str, tier: &str, permissions: Vec<Permission>) -> (String, ApiKey) {
        let key_id = format!("ak_{}", generate_id());
        let raw_key = format!("aeth_{}_{}", tier, generate_id());
        let key_hash = hash_key(&raw_key);

        let api_key = ApiKey {
            id: key_id.clone(),
            key_hash: key_hash.clone(),
            owner: owner.to_string(),
            name: name.to_string(),
            tier: tier.to_string(),
            permissions,
            created_at: current_timestamp(),
            expires_at: None,
            last_used_at: None,
            usage_count: 0,
            active: true,
        };

        self.keys.insert(key_id.clone(), api_key.clone());
        self.key_by_hash.insert(key_hash, key_id);

        (raw_key, api_key)
    }

    /// Validate API key
    pub fn validate(&mut self, raw_key: &str) -> Option<&ApiKey> {
        let key_hash = hash_key(raw_key);

        if let Some(key_id) = self.key_by_hash.get(&key_hash) {
            if let Some(key) = self.keys.get_mut(key_id) {
                // Check if active and not expired
                if !key.active {
                    return None;
                }

                if let Some(expires_at) = key.expires_at {
                    if expires_at < current_timestamp() {
                        return None;
                    }
                }

                // Update usage
                key.last_used_at = Some(current_timestamp());
                key.usage_count += 1;

                return Some(key);
            }
        }

        None
    }

    /// Revoke API key
    pub fn revoke(&mut self, key_id: &str) -> Result<(), String> {
        if let Some(key) = self.keys.get_mut(key_id) {
            key.active = false;
            Ok(())
        } else {
            Err(format!("Key {} not found", key_id))
        }
    }

    /// List keys for owner
    pub fn list_keys(&self, owner: &str) -> Vec<&ApiKey> {
        self.keys.values()
            .filter(|k| k.owner == owner)
            .collect()
    }
}

impl Default for ApiKeyManager {
    fn default() -> Self {
        Self::new()
    }
}

// ============ CORS Configuration ============

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorsConfig {
    pub allowed_origins: Vec<String>,
    pub allowed_methods: Vec<String>,
    pub allowed_headers: Vec<String>,
    pub exposed_headers: Vec<String>,
    pub allow_credentials: bool,
    pub max_age_seconds: u64,
}

impl Default for CorsConfig {
    fn default() -> Self {
        Self {
            allowed_origins: vec!["*".to_string()],
            allowed_methods: vec![
                "GET".to_string(),
                "POST".to_string(),
                "PUT".to_string(),
                "DELETE".to_string(),
                "OPTIONS".to_string(),
            ],
            allowed_headers: vec![
                "Content-Type".to_string(),
                "Authorization".to_string(),
                "X-Api-Key".to_string(),
                "X-Request-Id".to_string(),
            ],
            exposed_headers: vec![
                "X-RateLimit-Limit".to_string(),
                "X-RateLimit-Remaining".to_string(),
                "X-RateLimit-Reset".to_string(),
            ],
            allow_credentials: true,
            max_age_seconds: 86400,
        }
    }
}

// ============ API Router ============

pub struct ApiRouter {
    config: ApiConfig,
    routes: Vec<Route>,
    middleware: Vec<Box<dyn Middleware>>,
}

#[derive(Debug, Clone)]
pub struct Route {
    pub method: HttpMethod,
    pub path: String,
    pub handler: String,
    pub auth_required: bool,
    pub permissions: Vec<Permission>,
    pub rate_limit_key: Option<String>,
    pub deprecated: bool,
    pub deprecated_message: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpMethod {
    GET,
    POST,
    PUT,
    DELETE,
    PATCH,
    OPTIONS,
}

pub trait Middleware: Send + Sync {
    fn name(&self) -> &str;
    fn process(&self, request: &mut ApiRequest) -> Result<(), ApiError>;
}

impl ApiRouter {
    pub fn new(config: ApiConfig) -> Self {
        let mut router = Self {
            config,
            routes: Vec::new(),
            middleware: Vec::new(),
        };

        router.register_default_routes();
        router
    }

    fn register_default_routes(&mut self) {
        // Health and status
        self.add_route(Route {
            method: HttpMethod::GET,
            path: "/health".to_string(),
            handler: "health_check".to_string(),
            auth_required: false,
            permissions: vec![],
            rate_limit_key: None,
            deprecated: false,
            deprecated_message: None,
        });

        self.add_route(Route {
            method: HttpMethod::GET,
            path: "/status".to_string(),
            handler: "get_status".to_string(),
            auth_required: false,
            permissions: vec![],
            rate_limit_key: None,
            deprecated: false,
            deprecated_message: None,
        });

        // Chain information
        self.add_route(Route {
            method: HttpMethod::GET,
            path: "/chain/info".to_string(),
            handler: "get_chain_info".to_string(),
            auth_required: false,
            permissions: vec![],
            rate_limit_key: None,
            deprecated: false,
            deprecated_message: None,
        });

        self.add_route(Route {
            method: HttpMethod::GET,
            path: "/chain/blocks/:height".to_string(),
            handler: "get_block".to_string(),
            auth_required: false,
            permissions: vec![],
            rate_limit_key: None,
            deprecated: false,
            deprecated_message: None,
        });

        self.add_route(Route {
            method: HttpMethod::GET,
            path: "/chain/transactions/:hash".to_string(),
            handler: "get_transaction".to_string(),
            auth_required: false,
            permissions: vec![],
            rate_limit_key: None,
            deprecated: false,
            deprecated_message: None,
        });

        // Faucet
        self.add_route(Route {
            method: HttpMethod::POST,
            path: "/faucet/request".to_string(),
            handler: "request_tokens".to_string(),
            auth_required: false,
            permissions: vec![Permission::FaucetRequest],
            rate_limit_key: Some("faucet".to_string()),
            deprecated: false,
            deprecated_message: None,
        });

        self.add_route(Route {
            method: HttpMethod::GET,
            path: "/faucet/status".to_string(),
            handler: "faucet_status".to_string(),
            auth_required: false,
            permissions: vec![],
            rate_limit_key: None,
            deprecated: false,
            deprecated_message: None,
        });

        // Accounts
        self.add_route(Route {
            method: HttpMethod::GET,
            path: "/accounts/:address".to_string(),
            handler: "get_account".to_string(),
            auth_required: false,
            permissions: vec![],
            rate_limit_key: None,
            deprecated: false,
            deprecated_message: None,
        });

        self.add_route(Route {
            method: HttpMethod::GET,
            path: "/accounts/:address/balance".to_string(),
            handler: "get_balance".to_string(),
            auth_required: false,
            permissions: vec![],
            rate_limit_key: None,
            deprecated: false,
            deprecated_message: None,
        });

        self.add_route(Route {
            method: HttpMethod::GET,
            path: "/accounts/:address/transactions".to_string(),
            handler: "get_account_transactions".to_string(),
            auth_required: false,
            permissions: vec![],
            rate_limit_key: None,
            deprecated: false,
            deprecated_message: None,
        });

        // Transactions
        self.add_route(Route {
            method: HttpMethod::POST,
            path: "/transactions/send".to_string(),
            handler: "send_transaction".to_string(),
            auth_required: true,
            permissions: vec![Permission::Write],
            rate_limit_key: Some("transactions".to_string()),
            deprecated: false,
            deprecated_message: None,
        });

        self.add_route(Route {
            method: HttpMethod::POST,
            path: "/transactions/simulate".to_string(),
            handler: "simulate_transaction".to_string(),
            auth_required: false,
            permissions: vec![],
            rate_limit_key: None,
            deprecated: false,
            deprecated_message: None,
        });

        // Seals (AI model sealing)
        self.add_route(Route {
            method: HttpMethod::POST,
            path: "/seals/create".to_string(),
            handler: "create_seal".to_string(),
            auth_required: true,
            permissions: vec![Permission::SealCreate],
            rate_limit_key: Some("seals".to_string()),
            deprecated: false,
            deprecated_message: None,
        });

        self.add_route(Route {
            method: HttpMethod::GET,
            path: "/seals/:id".to_string(),
            handler: "get_seal".to_string(),
            auth_required: false,
            permissions: vec![],
            rate_limit_key: None,
            deprecated: false,
            deprecated_message: None,
        });

        self.add_route(Route {
            method: HttpMethod::GET,
            path: "/seals/:id/verify".to_string(),
            handler: "verify_seal".to_string(),
            auth_required: false,
            permissions: vec![],
            rate_limit_key: None,
            deprecated: false,
            deprecated_message: None,
        });

        // Jobs (AI compute)
        self.add_route(Route {
            method: HttpMethod::POST,
            path: "/jobs/submit".to_string(),
            handler: "submit_job".to_string(),
            auth_required: true,
            permissions: vec![Permission::JobSubmit],
            rate_limit_key: Some("jobs".to_string()),
            deprecated: false,
            deprecated_message: None,
        });

        self.add_route(Route {
            method: HttpMethod::GET,
            path: "/jobs/:id".to_string(),
            handler: "get_job".to_string(),
            auth_required: false,
            permissions: vec![],
            rate_limit_key: None,
            deprecated: false,
            deprecated_message: None,
        });

        self.add_route(Route {
            method: HttpMethod::GET,
            path: "/jobs/:id/result".to_string(),
            handler: "get_job_result".to_string(),
            auth_required: false,
            permissions: vec![],
            rate_limit_key: None,
            deprecated: false,
            deprecated_message: None,
        });

        // Validators
        self.add_route(Route {
            method: HttpMethod::GET,
            path: "/validators".to_string(),
            handler: "list_validators".to_string(),
            auth_required: false,
            permissions: vec![],
            rate_limit_key: None,
            deprecated: false,
            deprecated_message: None,
        });

        self.add_route(Route {
            method: HttpMethod::GET,
            path: "/validators/:address".to_string(),
            handler: "get_validator".to_string(),
            auth_required: false,
            permissions: vec![],
            rate_limit_key: None,
            deprecated: false,
            deprecated_message: None,
        });

        // Webhooks
        self.add_route(Route {
            method: HttpMethod::POST,
            path: "/webhooks".to_string(),
            handler: "create_webhook".to_string(),
            auth_required: true,
            permissions: vec![Permission::WebhookManage],
            rate_limit_key: None,
            deprecated: false,
            deprecated_message: None,
        });

        self.add_route(Route {
            method: HttpMethod::GET,
            path: "/webhooks".to_string(),
            handler: "list_webhooks".to_string(),
            auth_required: true,
            permissions: vec![Permission::WebhookManage],
            rate_limit_key: None,
            deprecated: false,
            deprecated_message: None,
        });

        self.add_route(Route {
            method: HttpMethod::DELETE,
            path: "/webhooks/:id".to_string(),
            handler: "delete_webhook".to_string(),
            auth_required: true,
            permissions: vec![Permission::WebhookManage],
            rate_limit_key: None,
            deprecated: false,
            deprecated_message: None,
        });

        // Debug
        self.add_route(Route {
            method: HttpMethod::POST,
            path: "/debug/trace".to_string(),
            handler: "trace_transaction".to_string(),
            auth_required: true,
            permissions: vec![Permission::Read],
            rate_limit_key: None,
            deprecated: false,
            deprecated_message: None,
        });

        self.add_route(Route {
            method: HttpMethod::POST,
            path: "/debug/simulate".to_string(),
            handler: "debug_simulate".to_string(),
            auth_required: true,
            permissions: vec![Permission::Read],
            rate_limit_key: None,
            deprecated: false,
            deprecated_message: None,
        });

        // Models
        self.add_route(Route {
            method: HttpMethod::GET,
            path: "/models".to_string(),
            handler: "list_models".to_string(),
            auth_required: false,
            permissions: vec![],
            rate_limit_key: None,
            deprecated: false,
            deprecated_message: None,
        });

        self.add_route(Route {
            method: HttpMethod::GET,
            path: "/models/:hash".to_string(),
            handler: "get_model".to_string(),
            auth_required: false,
            permissions: vec![],
            rate_limit_key: None,
            deprecated: false,
            deprecated_message: None,
        });
    }

    pub fn add_route(&mut self, route: Route) {
        self.routes.push(route);
    }

    pub fn add_middleware(&mut self, middleware: Box<dyn Middleware>) {
        self.middleware.push(middleware);
    }

    pub fn get_routes(&self) -> &[Route] {
        &self.routes
    }

    pub fn find_route(&self, method: HttpMethod, path: &str) -> Option<&Route> {
        self.routes.iter()
            .find(|r| r.method == method && self.path_matches(&r.path, path))
    }

    fn path_matches(&self, pattern: &str, path: &str) -> bool {
        let pattern_parts: Vec<&str> = pattern.split('/').collect();
        let path_parts: Vec<&str> = path.split('/').collect();

        if pattern_parts.len() != path_parts.len() {
            return false;
        }

        for (p, s) in pattern_parts.iter().zip(path_parts.iter()) {
            if p.starts_with(':') {
                continue; // Parameter matches anything
            }
            if p != s {
                return false;
            }
        }

        true
    }

    pub fn generate_openapi_spec(&self) -> serde_json::Value {
        let mut paths = serde_json::Map::new();

        for route in &self.routes {
            let method = match route.method {
                HttpMethod::GET => "get",
                HttpMethod::POST => "post",
                HttpMethod::PUT => "put",
                HttpMethod::DELETE => "delete",
                HttpMethod::PATCH => "patch",
                HttpMethod::OPTIONS => "options",
            };

            let path_entry = paths.entry(route.path.clone())
                .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));

            if let serde_json::Value::Object(ref mut map) = path_entry {
                map.insert(method.to_string(), serde_json::json!({
                    "operationId": route.handler,
                    "security": if route.auth_required { vec![serde_json::json!({"apiKey": []})] } else { vec![] },
                    "deprecated": route.deprecated,
                    "responses": {
                        "200": { "description": "Success" },
                        "400": { "description": "Bad Request" },
                        "401": { "description": "Unauthorized" },
                        "429": { "description": "Rate Limited" },
                        "500": { "description": "Internal Error" }
                    }
                }));
            }
        }

        serde_json::json!({
            "openapi": "3.0.0",
            "info": {
                "title": "Aethelred Testnet API",
                "version": self.config.version.as_str(),
                "description": "API for interacting with the Aethelred AI Blockchain Testnet"
            },
            "servers": [
                { "url": "https://testnet-api.aethelred.io/api/v1" }
            ],
            "paths": paths,
            "components": {
                "securitySchemes": {
                    "apiKey": {
                        "type": "apiKey",
                        "in": "header",
                        "name": "X-Api-Key"
                    },
                    "bearerAuth": {
                        "type": "http",
                        "scheme": "bearer",
                        "bearerFormat": "JWT"
                    }
                }
            }
        })
    }
}

// ============ Request/Response Types ============

#[derive(Debug, Clone)]
pub struct ApiRequest {
    pub id: String,
    pub method: HttpMethod,
    pub path: String,
    pub headers: HashMap<String, String>,
    pub query_params: HashMap<String, String>,
    pub body: Option<serde_json::Value>,
    pub auth: Option<AuthInfo>,
    pub client_ip: String,
    pub timestamp: u64,
}

#[derive(Debug, Clone)]
pub struct AuthInfo {
    pub user_id: String,
    pub tier: ApiTier,
    pub permissions: Vec<Permission>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ApiResponse {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: serde_json::Value,
    pub request_id: String,
    pub latency_ms: u64,
}

impl ApiResponse {
    pub fn success(body: serde_json::Value, request_id: &str) -> Self {
        Self {
            status: 200,
            headers: HashMap::new(),
            body,
            request_id: request_id.to_string(),
            latency_ms: 0,
        }
    }

    pub fn error(status: u16, message: &str, request_id: &str) -> Self {
        Self {
            status,
            headers: HashMap::new(),
            body: serde_json::json!({
                "error": {
                    "code": status,
                    "message": message
                }
            }),
            request_id: request_id.to_string(),
            latency_ms: 0,
        }
    }

    pub fn with_rate_limit_headers(mut self, remaining: u32, reset_at: u64) -> Self {
        self.headers.insert("X-RateLimit-Remaining".to_string(), remaining.to_string());
        self.headers.insert("X-RateLimit-Reset".to_string(), reset_at.to_string());
        self
    }
}

#[derive(Debug, Clone)]
pub struct ApiError {
    pub status: u16,
    pub code: String,
    pub message: String,
    pub details: Option<serde_json::Value>,
}

impl ApiError {
    pub fn bad_request(message: &str) -> Self {
        Self {
            status: 400,
            code: "BAD_REQUEST".to_string(),
            message: message.to_string(),
            details: None,
        }
    }

    pub fn unauthorized(message: &str) -> Self {
        Self {
            status: 401,
            code: "UNAUTHORIZED".to_string(),
            message: message.to_string(),
            details: None,
        }
    }

    pub fn forbidden(message: &str) -> Self {
        Self {
            status: 403,
            code: "FORBIDDEN".to_string(),
            message: message.to_string(),
            details: None,
        }
    }

    pub fn not_found(resource: &str) -> Self {
        Self {
            status: 404,
            code: "NOT_FOUND".to_string(),
            message: format!("{} not found", resource),
            details: None,
        }
    }

    pub fn rate_limited(retry_after_ms: u64) -> Self {
        Self {
            status: 429,
            code: "RATE_LIMITED".to_string(),
            message: "Too many requests".to_string(),
            details: Some(serde_json::json!({ "retry_after_ms": retry_after_ms })),
        }
    }

    pub fn internal(message: &str) -> Self {
        Self {
            status: 500,
            code: "INTERNAL_ERROR".to_string(),
            message: message.to_string(),
            details: None,
        }
    }
}

// ============ WebSocket Types ============

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WsMessage {
    pub msg_type: WsMessageType,
    pub channel: Option<String>,
    pub data: serde_json::Value,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WsMessageType {
    Subscribe,
    Unsubscribe,
    Event,
    Error,
    Ping,
    Pong,
    Auth,
}

#[derive(Debug, Clone)]
pub struct WsSubscription {
    pub id: String,
    pub channel: String,
    pub filters: HashMap<String, String>,
    pub created_at: u64,
}

pub struct WsConnectionManager {
    connections: HashMap<String, WsConnection>,
    subscriptions: HashMap<String, Vec<String>>, // channel -> connection_ids
    metrics: WsMetrics,
}

#[derive(Debug, Clone)]
pub struct WsConnection {
    pub id: String,
    pub client_ip: String,
    pub auth: Option<AuthInfo>,
    pub subscriptions: Vec<WsSubscription>,
    pub connected_at: u64,
    pub last_ping: u64,
    pub messages_received: u64,
    pub messages_sent: u64,
}

#[derive(Debug, Clone, Default)]
pub struct WsMetrics {
    pub active_connections: u64,
    pub total_connections: u64,
    pub messages_in: u64,
    pub messages_out: u64,
    pub subscriptions_by_channel: HashMap<String, u64>,
}

impl WsConnectionManager {
    pub fn new() -> Self {
        Self {
            connections: HashMap::new(),
            subscriptions: HashMap::new(),
            metrics: WsMetrics::default(),
        }
    }

    pub fn add_connection(&mut self, connection: WsConnection) {
        let id = connection.id.clone();
        self.connections.insert(id, connection);
        self.metrics.active_connections += 1;
        self.metrics.total_connections += 1;
    }

    pub fn remove_connection(&mut self, connection_id: &str) {
        if let Some(conn) = self.connections.remove(connection_id) {
            // Remove from all subscriptions
            for sub in &conn.subscriptions {
                if let Some(subs) = self.subscriptions.get_mut(&sub.channel) {
                    subs.retain(|id| id != connection_id);
                }
            }
            self.metrics.active_connections = self.metrics.active_connections.saturating_sub(1);
        }
    }

    pub fn subscribe(&mut self, connection_id: &str, channel: &str, filters: HashMap<String, String>) -> Result<String, String> {
        let conn = self.connections.get_mut(connection_id)
            .ok_or_else(|| "Connection not found".to_string())?;

        let sub_id = format!("sub_{}", generate_id());
        let subscription = WsSubscription {
            id: sub_id.clone(),
            channel: channel.to_string(),
            filters,
            created_at: current_timestamp(),
        };

        conn.subscriptions.push(subscription);

        self.subscriptions.entry(channel.to_string())
            .or_insert_with(Vec::new)
            .push(connection_id.to_string());

        *self.metrics.subscriptions_by_channel.entry(channel.to_string()).or_insert(0) += 1;

        Ok(sub_id)
    }

    pub fn unsubscribe(&mut self, connection_id: &str, subscription_id: &str) -> Result<(), String> {
        let conn = self.connections.get_mut(connection_id)
            .ok_or_else(|| "Connection not found".to_string())?;

        if let Some(pos) = conn.subscriptions.iter().position(|s| s.id == subscription_id) {
            let sub = conn.subscriptions.remove(pos);

            if let Some(subs) = self.subscriptions.get_mut(&sub.channel) {
                subs.retain(|id| id != connection_id);
            }

            if let Some(count) = self.metrics.subscriptions_by_channel.get_mut(&sub.channel) {
                *count = count.saturating_sub(1);
            }
        }

        Ok(())
    }

    pub fn broadcast_to_channel(&mut self, channel: &str, message: WsMessage) -> usize {
        let connection_ids = match self.subscriptions.get(channel) {
            Some(ids) => ids.clone(),
            None => return 0,
        };

        let mut sent = 0;
        for conn_id in connection_ids {
            if let Some(conn) = self.connections.get_mut(&conn_id) {
                conn.messages_sent += 1;
                self.metrics.messages_out += 1;
                sent += 1;
            }
        }

        sent
    }

    pub fn metrics(&self) -> &WsMetrics {
        &self.metrics
    }

    pub fn available_channels() -> Vec<&'static str> {
        vec![
            "blocks",
            "transactions",
            "seals",
            "jobs",
            "validators",
            "faucet",
            "debug",
        ]
    }
}

impl Default for WsConnectionManager {
    fn default() -> Self {
        Self::new()
    }
}

// ============ SDK Integration ============

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SdkConfig {
    /// Testnet RPC URL
    pub rpc_url: String,

    /// WebSocket URL
    pub ws_url: String,

    /// API key
    pub api_key: Option<String>,

    /// Request timeout (ms)
    pub timeout_ms: u64,

    /// Enable retry
    pub retry_enabled: bool,

    /// Max retries
    pub max_retries: u32,

    /// Network ID
    pub network_id: String,

    /// Chain ID
    pub chain_id: String,
}

impl Default for SdkConfig {
    fn default() -> Self {
        Self {
            rpc_url: "https://testnet-api.aethelred.io".to_string(),
            ws_url: "wss://testnet-ws.aethelred.io".to_string(),
            api_key: None,
            timeout_ms: 30000,
            retry_enabled: true,
            max_retries: 3,
            network_id: "aethelred-testnet-1".to_string(),
            chain_id: "aethelred-testnet".to_string(),
        }
    }
}

/// SDK code generator for different languages
pub struct SdkGenerator {
    config: SdkConfig,
    routes: Vec<Route>,
}

impl SdkGenerator {
    pub fn new(config: SdkConfig, routes: Vec<Route>) -> Self {
        Self { config, routes }
    }

    /// Generate TypeScript SDK snippet
    pub fn generate_typescript(&self) -> String {
        let mut code = String::new();

        code.push_str("// Aethelred Testnet SDK\n");
        code.push_str("// Auto-generated TypeScript client\n\n");

        code.push_str("export interface AethelredConfig {\n");
        code.push_str("  rpcUrl: string;\n");
        code.push_str("  wsUrl: string;\n");
        code.push_str("  apiKey?: string;\n");
        code.push_str("  timeout?: number;\n");
        code.push_str("}\n\n");

        code.push_str("export class AethelredClient {\n");
        code.push_str("  private config: AethelredConfig;\n\n");

        code.push_str("  constructor(config: Partial<AethelredConfig> = {}) {\n");
        code.push_str(&format!("    this.config = {{\n"));
        code.push_str(&format!("      rpcUrl: config.rpcUrl || '{}',\n", self.config.rpc_url));
        code.push_str(&format!("      wsUrl: config.wsUrl || '{}',\n", self.config.ws_url));
        code.push_str("      apiKey: config.apiKey,\n");
        code.push_str(&format!("      timeout: config.timeout || {},\n", self.config.timeout_ms));
        code.push_str("    };\n");
        code.push_str("  }\n\n");

        // Generate methods for each route
        for route in &self.routes {
            let method_name = route.handler.replace("_", "");
            let http_method = match route.method {
                HttpMethod::GET => "GET",
                HttpMethod::POST => "POST",
                HttpMethod::PUT => "PUT",
                HttpMethod::DELETE => "DELETE",
                _ => "GET",
            };

            code.push_str(&format!("  async {}(", method_name));

            // Add parameters for path variables
            let params: Vec<&str> = route.path.split('/')
                .filter(|p| p.starts_with(':'))
                .map(|p| &p[1..])
                .collect();

            for (i, param) in params.iter().enumerate() {
                if i > 0 { code.push_str(", "); }
                code.push_str(&format!("{}: string", param));
            }

            if route.method == HttpMethod::POST || route.method == HttpMethod::PUT {
                if !params.is_empty() { code.push_str(", "); }
                code.push_str("body?: any");
            }

            code.push_str("): Promise<any> {\n");

            let mut path = route.path.clone();
            for param in params {
                path = path.replace(&format!(":{}", param), &format!("${{{}}}", param));
            }

            code.push_str(&format!("    const url = `${{this.config.rpcUrl}}{}`;\n", path));
            code.push_str(&format!("    return this.request('{}', url", http_method));
            if route.method == HttpMethod::POST || route.method == HttpMethod::PUT {
                code.push_str(", body");
            }
            code.push_str(");\n");
            code.push_str("  }\n\n");
        }

        // Add request helper
        code.push_str("  private async request(method: string, url: string, body?: any): Promise<any> {\n");
        code.push_str("    const headers: Record<string, string> = {\n");
        code.push_str("      'Content-Type': 'application/json',\n");
        code.push_str("    };\n");
        code.push_str("    if (this.config.apiKey) {\n");
        code.push_str("      headers['X-Api-Key'] = this.config.apiKey;\n");
        code.push_str("    }\n");
        code.push_str("    const response = await fetch(url, {\n");
        code.push_str("      method,\n");
        code.push_str("      headers,\n");
        code.push_str("      body: body ? JSON.stringify(body) : undefined,\n");
        code.push_str("    });\n");
        code.push_str("    return response.json();\n");
        code.push_str("  }\n");

        code.push_str("}\n");

        code
    }

    /// Generate Python SDK snippet
    pub fn generate_python(&self) -> String {
        let mut code = String::new();

        code.push_str("# Aethelred Testnet SDK\n");
        code.push_str("# Auto-generated Python client\n\n");
        code.push_str("import requests\n");
        code.push_str("from typing import Optional, Dict, Any\n\n");

        code.push_str("class AethelredClient:\n");
        code.push_str("    def __init__(\n");
        code.push_str("        self,\n");
        code.push_str(&format!("        rpc_url: str = '{}',\n", self.config.rpc_url));
        code.push_str(&format!("        ws_url: str = '{}',\n", self.config.ws_url));
        code.push_str("        api_key: Optional[str] = None,\n");
        code.push_str(&format!("        timeout: int = {}\n", self.config.timeout_ms / 1000));
        code.push_str("    ):\n");
        code.push_str("        self.rpc_url = rpc_url\n");
        code.push_str("        self.ws_url = ws_url\n");
        code.push_str("        self.api_key = api_key\n");
        code.push_str("        self.timeout = timeout\n\n");

        // Generate methods
        for route in &self.routes {
            let method_name = route.handler.clone();

            code.push_str(&format!("    def {}(self", method_name));

            let params: Vec<&str> = route.path.split('/')
                .filter(|p| p.starts_with(':'))
                .map(|p| &p[1..])
                .collect();

            for param in &params {
                code.push_str(&format!(", {}: str", param));
            }

            if route.method == HttpMethod::POST || route.method == HttpMethod::PUT {
                code.push_str(", body: Optional[Dict[str, Any]] = None");
            }

            code.push_str(") -> Dict[str, Any]:\n");

            let mut path = route.path.clone();
            for param in &params {
                path = path.replace(&format!(":{}", param), &format!("{{{}}}", param));
            }

            code.push_str(&format!("        url = f'{{self.rpc_url}}{}'\n", path));
            code.push_str("        return self._request(\n");
            code.push_str(&format!("            '{}',\n", match route.method {
                HttpMethod::GET => "GET",
                HttpMethod::POST => "POST",
                HttpMethod::PUT => "PUT",
                HttpMethod::DELETE => "DELETE",
                _ => "GET",
            }));
            code.push_str("            url");
            if route.method == HttpMethod::POST || route.method == HttpMethod::PUT {
                code.push_str(",\n            json=body");
            }
            code.push_str("\n        )\n\n");
        }

        // Add request helper
        code.push_str("    def _request(\n");
        code.push_str("        self,\n");
        code.push_str("        method: str,\n");
        code.push_str("        url: str,\n");
        code.push_str("        json: Optional[Dict[str, Any]] = None\n");
        code.push_str("    ) -> Dict[str, Any]:\n");
        code.push_str("        headers = {'Content-Type': 'application/json'}\n");
        code.push_str("        if self.api_key:\n");
        code.push_str("            headers['X-Api-Key'] = self.api_key\n");
        code.push_str("        response = requests.request(\n");
        code.push_str("            method,\n");
        code.push_str("            url,\n");
        code.push_str("            headers=headers,\n");
        code.push_str("            json=json,\n");
        code.push_str("            timeout=self.timeout\n");
        code.push_str("        )\n");
        code.push_str("        response.raise_for_status()\n");
        code.push_str("        return response.json()\n");

        code
    }

    /// Generate Go SDK snippet
    pub fn generate_go(&self) -> String {
        let mut code = String::new();

        code.push_str("// Aethelred Testnet SDK\n");
        code.push_str("// Auto-generated Go client\n\n");
        code.push_str("package aethelred\n\n");

        code.push_str("import (\n");
        code.push_str("    \"bytes\"\n");
        code.push_str("    \"encoding/json\"\n");
        code.push_str("    \"fmt\"\n");
        code.push_str("    \"net/http\"\n");
        code.push_str("    \"time\"\n");
        code.push_str(")\n\n");

        code.push_str("type Client struct {\n");
        code.push_str("    RPCURL   string\n");
        code.push_str("    WSURL    string\n");
        code.push_str("    APIKey   string\n");
        code.push_str("    Timeout  time.Duration\n");
        code.push_str("    client   *http.Client\n");
        code.push_str("}\n\n");

        code.push_str("func NewClient(apiKey string) *Client {\n");
        code.push_str("    return &Client{\n");
        code.push_str(&format!("        RPCURL:  \"{}\",\n", self.config.rpc_url));
        code.push_str(&format!("        WSURL:   \"{}\",\n", self.config.ws_url));
        code.push_str("        APIKey:  apiKey,\n");
        code.push_str(&format!("        Timeout: {} * time.Millisecond,\n", self.config.timeout_ms));
        code.push_str("        client:  &http.Client{},\n");
        code.push_str("    }\n");
        code.push_str("}\n\n");

        // Generate a few example methods
        code.push_str("func (c *Client) GetChainInfo() (map[string]interface{}, error) {\n");
        code.push_str("    return c.request(\"GET\", \"/chain/info\", nil)\n");
        code.push_str("}\n\n");

        code.push_str("func (c *Client) GetBlock(height string) (map[string]interface{}, error) {\n");
        code.push_str("    return c.request(\"GET\", fmt.Sprintf(\"/chain/blocks/%s\", height), nil)\n");
        code.push_str("}\n\n");

        code.push_str("func (c *Client) RequestTokens(address string) (map[string]interface{}, error) {\n");
        code.push_str("    body := map[string]string{\"address\": address}\n");
        code.push_str("    return c.request(\"POST\", \"/faucet/request\", body)\n");
        code.push_str("}\n\n");

        // Request helper
        code.push_str("func (c *Client) request(method, path string, body interface{}) (map[string]interface{}, error) {\n");
        code.push_str("    var buf bytes.Buffer\n");
        code.push_str("    if body != nil {\n");
        code.push_str("        if err := json.NewEncoder(&buf).Encode(body); err != nil {\n");
        code.push_str("            return nil, err\n");
        code.push_str("        }\n");
        code.push_str("    }\n\n");
        code.push_str("    req, err := http.NewRequest(method, c.RPCURL+path, &buf)\n");
        code.push_str("    if err != nil {\n");
        code.push_str("        return nil, err\n");
        code.push_str("    }\n\n");
        code.push_str("    req.Header.Set(\"Content-Type\", \"application/json\")\n");
        code.push_str("    if c.APIKey != \"\" {\n");
        code.push_str("        req.Header.Set(\"X-Api-Key\", c.APIKey)\n");
        code.push_str("    }\n\n");
        code.push_str("    resp, err := c.client.Do(req)\n");
        code.push_str("    if err != nil {\n");
        code.push_str("        return nil, err\n");
        code.push_str("    }\n");
        code.push_str("    defer resp.Body.Close()\n\n");
        code.push_str("    var result map[string]interface{}\n");
        code.push_str("    if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {\n");
        code.push_str("        return nil, err\n");
        code.push_str("    }\n\n");
        code.push_str("    return result, nil\n");
        code.push_str("}\n");

        code
    }
}

// ============ API Metrics ============

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ApiMetrics {
    pub total_requests: u64,
    pub successful_requests: u64,
    pub failed_requests: u64,
    pub avg_response_time_ms: f64,
    pub requests_by_endpoint: HashMap<String, u64>,
    pub requests_by_status: HashMap<u16, u64>,
    pub active_connections: u64,
    pub ws_messages_in: u64,
    pub ws_messages_out: u64,
}

// ============ Helper Functions ============

fn generate_id() -> String {
    let timestamp = current_timestamp();
    let random: u64 = rand::random();
    format!("{:x}{:x}", timestamp, random)
}

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn hash_key(key: &str) -> String {
    let mut hash: u64 = 5381;
    for byte in key.bytes() {
        hash = hash.wrapping_mul(33).wrapping_add(byte as u64);
    }
    format!("{:x}", hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limiter() {
        let config = RateLimitConfig::default();
        let mut limiter = RateLimiter::new(config);

        // First request should be allowed
        let result = limiter.check("user1", "/test", ApiTier::Basic);
        assert!(matches!(result, RateLimitResult::Allowed { .. }));
    }

    #[test]
    fn test_api_key_manager() {
        let mut manager = ApiKeyManager::new();

        let (raw_key, api_key) = manager.create_key(
            "owner1",
            "Test Key",
            "basic",
            vec![Permission::Read, Permission::Write],
        );

        assert!(api_key.active);
        assert!(manager.validate(&raw_key).is_some());
    }

    #[test]
    fn test_router() {
        let config = ApiConfig::default();
        let router = ApiRouter::new(config);

        // Should find health route
        let route = router.find_route(HttpMethod::GET, "/health");
        assert!(route.is_some());
        assert_eq!(route.unwrap().handler, "health_check");
    }

    #[test]
    fn test_sdk_generator() {
        let config = SdkConfig::default();
        let routes = vec![
            Route {
                method: HttpMethod::GET,
                path: "/chain/info".to_string(),
                handler: "get_chain_info".to_string(),
                auth_required: false,
                permissions: vec![],
                rate_limit_key: None,
                deprecated: false,
                deprecated_message: None,
            },
        ];

        let generator = SdkGenerator::new(config, routes);

        let ts_code = generator.generate_typescript();
        assert!(ts_code.contains("class AethelredClient"));

        let py_code = generator.generate_python();
        assert!(py_code.contains("class AethelredClient"));

        let go_code = generator.generate_go();
        assert!(go_code.contains("type Client struct"));
    }

    #[test]
    fn test_ws_connection_manager() {
        let mut manager = WsConnectionManager::new();

        let conn = WsConnection {
            id: "conn1".to_string(),
            client_ip: "127.0.0.1".to_string(),
            auth: None,
            subscriptions: Vec::new(),
            connected_at: current_timestamp(),
            last_ping: current_timestamp(),
            messages_received: 0,
            messages_sent: 0,
        };

        manager.add_connection(conn);
        assert_eq!(manager.metrics().active_connections, 1);

        manager.subscribe("conn1", "blocks", HashMap::new()).unwrap();
        assert_eq!(*manager.metrics().subscriptions_by_channel.get("blocks").unwrap(), 1);
    }
}
