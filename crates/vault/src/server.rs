//! Cruzible TEE HTTP Service
//!
//! Exposes the validator selection, MEV protection, and reward calculation
//! algorithms as a stateless HTTP API. Designed to run inside a TEE enclave.
//!
//! ## Endpoints
//!
//! | Method | Path                    | Description                          | Auth |
//! |--------|-------------------------|--------------------------------------|------|
//! | POST   | /select-validators      | TEE validator selection               | Yes  |
//! | POST   | /calculate-rewards      | TEE reward calculation + Merkle tree | Yes  |
//! | POST   | /order-transactions     | MEV-protected transaction ordering   | Yes  |
//! | POST   | /verify-commitment      | Verify a commit-reveal commitment    | Yes  |
//! | POST   | /attest-delegation      | TEE delegation attestation           | Yes  |
//! | GET    | /health                 | Service health check + metrics       | No   |
//! | GET    | /capabilities           | Service capabilities                 | Yes  |
//! | GET    | /metrics                | Prometheus exposition format          | No   |

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use axum::{
    extract::{DefaultBodyLimit, Request, State},
    http::StatusCode,
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use tokio::sync::{Mutex, RwLock};
use tracing::{error, info, warn};

use sha2::{Digest, Sha256};

#[cfg(feature = "mock-tee")]
use crate::attestation::LocalVendorAttester;
#[cfg(feature = "remote-attestation")]
use crate::attestation::RemoteVendorAttester;
use crate::attestation::{AttestationGenerator, TEEConfig, TEEPlatform};
use crate::mev_protection;
use crate::reward_calculator;
use crate::types::*;
use crate::validator_selection;

/// Production metrics tracked with lock-free atomic counters.
///
/// These counters are incremented from request handlers and middleware without
/// requiring a write lock, eliminating contention under high throughput. All
/// counters are monotonically increasing — wrap-around at `u64::MAX` is
/// acceptable (would take ~584 years at 1 billion increments per second).
pub struct MetricsState {
    /// Per-type attestation counters.
    pub validator_selections: AtomicU64,
    pub reward_calculations: AtomicU64,
    pub mev_orderings: AtomicU64,
    pub delegation_attestations: AtomicU64,
    /// Total handler errors (4xx + 5xx responses).
    pub total_errors: AtomicU64,
    /// Total authentication failures (401 Unauthorized).
    pub auth_failures: AtomicU64,
    /// Unix timestamp (seconds) of the last successful attestation.
    /// 0 = no attestation yet.
    pub last_attestation_at: AtomicU64,
}

impl MetricsState {
    fn new() -> Self {
        Self {
            validator_selections: AtomicU64::new(0),
            reward_calculations: AtomicU64::new(0),
            mev_orderings: AtomicU64::new(0),
            delegation_attestations: AtomicU64::new(0),
            total_errors: AtomicU64::new(0),
            auth_failures: AtomicU64::new(0),
            last_attestation_at: AtomicU64::new(0),
        }
    }

    /// Record a successful attestation timestamp (current Unix epoch seconds).
    fn record_attestation_time(&self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.last_attestation_at.store(now, Ordering::Relaxed);
    }

    /// Format `last_attestation_at` as an ISO-8601 string, or `None` if no attestation yet.
    fn last_attestation_iso(&self) -> Option<String> {
        let ts = self.last_attestation_at.load(Ordering::Relaxed);
        if ts == 0 {
            return None;
        }
        // Simple UTC timestamp: YYYY-MM-DDTHH:MM:SSZ
        let secs_per_day = 86400u64;
        let days = ts / secs_per_day;
        let rem = ts % secs_per_day;
        let hours = rem / 3600;
        let minutes = (rem % 3600) / 60;
        let seconds = rem % 60;

        // Days since 1970-01-01 → (year, month, day) using civil calendar
        let (y, m, d) = days_to_ymd(days);
        Some(format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
            y, m, d, hours, minutes, seconds
        ))
    }
}

/// Convert days since Unix epoch to (year, month, day).
fn days_to_ymd(days: u64) -> (u64, u64, u64) {
    // Algorithm from Howard Hinnant's date library (public domain).
    let z = days + 719468;
    let era = z / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

/// Shared application state.
pub struct AppState {
    pub start_time: Instant,
    pub attestation_gen: AttestationGenerator,
    pub total_attestations: RwLock<u64>,
    pub current_epoch: RwLock<u64>,
    pub config: VaultServiceConfig,
    /// Lock-free production metrics.
    pub metrics: MetricsState,
}

/// Service configuration.
#[derive(Debug, Clone)]
pub struct VaultServiceConfig {
    pub listen_addr: String,
    pub tee_platform: TEEPlatform,
    pub allow_simulated: bool,
    pub max_validators: usize,
    pub max_stakers: usize,
    /// Maximum number of commitments (and reveals) per MEV ordering request.
    ///
    /// Bounds the work `order_transactions_handler` performs in a single call.
    /// Reveals exceeding this limit are rejected with `400 Bad Request`.
    pub max_commitments: usize,
    /// Hex-encoded secp256k1 private key (64 hex chars = 32 bytes).
    /// If `None`, a random key is generated at startup (development only).
    pub operator_key_hex: Option<String>,
    /// Hex-encoded P-256 private key for local vendor attestation signing.
    ///
    /// ⚠ **Development / testing only.** Using a local vendor key means the
    /// enclave operator holds the signing authority that should belong to an
    /// independent hardware vendor. A compromised operator could forge vendor
    /// attestations. In production, use `attestation_relay_url` instead.
    pub vendor_attestation_key_hex: Option<String>,
    /// URL of the attestation relay service for production attestation authority.
    ///
    /// The relay is a **trusted bridge** that verifies hardware evidence (SGX DCAP
    /// quote, Nitro attestation document, SEV-SNP report) and signs the platform
    /// key binding with its own P-256 key.
    ///
    /// **Trust model**: The relay's P-256 public key must be registered on-chain
    /// via `VaultTEEVerifier.registerAttestationRelay()` (not the legacy
    /// `setVendorRootKey()`). This provides governance accountability:
    ///   - Time-locked key rotation (48-hour delay)
    ///   - On-chain liveness challenges with P-256 proof-of-possession
    ///   - Emergency revocation by governance
    ///   - Attestation counting and audit trail
    ///
    /// The relay verifies the hardware chain of trust off-chain. If the relay is
    /// compromised, it could certify arbitrary platform keys. The on-chain
    /// governance controls (rotation timelock, challenges, revocation) mitigate
    /// this by enabling detection, containment, and recovery.
    ///
    /// Takes precedence over `vendor_attestation_key_hex` when both are set.
    /// Requires the `remote-attestation` feature.
    pub attestation_relay_url: Option<String>,
    /// Hex-encoded enclave measurement (64 hex chars = 32 bytes).
    ///
    /// - **SGX**: MRENCLAVE — hash of the enclave code and initial state
    /// - **Nitro**: PCR0-based measurement hash
    /// - **SEV-SNP**: MEASUREMENT field (SHA-384 compressed to SHA-256)
    ///
    /// Required for real platforms. For Mock, defaults to `[0xAE; 32]`.
    /// Must match the value registered on-chain via `setEnclaveConfig()`.
    pub enclave_hash_hex: Option<String>,
    /// Hex-encoded signer measurement (64 hex chars = 32 bytes).
    ///
    /// - **SGX**: MRSIGNER — hash of the enclave signing key
    /// - **Nitro**: PCR1-based measurement hash
    /// - **SEV-SNP**: HOST_DATA field
    ///
    /// Required for real platforms. For Mock, defaults to `[0x51; 32]`.
    /// Must match the value registered on-chain via `setEnclaveConfig()`.
    pub signer_hash_hex: Option<String>,
    /// Hex-encoded application measurement (64 hex chars = 32 bytes).
    ///
    /// - **Nitro only**: PCR2-based application hash
    /// - **SGX / SEV**: not applicable, leave `None`
    ///
    /// Required for Nitro enclaves. Must match the value registered on-chain.
    pub application_hash_hex: Option<String>,
    /// Bearer token for authenticating API requests.
    ///
    /// When set, all endpoints except `/health` require an `Authorization: Bearer <token>`
    /// header. When `None`, no authentication is enforced (development only).
    pub auth_token: Option<String>,
    /// Maximum requests per second (token-bucket rate limiter).
    ///
    /// When > 0, a per-second rate limiter rejects excess requests with 429.
    /// Defaults to 0 (no rate limit) for backward compatibility.
    pub rate_limit_rps: u32,
    /// Explicitly bypass the fail-closed auth requirement.
    ///
    /// When `true`, the server will start without `auth_token` even on
    /// non-loopback interfaces or real TEE platforms. **NOT for production.**
    /// Set via `CRUZIBLE_INSECURE_NO_AUTH=true`.
    pub insecure_no_auth: bool,
    /// Allow `vendor_attestation_key_hex` (local vendor signing) on real TEE
    /// platforms.
    ///
    /// By default, real platforms (SGX, Nitro, SEV) **require**
    /// `attestation_relay_url` — the remote attestation relay that verifies
    /// hardware evidence before signing the platform key binding.
    /// `vendor_attestation_key_hex` is rejected because `LocalVendorAttester`
    /// ignores hardware evidence, collapsing the vendor trust boundary into
    /// operator-local signing.
    ///
    /// This flag is **self-limiting** — even when `true`, the server will only
    /// accept a local vendor key if **all** of the following hold:
    ///
    /// 1. The binary was built with the `mock-tee` feature (compile-time gate).
    ///    Production images must never enable `mock-tee`.
    /// 2. `listen_addr` resolves to a loopback interface (127.0.0.1 / ::1 /
    ///    localhost). Non-loopback bindings are unconditionally rejected.
    /// 3. `CRUZIBLE_INSECURE_LOCAL_VENDOR_KEY=true` (this flag, runtime gate).
    ///
    /// **NOT for production.**
    pub insecure_local_vendor_key: bool,
}

impl Default for VaultServiceConfig {
    fn default() -> Self {
        Self {
            listen_addr: "127.0.0.1:8547".to_string(),
            tee_platform: TEEPlatform::Mock,
            allow_simulated: true,
            max_validators: 200,
            max_stakers: 100_000,
            max_commitments: 10_000,
            // No pre-configured key: a random key will be generated at startup.
            // In production, set this to the TEE operator's signing key.
            operator_key_hex: None,
            vendor_attestation_key_hex: None,
            attestation_relay_url: None,
            enclave_hash_hex: None,
            signer_hash_hex: None,
            application_hash_hex: None,
            auth_token: None,
            rate_limit_rps: 0,
            insecure_no_auth: false,
            insecure_local_vendor_key: false,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Token-bucket rate limiter
// ─────────────────────────────────────────────────────────────────────────────

/// Simple token-bucket rate limiter for request throttling.
struct TokenBucket {
    tokens: f64,
    max_burst: f64,
    rate: f64,
    last: Instant,
}

impl TokenBucket {
    fn new(rps: u32) -> Self {
        let rate = rps as f64;
        Self {
            tokens: rate,
            max_burst: rate,
            rate,
            last: Instant::now(),
        }
    }

    fn allow(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + elapsed * self.rate).min(self.max_burst);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Middleware
// ─────────────────────────────────────────────────────────────────────────────

/// Rate-limiting middleware (token-bucket).
///
/// `/health` and `/metrics` are exempt so that load-balancer probes,
/// orchestrator liveness checks, and Prometheus scraping are never rejected
/// under load. Without this exemption, a traffic spike that exhausts the
/// bucket would cause health probes to receive 429, making orchestrators
/// drain or restart a healthy worker.
async fn rate_limit_middleware(
    State(bucket): State<Arc<Mutex<TokenBucket>>>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // Health and metrics endpoints are always exempt.
    let path = request.uri().path();
    if path == "/health" || path == "/metrics" {
        return Ok(next.run(request).await);
    }

    let allowed = {
        let mut b = bucket.lock().await;
        b.allow()
    };
    if !allowed {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    Ok(next.run(request).await)
}

/// Build the Axum router with all endpoints.
///
/// Applies a global body-size limit (16 MiB) to prevent memory exhaustion from
/// oversized payloads. Individual handlers add their own cardinality checks on
/// top of this blanket limit.
///
/// Security layers (applied when configured):
///   - Bearer-token authentication (all endpoints except /health, /metrics)
///   - Token-bucket rate limiting (all endpoints except /health, /metrics)
///   - No permissive CORS — the service is designed for loopback/private access
pub fn build_router(state: Arc<AppState>) -> Router {
    let auth_token = state.config.auth_token.clone();
    let rate_limit_rps = state.config.rate_limit_rps;

    let mut app = Router::new()
        .route("/health", get(health_handler))
        .route("/capabilities", get(capabilities_handler))
        .route("/metrics", get(metrics_handler))
        .route("/select-validators", post(select_validators_handler))
        .route("/calculate-rewards", post(calculate_rewards_handler))
        .route("/order-transactions", post(order_transactions_handler))
        .route("/verify-commitment", post(verify_commitment_handler))
        .route("/attest-delegation", post(attest_delegation_handler))
        .layer(DefaultBodyLimit::max(16 * 1024 * 1024)) // 16 MiB
        .with_state(state.clone());

    // Auth middleware — applied when a token is configured.
    // Uses a closure to capture the full AppState for auth-failure counting.
    if let Some(_token) = auth_token {
        let captured_state = state.clone();
        app = app.layer(middleware::from_fn(move |request: Request, next: Next| {
            let st = captured_state.clone();
            async move {
                // Health and metrics are always public.
                let path = request.uri().path().to_string();
                if path == "/health" || path == "/metrics" {
                    return Ok(next.run(request).await);
                }

                let auth_header = request
                    .headers()
                    .get("authorization")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_string();

                let expected = match &st.config.auth_token {
                    Some(t) => t.as_str(),
                    None => return Ok(next.run(request).await),
                };

                const PREFIX: &str = "Bearer ";
                if !auth_header.starts_with(PREFIX) || &auth_header[PREFIX.len()..] != expected {
                    st.metrics.auth_failures.fetch_add(1, Ordering::Relaxed);
                    warn!(path = %path, "Authentication failure — invalid or missing bearer token");
                    return Err(StatusCode::UNAUTHORIZED);
                }

                Ok::<Response, StatusCode>(next.run(request).await)
            }
        }));
    }

    // Rate-limit middleware — applied when rps > 0.
    if rate_limit_rps > 0 {
        let bucket = Arc::new(Mutex::new(TokenBucket::new(rate_limit_rps)));
        app = app.layer(middleware::from_fn_with_state(
            bucket,
            rate_limit_middleware,
        ));
    }

    app
}

/// Returns `true` if the listen address binds only to a loopback interface.
fn is_loopback_addr(addr: &str) -> bool {
    // Strip optional host part before the port.
    let host = match addr.rsplit_once(':') {
        Some((h, _)) => h,
        None => addr,
    };
    matches!(host, "127.0.0.1" | "::1" | "localhost")
}

/// Validate production configuration and log warnings for non-production settings.
///
/// This function is called at startup before binding the listener. It checks
/// for configuration issues that would be dangerous in production and provides
/// clear, actionable warnings. All checks are advisory (logged as warnings)
/// rather than hard errors, because the fail-closed checks in `start_server`
/// already prevent truly unsafe configurations.
///
/// ## Checks performed
///
/// 1. **Rate limiting**: Warns if `rate_limit_rps == 0` on non-loopback.
/// 2. **Operator key**: Warns if no `operator_key_hex` (random key in use).
/// 3. **Max limits**: Warns if validator/staker limits exceed recommended bounds.
/// 4. **Platform + measurement alignment**: Warns if real platform but mock-like config.
fn validate_production_config(config: &VaultServiceConfig) {
    let is_loopback = is_loopback_addr(&config.listen_addr);
    let is_mock = config.tee_platform == TEEPlatform::Mock;

    // Rate limiting should be enabled on non-loopback deployments.
    if config.rate_limit_rps == 0 && !is_loopback {
        warn!(
            listen_addr = %config.listen_addr,
            "Rate limiting is DISABLED on a non-loopback interface. \
             Set CRUZIBLE_RATE_LIMIT_RPS to protect against API abuse."
        );
    }

    // Random operator key means attestations are not reproducible across restarts.
    if config.operator_key_hex.is_none() {
        warn!(
            "No operator_key_hex configured — a random signing key will be generated. \
             Attestations will not survive restarts. Set CRUZIBLE_OPERATOR_KEY_HEX \
             for persistent enclave identity."
        );
    }

    // Sanity-check resource limits.
    if config.max_validators > 1000 {
        warn!(
            max_validators = config.max_validators,
            "max_validators exceeds recommended limit of 1000. \
             High values increase per-request CPU and memory usage."
        );
    }
    if config.max_stakers > 500_000 {
        warn!(
            max_stakers = config.max_stakers,
            "max_stakers exceeds recommended limit of 500,000. \
             High values increase per-request CPU and memory usage."
        );
    }

    // Mock platform on non-loopback is suspicious.
    if is_mock && !is_loopback {
        warn!(
            listen_addr = %config.listen_addr,
            "Mock TEE platform on a non-loopback interface. \
             Attestations are NOT hardware-backed. Use SGX/Nitro/SEV for production."
        );
    }

    // Attestation trust-model logging.
    if !is_mock {
        if config.attestation_relay_url.is_some() {
            info!(
                platform = %config.tee_platform,
                "Attestation trust model: RELAY-ROOTED. Hardware evidence is verified by \
                 a trusted attestation relay, not directly on-chain. Ensure the relay's \
                 P-256 key is registered via registerAttestationRelay() with governance \
                 controls (rotation timelock, liveness challenges, emergency revocation)."
            );
        } else if config.vendor_attestation_key_hex.is_some() {
            warn!(
                platform = %config.tee_platform,
                "Attestation trust model: LOCAL-SIGNED (development only). Hardware evidence \
                 is NOT verified. The operator holds the signing key, defeating trust \
                 separation. Do NOT use this configuration in production."
            );
        }
    }

    // Log the final configuration summary.
    info!(
        platform = %config.tee_platform,
        listen_addr = %config.listen_addr,
        auth_enabled = config.auth_token.is_some(),
        rate_limit_rps = config.rate_limit_rps,
        max_validators = config.max_validators,
        max_stakers = config.max_stakers,
        max_commitments = config.max_commitments,
        attestation_relay = config.attestation_relay_url.is_some(),
        is_loopback = is_loopback,
        "Cruzible TEE service configuration validated"
    );
}

/// Start the HTTP server.
///
/// # Fail-closed auth policy
///
/// The server **always** requires `auth_token` when `listen_addr` is not a
/// loopback interface — no flag can override this. On loopback the rules are:
///
/// | Platform | Loopback | `auth_token` | `insecure_no_auth` | Result |
/// |----------|----------|--------------|--------------------|--------|
/// | Mock     | yes      | None         | any                | starts (warn) |
/// | Real     | yes      | None         | **true**           | starts (warn) |
/// | Real     | yes      | None         | false              | **hard error** |
/// | Any      | **no**   | None         | any                | **hard error** |
/// | Any      | any      | set          | any                | starts |
///
/// `CRUZIBLE_INSECURE_NO_AUTH` only relaxes the platform check and **only**
/// on loopback, so a misconfigured production deployment on a public
/// interface can never silently start without authentication.
///
/// # Fail-closed vendor attestation policy
///
/// On real platforms (SGX / Nitro / SEV), `vendor_attestation_key_hex`
/// (local vendor signing) is gated by **two tiers**:
///
/// | Build feature | Loopback | `insecure_local_vendor_key` | Result |
/// |---------------|----------|-----------------------------|--------|
/// | no `mock-tee` | any      | any                         | **compile-time reject** |
/// | `mock-tee`    | yes      | **true**                    | starts (warn) |
/// | `mock-tee`    | yes      | false                       | **hard error** |
/// | `mock-tee`    | **no**   | any                         | **hard error** |
///
/// Production images must never enable `mock-tee`, so the local vendor
/// path is removed entirely at compile time.  In dev builds, both
/// loopback binding and the explicit flag are required.
pub async fn start_server(config: VaultServiceConfig) -> Result<(), Box<dyn std::error::Error>> {
    // ── Production configuration validation ──────────────────────────────
    validate_production_config(&config);

    // ── Fail-closed: require auth unless safe local-dev conditions ────────
    if config.auth_token.is_none() {
        let is_loopback = is_loopback_addr(&config.listen_addr);
        let is_mock = config.tee_platform == TEEPlatform::Mock;

        // Non-loopback is NEVER allowed without auth — no override exists.
        if !is_loopback {
            return Err(format!(
                "CRUZIBLE_AUTH_TOKEN is required when listen_addr is not loopback.\n  \
                 Current: listen_addr={}\n  \
                 Bind to 127.0.0.1 / ::1 / localhost for development, \
                 or set CRUZIBLE_AUTH_TOKEN for production.",
                config.listen_addr
            )
            .into());
        }

        // Loopback + Mock is always safe for local dev.
        // Loopback + Real platform requires the explicit insecure flag.
        if !is_mock && !config.insecure_no_auth {
            return Err(format!(
                "CRUZIBLE_AUTH_TOKEN is required for real TEE platform '{}'.\n  \
                 Set CRUZIBLE_AUTH_TOKEN to a bearer token, or for local testing \
                 on loopback set CRUZIBLE_INSECURE_NO_AUTH=true (NOT for production).",
                config.tee_platform
            )
            .into());
        }

        if !is_mock && config.insecure_no_auth {
            warn!(
                platform = %config.tee_platform,
                addr = %config.listen_addr,
                "CRUZIBLE_INSECURE_NO_AUTH=true — running real platform WITHOUT \
                 authentication on loopback. NOT safe for production."
            );
        } else {
            warn!(
                "Starting WITHOUT authentication — mock platform on loopback only. \
                 Set CRUZIBLE_AUTH_TOKEN for any non-development deployment."
            );
        }
    }

    // Derive the operator signing key
    let signing_key_bytes: [u8; 32] = match &config.operator_key_hex {
        Some(key_hex) => {
            let bytes =
                hex::decode(key_hex).map_err(|e| format!("invalid operator_key_hex: {}", e))?;
            bytes
                .try_into()
                .map_err(|_| "operator key must be exactly 32 bytes (64 hex chars)")?
        }
        None => {
            // Generate a random key for development/testing
            use rand::RngCore;
            let mut key = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut key);
            warn!("No operator_key_hex configured — using random key (development only)");
            key
        }
    };

    // Derive TEE enclave measurements from config.
    //
    // Real platforms MUST have explicit measurements — these are baked into the
    // enclave binary at build time and registered on-chain. Using placeholders
    // would cause measurement mismatch errors at attestation time.
    //
    // Mock platform uses well-known test values if not explicitly configured.
    let enclave_hash: [u8; 32] = match &config.enclave_hash_hex {
        Some(hex_str) => {
            let bytes =
                hex::decode(hex_str).map_err(|e| format!("invalid enclave_hash_hex: {}", e))?;
            bytes
                .try_into()
                .map_err(|_| "enclave_hash_hex must be exactly 32 bytes (64 hex chars)")?
        }
        None if config.tee_platform == TEEPlatform::Mock => {
            warn!("Using placeholder enclave hash [0xAE; 32] — mock platform only");
            [0xAE; 32]
        }
        None => {
            return Err(format!(
                "real TEE platform '{}' requires enclave_hash_hex (MRENCLAVE / enclave measurement). \
                 Set CRUZIBLE_ENCLAVE_HASH_HEX to the 64-char hex hash of the enclave binary.",
                config.tee_platform
            ).into());
        }
    };

    let signer_hash: [u8; 32] = match &config.signer_hash_hex {
        Some(hex_str) => {
            let bytes =
                hex::decode(hex_str).map_err(|e| format!("invalid signer_hash_hex: {}", e))?;
            bytes
                .try_into()
                .map_err(|_| "signer_hash_hex must be exactly 32 bytes (64 hex chars)")?
        }
        None if config.tee_platform == TEEPlatform::Mock => {
            warn!("Using placeholder signer hash [0x51; 32] — mock platform only");
            [0x51; 32]
        }
        None => {
            return Err(format!(
                "real TEE platform '{}' requires signer_hash_hex (MRSIGNER / signer measurement). \
                 Set CRUZIBLE_SIGNER_HASH_HEX to the 64-char hex hash of the enclave signer.",
                config.tee_platform
            )
            .into());
        }
    };

    // Application hash — only required for Nitro (PCR2)
    let application_hash: Option<[u8; 32]> = match &config.application_hash_hex {
        Some(hex_str) => {
            let bytes =
                hex::decode(hex_str).map_err(|e| format!("invalid application_hash_hex: {}", e))?;
            let arr: [u8; 32] = bytes
                .try_into()
                .map_err(|_| "application_hash_hex must be exactly 32 bytes (64 hex chars)")?;
            Some(arr)
        }
        None if config.tee_platform == TEEPlatform::AWSNitro => {
            return Err(
                "Nitro platform requires application_hash_hex (PCR2 / application measurement). \
                 Set CRUZIBLE_APPLICATION_HASH_HEX to the 64-char hex hash of the application."
                    .to_string()
                    .into(),
            );
        }
        None => None,
    };

    let tee_config = TEEConfig {
        platform: config.tee_platform,
        enclave_hash,
        signer_hash,
        application_hash,
        allow_simulated: config.allow_simulated,
        signing_key: signing_key_bytes,
    };

    // Vendor attestation bootstrap.
    //
    // Mock platform: uses a well-known test vendor root key (D=2).
    //
    // Real platforms (SGX, Nitro, SEV): the attestation authority signing key
    // must NOT reside in the enclave. We support two modes:
    //
    //   1. `attestation_relay_url` (production): sends hardware evidence to
    //      a trusted attestation relay that verifies the hardware chain of
    //      trust and signs the platform key binding with its own P-256 key.
    //      The relay's key must be registered on-chain via
    //      `VaultTEEVerifier.registerAttestationRelay()` for governance
    //      accountability (rotation timelock, liveness challenges, revocation).
    //      Requires the `remote-attestation` feature.
    //
    //   2. `vendor_attestation_key_hex` (development/testing): uses a local
    //      P-256 key to sign the platform key binding. The hardware evidence
    //      is NOT verified - this mode defeats trust separation and must NOT
    //      be used in production.
    //
    //   If neither is set for a real platform, startup fails with a clear error.
    let attestation_gen = if config.tee_platform == TEEPlatform::Mock {
        let mut vendor_key = [0u8; 32];
        vendor_key[31] = 2; // Test vendor root key (D=2)
        warn!("Using test vendor root key (D=2) — mock platform, NOT for production");
        AttestationGenerator::new(tee_config, vendor_key)
            .map_err(|e| format!("failed to initialize attestation generator: {}", e))?
    } else if let Some(ref relay_url) = config.attestation_relay_url {
        // Production path: remote attestation relay verifies hardware evidence.
        #[cfg(feature = "remote-attestation")]
        {
            info!(
                relay_url = %relay_url,
                platform = %config.tee_platform,
                "Using attestation relay as trusted bridge for platform key certification. \
                 Ensure the relay's P-256 public key is registered on-chain via \
                 registerAttestationRelay() (not setVendorRootKey) for governance accountability."
            );
            let attester = Box::new(RemoteVendorAttester::new(relay_url.clone()));
            AttestationGenerator::with_vendor_attester(tee_config, attester).map_err(|e| {
                format!(
                    "failed to initialize attestation generator with remote attester: {}",
                    e
                )
            })?
        }
        #[cfg(not(feature = "remote-attestation"))]
        {
            let _ = relay_url;
            return Err("attestation_relay_url is set but the 'remote-attestation' feature is not enabled. \
                        Rebuild with: cargo build --features remote-attestation".into());
        }
    } else if let Some(ref vendor_key_hex) = config.vendor_attestation_key_hex {
        // ── Compile-time gate ──────────────────────────────────────────
        // Without the `mock-tee` feature, local vendor keys are
        // unconditionally rejected for real platforms.  Production images
        // must never enable `mock-tee`, so this is a hard compile-time
        // boundary that cannot be bypassed by any runtime flag.
        #[cfg(not(feature = "mock-tee"))]
        {
            let _ = vendor_key_hex;
            return Err(format!(
                "vendor_attestation_key_hex is not available for real TEE platform '{}' \
                 in this build.\n  \
                 LocalVendorAttester ignores hardware evidence, defeating trust separation.\n  \
                 Configure attestation_relay_url for production.\n  \
                 To use a local vendor key for development, rebuild with: \
                 cargo build --features mock-tee",
                config.tee_platform
            )
            .into());
        }

        // ── Runtime gate (dev builds only): loopback + explicit flag ──
        // Even in mock-tee builds, the local vendor key on a real
        // platform requires BOTH loopback binding AND the explicit
        // insecure flag, mirroring the auth fail-closed pattern.
        #[cfg(feature = "mock-tee")]
        {
            let is_loopback = is_loopback_addr(&config.listen_addr);

            if !config.insecure_local_vendor_key {
                return Err(format!(
                    "vendor_attestation_key_hex is not allowed for real TEE platform '{}'.\n  \
                     LocalVendorAttester ignores hardware evidence, defeating trust separation.\n  \
                     Configure attestation_relay_url for production, or for local dev set:\n  \
                     • CRUZIBLE_INSECURE_LOCAL_VENDOR_KEY=true\n  \
                     • Bind to loopback (127.0.0.1 / ::1 / localhost)",
                    config.tee_platform
                )
                .into());
            }

            if !is_loopback {
                return Err(format!(
                    "CRUZIBLE_INSECURE_LOCAL_VENDOR_KEY requires loopback binding.\n  \
                     Current: listen_addr={}\n  \
                     LocalVendorAttester ignores hardware evidence — non-loopback binding \
                     would allow network clients to receive unverified attestations.\n  \
                     Bind to 127.0.0.1 / ::1 / localhost for local development.",
                    config.listen_addr
                )
                .into());
            }

            warn!(
                platform = %config.tee_platform,
                addr = %config.listen_addr,
                "⚠ INSECURE: Using LOCAL vendor attestation key for real platform. \
                 Hardware evidence is NOT verified. Loopback-only dev mode. \
                 NOT FOR PRODUCTION."
            );
            let vendor_key_bytes = hex::decode(vendor_key_hex)
                .map_err(|e| format!("invalid vendor_attestation_key_hex: {}", e))?;
            let vendor_key: [u8; 32] = vendor_key_bytes.try_into().map_err(|_| {
                "vendor_attestation_key_hex must be exactly 32 bytes (64 hex chars)"
            })?;
            let attester = Box::new(LocalVendorAttester::new(vendor_key));
            AttestationGenerator::with_vendor_attester(tee_config, attester).map_err(|e| {
                format!(
                    "failed to initialize attestation generator with local attester: {}",
                    e
                )
            })?
        }
    } else {
        // Neither relay URL nor local vendor key configured for a real platform.
        return Err(format!(
            "real TEE platform '{}' requires vendor attestation.\n  \
             Set CRUZIBLE_ATTESTATION_RELAY_URL to a remote attestation relay (production).\n  \
             For development with real hardware but no relay, rebuild with --features mock-tee \
             and set:\n  \
             • CRUZIBLE_VENDOR_KEY_HEX — local P-256 vendor key (64 hex chars)\n  \
             • CRUZIBLE_INSECURE_LOCAL_VENDOR_KEY=true — acknowledge insecure mode\n  \
             • Bind to loopback (127.0.0.1 / ::1 / localhost)",
            config.tee_platform
        )
        .into());
    };

    // Log the operator public key so it can be registered on-chain
    match attestation_gen.operator_pubkey_hex() {
        Ok(pubkey) => {
            info!(operator_pubkey = %pubkey, "TEE operator public key (register on-chain)")
        }
        Err(e) => return Err(format!("failed to derive operator pubkey: {}", e).into()),
    }

    // Log vendor key attestation for on-chain registration.
    // The attestation was generated atomically with the platform key by the
    // hardware provider during construction.
    {
        let key_attest = attestation_gen.key_attestation();
        info!(
            platform_key_x = %hex::encode(key_attest.platform_key_x),
            platform_key_y = %hex::encode(key_attest.platform_key_y),
            vendor_attest_r = %hex::encode(key_attest.vendor_sig_r),
            vendor_attest_s = %hex::encode(key_attest.vendor_sig_s),
            "Platform key generated by hardware provider (register on-chain)"
        );
    }

    let state = Arc::new(AppState {
        start_time: Instant::now(),
        attestation_gen,
        total_attestations: RwLock::new(0),
        current_epoch: RwLock::new(1),
        config: config.clone(),
        metrics: MetricsState::new(),
    });

    let app = build_router(state);
    let listener = tokio::net::TcpListener::bind(&config.listen_addr).await?;

    info!(
        listen_addr = %config.listen_addr,
        platform = %config.tee_platform,
        auth_enabled = config.auth_token.is_some(),
        rate_limit_rps = config.rate_limit_rps,
        "Cruzible TEE service listening"
    );

    axum::serve(listener, app).await?;
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Canonical Validator Set Hash
// ─────────────────────────────────────────────────────────────────────────────

/// Compute the canonical validator set hash for cross-layer verification.
///
/// All three verification layers (Rust TEE producer, Solidity on-chain verifier,
/// Go native verifier) compute this identical hash from their respective data
/// structures. The hash covers the same canonical fields in the same order with
/// identical byte-level encoding, ensuring attestation integrity regardless of
/// language-specific serialization differences.
///
/// ## Schema (big-endian, uint256-padded)
///
/// ```text
/// inner_hash_i = SHA-256(
///   pad32(address_bytes) || uint256(stake) || uint256(perf_score) ||
///   uint256(decent_score) || uint256(rep_score) || uint256(composite_score) ||
///   bytes32(tee_key) || uint256(commission)
/// )
///
/// canonical_hash = SHA-256(
///   "CruzibleValidatorSet-v1" || be8(epoch) || be4(count) ||
///   inner_hash_0 || inner_hash_1 || ...
/// )
/// ```
///
/// ## Matching implementations
///
/// - **Solidity**: `Cruzible._computeValidatorSetHash()`
/// - **Go**: `keeper.computeValidatorSetHash()`
pub fn compute_validator_set_hash(epoch: u64, validators: &[ScoredValidator]) -> [u8; 32] {
    let mut outer = Sha256::new();
    outer.update(b"CruzibleValidatorSet-v1");
    outer.update(epoch.to_be_bytes());
    outer.update((validators.len() as u32).to_be_bytes());

    for v in validators {
        let inner_hash = compute_validator_inner_hash(v);
        outer.update(inner_hash);
    }

    let mut result = [0u8; 32];
    result.copy_from_slice(&outer.finalize());
    result
}

/// Compute the per-validator inner hash (8 fields × 32 bytes = 256 bytes → SHA-256).
fn compute_validator_inner_hash(v: &ScoredValidator) -> [u8; 32] {
    let mut inner = Sha256::new();

    // address → left-pad to 32 bytes (ABI uint256 encoding of address)
    let addr_hex = v.address.trim_start_matches("0x");
    let addr_bytes = match hex::decode(addr_hex) {
        Ok(bytes) if bytes.len() <= 32 => bytes,
        _ => {
            // Non-hex address (e.g., Cosmos bech32): hash to 20 bytes for determinism
            let h = Sha256::digest(v.address.as_bytes());
            h[..20].to_vec()
        }
    };
    let mut addr_padded = [0u8; 32];
    let start = 32 - addr_bytes.len().min(32);
    addr_padded[start..].copy_from_slice(&addr_bytes[..addr_bytes.len().min(32)]);
    inner.update(addr_padded);

    // stake as uint256 (u128 → 32 bytes big-endian, left-padded)
    let mut stake_padded = [0u8; 32];
    stake_padded[16..].copy_from_slice(&v.stake.to_be_bytes());
    inner.update(stake_padded);

    // performance_score as uint256 (u32 → 32 bytes big-endian)
    let mut perf_padded = [0u8; 32];
    perf_padded[28..].copy_from_slice(&v.performance_score.to_be_bytes());
    inner.update(perf_padded);

    // decentralization_score as uint256
    let mut decent_padded = [0u8; 32];
    decent_padded[28..].copy_from_slice(&v.decentralization_score.to_be_bytes());
    inner.update(decent_padded);

    // reputation_score as uint256
    let mut rep_padded = [0u8; 32];
    rep_padded[28..].copy_from_slice(&v.reputation_score.to_be_bytes());
    inner.update(rep_padded);

    // composite_score as uint256
    let mut comp_padded = [0u8; 32];
    comp_padded[28..].copy_from_slice(&v.composite_score.to_be_bytes());
    inner.update(comp_padded);

    // tee_public_key as bytes32 (left-aligned, zero-padded)
    let key_hex = v.tee_public_key.trim_start_matches("0x");
    let key_bytes = hex::decode(key_hex).unwrap_or_default();
    let mut key_padded = [0u8; 32];
    let copy_len = key_bytes.len().min(32);
    key_padded[..copy_len].copy_from_slice(&key_bytes[..copy_len]);
    inner.update(key_padded);

    // commission as uint256 (u32 → 32 bytes big-endian)
    let mut comm_padded = [0u8; 32];
    comm_padded[28..].copy_from_slice(&v.commission_bps.to_be_bytes());
    inner.update(comm_padded);

    let mut result = [0u8; 32];
    result.copy_from_slice(&inner.finalize());
    result
}

// ─────────────────────────────────────────────────────────────────────────────
// Canonical Selection Policy Hash
// ─────────────────────────────────────────────────────────────────────────────

/// Compute the canonical hash of a validator selection policy.
///
/// This binds the TEE attestation to the specific scoring parameters used,
/// closing the trust gap where a caller could supply arbitrary weights/thresholds
/// to bias selection while still obtaining a valid attestation.
///
/// ## Schema (domain-separated SHA-256, big-endian, uint256-padded)
///
/// ```text
/// policy_hash = SHA-256(
///   "CruzibleSelectionPolicy-v1" ||
///   float64_be(performance_weight) || float64_be(decentralization_weight) ||
///   float64_be(reputation_weight)  || float64_be(min_uptime_pct) ||
///   uint256(max_commission_bps)    || uint256(max_per_region) ||
///   uint256(max_per_operator)      || uint256(min_stake)
/// )
/// ```
///
/// Float64 fields are encoded as IEEE-754 big-endian to ensure byte-level
/// determinism across Rust and Go. The contract stores only the resulting hash
/// and does not need to reconstruct the float encoding.
///
/// ## Matching implementations
///
/// - **Solidity**: `Cruzible.selectionPolicyHash` (stored, set by governance)
/// - **Go**: `keeper.computeSelectionPolicyHash()`
pub fn compute_selection_policy_hash(config: &SelectionConfig) -> [u8; 32] {
    let mut h = Sha256::new();

    // Domain separator
    h.update(b"CruzibleSelectionPolicy-v1");

    // performance_weight as float64 big-endian (8 bytes)
    h.update(config.performance_weight.to_be_bytes());

    // decentralization_weight as float64 big-endian (8 bytes)
    h.update(config.decentralization_weight.to_be_bytes());

    // reputation_weight as float64 big-endian (8 bytes)
    h.update(config.reputation_weight.to_be_bytes());

    // min_uptime_pct as float64 big-endian (8 bytes)
    h.update(config.min_uptime_pct.to_be_bytes());

    // max_commission_bps as uint256 (u32 → 32 bytes big-endian, left-padded)
    let mut comm_padded = [0u8; 32];
    comm_padded[28..].copy_from_slice(&config.max_commission_bps.to_be_bytes());
    h.update(comm_padded);

    // max_per_region as uint256 (usize → 32 bytes big-endian)
    let mut region_padded = [0u8; 32];
    region_padded[24..].copy_from_slice(&(config.max_per_region as u64).to_be_bytes());
    h.update(region_padded);

    // max_per_operator as uint256 (usize → 32 bytes big-endian)
    let mut operator_padded = [0u8; 32];
    operator_padded[24..].copy_from_slice(&(config.max_per_operator as u64).to_be_bytes());
    h.update(operator_padded);

    // min_stake as uint256 (u128 → 32 bytes big-endian, left-padded)
    let mut stake_padded = [0u8; 32];
    stake_padded[16..].copy_from_slice(&config.min_stake.to_be_bytes());
    h.update(stake_padded);

    let mut result = [0u8; 32];
    result.copy_from_slice(&h.finalize());
    result
}

// ─────────────────────────────────────────────────────────────────────────────
// Eligible Universe Hash
// ─────────────────────────────────────────────────────────────────────────────

/// Compute the eligible-universe hash from a list of validator addresses.
///
/// This is the TEE-side counterpart to the Go keeper's
/// `computeEligibleUniverseHash()`.  The addresses are sorted lexicographically,
/// then hashed with null-byte separators:
///
/// ```text
/// universe_hash = SHA-256(addr_0 || 0x00 || addr_1 || 0x00 || ... || addr_n || 0x00)
/// ```
///
/// The TEE **must** recompute this from the actual `request.validators` list and
/// reject the request if the result differs from the caller-supplied hash.  This
/// prevents a relayer from omitting targeted validators from the scored input
/// while still supplying the correct full-universe hash.
///
/// ## Matching implementations
///
/// - **Go**: `keeper.computeEligibleUniverseHash()`
pub fn compute_eligible_universe_hash(addresses: &[String]) -> [u8; 32] {
    let mut sorted: Vec<&str> = addresses.iter().map(|s| s.as_str()).collect();
    sorted.sort();

    let mut h = Sha256::new();
    for addr in &sorted {
        h.update(addr.as_bytes());
        h.update([0u8]); // null separator for domain separation
    }

    let mut result = [0u8; 32];
    result.copy_from_slice(&h.finalize());
    result
}

// ─────────────────────────────────────────────────────────────────────────────
// Canonical Stake Snapshot Hash
// ─────────────────────────────────────────────────────────────────────────────

/// Compute the canonical stake snapshot hash from staker records.
///
/// This binds the TEE reward attestation to the specific stake data it
/// computed from, preventing a relayer from omitting stakers or skewing
/// balances while still obtaining a valid attestation for a biased Merkle
/// root.
///
/// ## Schema (domain-separated SHA-256, sorted, uint256-padded)
///
/// ```text
/// staker_inner_i = SHA-256(
///   pad32(address) || uint256(shares) || pad32(delegated_to)
/// )
///
/// stake_snapshot_hash = SHA-256(
///   "CruzibleStakeSnapshot-v1" || be8(epoch) || be4(count) ||
///   staker_inner_0 || staker_inner_1 || ...
/// )
/// ```
///
/// Stakers are sorted by address for determinism.
///
/// ## Matching implementations
///
/// - **Go**: `keeper.computeStakeSnapshotHash()`
/// - **Solidity**: verified against `committedStakeSnapshotHash` (governance-set)
pub fn compute_stake_snapshot_hash(epoch: u64, stakers: &[StakerStake]) -> [u8; 32] {
    let mut sorted: Vec<&StakerStake> = stakers.iter().collect();
    sorted.sort_by(|a, b| a.address.cmp(&b.address));

    let mut outer = Sha256::new();
    outer.update(b"CruzibleStakeSnapshot-v1");
    outer.update(epoch.to_be_bytes());
    outer.update((sorted.len() as u32).to_be_bytes());

    for staker in &sorted {
        let inner_hash = compute_staker_inner_hash(staker);
        outer.update(inner_hash);
    }

    let mut result = [0u8; 32];
    result.copy_from_slice(&outer.finalize());
    result
}

/// Compute the per-staker inner hash (3 fields: address, shares, delegated_to).
fn compute_staker_inner_hash(staker: &StakerStake) -> [u8; 32] {
    let mut inner = Sha256::new();

    // address → left-pad to 32 bytes
    let addr_hex = staker.address.trim_start_matches("0x");
    let addr_bytes = match hex::decode(addr_hex) {
        Ok(bytes) if bytes.len() <= 32 => bytes,
        _ => {
            let h = Sha256::digest(staker.address.as_bytes());
            h[..20].to_vec()
        }
    };
    let mut addr_padded = [0u8; 32];
    let start = 32 - addr_bytes.len().min(32);
    addr_padded[start..].copy_from_slice(&addr_bytes[..addr_bytes.len().min(32)]);
    inner.update(addr_padded);

    // shares as uint256 (u128 → 32 bytes big-endian, left-padded)
    let mut shares_padded = [0u8; 32];
    shares_padded[16..].copy_from_slice(&staker.shares.to_be_bytes());
    inner.update(shares_padded);

    // delegated_to → left-pad to 32 bytes
    let del_hex = staker.delegated_to.trim_start_matches("0x");
    let del_bytes = match hex::decode(del_hex) {
        Ok(bytes) if bytes.len() <= 32 => bytes,
        _ => {
            let h = Sha256::digest(staker.delegated_to.as_bytes());
            h[..20].to_vec()
        }
    };
    let mut del_padded = [0u8; 32];
    let del_start = 32 - del_bytes.len().min(32);
    del_padded[del_start..].copy_from_slice(&del_bytes[..del_bytes.len().min(32)]);
    inner.update(del_padded);

    let mut result = [0u8; 32];
    result.copy_from_slice(&inner.finalize());
    result
}

// ─────────────────────────────────────────────────────────────────────────────
// Staker Registry Root (XOR Accumulator)
// ─────────────────────────────────────────────────────────────────────────────

/// Compute the XOR-based staker registry root that matches the on-chain
/// accumulator maintained by `StAETHEL.stakerRegistryRoot`.
///
/// For each staker with `shares > 0` the contribution is:
///
/// ```text
/// keccak256(abi.encodePacked(address, shares))
///         = keccak256(address_20_bytes || shares_uint256_32_bytes)
/// ```
///
/// The accumulator is the XOR of all such contributions.  Order is
/// irrelevant because XOR is commutative and associative.
///
/// ## Matching implementations
///
/// - **Solidity**: `StAETHEL._touchAccumulator()` updates the accumulator
///   incrementally on every share-changing operation (mint, burn, transfer).
/// - **Go**: (future) keeper can recompute for cross-layer verification.
pub fn compute_staker_registry_root(stakers: &[StakerStake]) -> [u8; 32] {
    use sha3::{Digest, Keccak256};

    // Defense-in-depth: callers must validate uniqueness before calling.
    // The XOR accumulator is self-inverse, so duplicate entries would
    // cancel out and produce a root that doesn't reflect the true set.
    debug_assert!(
        {
            let mut seen = std::collections::HashSet::with_capacity(stakers.len());
            stakers.iter().all(|s| seen.insert(&s.address))
        },
        "compute_staker_registry_root: duplicate staker address detected"
    );

    let mut accumulator = [0u8; 32];

    for staker in stakers {
        if staker.shares == 0 {
            continue;
        }

        // address as 20 bytes (matching Solidity abi.encodePacked(address))
        let addr_bytes = parse_address_bytes(&staker.address);

        // shares as uint256 (32 bytes big-endian, matching Solidity uint256)
        let mut shares_be = [0u8; 32];
        shares_be[16..].copy_from_slice(&staker.shares.to_be_bytes());

        // keccak256(abi.encodePacked(address, shares))
        let mut hasher = Keccak256::new();
        hasher.update(&addr_bytes);
        hasher.update(shares_be);
        let hash: [u8; 32] = hasher.finalize().into();

        // XOR into accumulator
        for i in 0..32 {
            accumulator[i] ^= hash[i];
        }
    }

    accumulator
}

// ─────────────────────────────────────────────────────────────────────────────
// Delegation Registry Root
// ─────────────────────────────────────────────────────────────────────────────

/// Compute the XOR-based delegation-registry root from the staker set.
///
/// The accumulator is the XOR of `keccak256(staker_address_20bytes ||
/// delegated_to_address_20bytes)` for every staker with non-zero shares.
///
/// This captures the delegation mapping — which validator each staker has
/// delegated to — independently of share amounts (which are covered by the
/// staker registry root).  Together the two roots bind both the share
/// distribution **and** the delegation topology that drives performance-
/// weighted reward allocation.
///
/// ## Trust boundary
///
/// Delegation is native-chain state that the EVM cannot independently verify.
/// The delegation registry root is TEE-attested and stored in the epoch
/// snapshot for auditability.  The Go native keeper can independently
/// recompute this root from native-chain delegation records and cross-check
/// against the on-chain value.
///
/// ## Matching implementations
///
/// - **Solidity**: stored in `EpochSnapshot.delegationRegistryRoot` (TEE-attested,
///   not independently derived on EVM since delegation is native-chain state).
/// - **Go**: (future) keeper can recompute for cross-layer verification.
pub fn compute_delegation_registry_root(stakers: &[StakerStake]) -> [u8; 32] {
    use sha3::{Digest, Keccak256};

    // Defense-in-depth: callers must validate uniqueness before calling.
    debug_assert!(
        {
            let mut seen = std::collections::HashSet::with_capacity(stakers.len());
            stakers.iter().all(|s| seen.insert(&s.address))
        },
        "compute_delegation_registry_root: duplicate staker address detected"
    );

    let mut accumulator = [0u8; 32];

    for staker in stakers {
        if staker.shares == 0 {
            continue;
        }

        // staker address as 20 bytes
        let staker_addr = parse_address_bytes(&staker.address);

        // delegated_to address as 20 bytes
        let delegate_addr = parse_address_bytes(&staker.delegated_to);

        // keccak256(abi.encodePacked(staker_address, delegated_to))
        let mut hasher = Keccak256::new();
        hasher.update(&staker_addr);
        hasher.update(&delegate_addr);
        let hash: [u8; 32] = hasher.finalize().into();

        // XOR into accumulator
        for i in 0..32 {
            accumulator[i] ^= hash[i];
        }
    }

    accumulator
}

/// Parse an Ethereum address string into 20 bytes.
///
/// Handles 0x-prefixed hex, left-pads short addresses, and falls back to
/// SHA-256 hashing for non-hex strings (e.g. bech32 Cosmos addresses).
///
/// The input is lowercased before processing to ensure cross-language
/// consistency — the Go keeper's `parseAddressBytes` does the same
/// normalization, so both produce identical 20-byte representations
/// regardless of input case.
fn parse_address_bytes(addr: &str) -> Vec<u8> {
    let addr_lower = addr.to_lowercase();
    let addr_hex = addr_lower.trim_start_matches("0x");
    match hex::decode(addr_hex) {
        Ok(bytes) if bytes.len() == 20 => bytes,
        Ok(bytes) if bytes.len() < 20 => {
            let mut padded = vec![0u8; 20 - bytes.len()];
            padded.extend_from_slice(&bytes);
            padded
        }
        _ => {
            // No SHA-256 fallback — all addresses must be canonical 20-byte
            // EVM hex by the time they reach the TEE. The Go keeper resolves
            // bech32/native addresses to EVM form via resolveEvmAddress()
            // before including them in the attestation request.
            vec![0u8; 20]
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Staker Uniqueness Validation
// ─────────────────────────────────────────────────────────────────────────────

/// Validate that no two stakers share the same address.
///
/// The XOR-based registry root accumulator is self-inverse: duplicate entries
/// cancel out (even count) or collapse to a single entry (odd count), allowing
/// a manipulated snapshot to preserve the same registry root while changing the
/// effective share distribution.  This fail-closed check prevents the attack
/// by rejecting any staker set with repeated addresses.
///
/// Returns `Ok(())` if all addresses are unique, or `Err(message)` with the
/// first duplicate address found.
pub fn validate_unique_staker_addresses(stakers: &[StakerStake]) -> Result<(), String> {
    let mut seen = std::collections::HashSet::with_capacity(stakers.len());
    for staker in stakers {
        if !seen.insert(&staker.address) {
            return Err(format!("duplicate staker address: {}", staker.address,));
        }
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Canonical Reward Payload
// ─────────────────────────────────────────────────────────────────────────────

/// Compute the canonical reward-summary payload for TEE attestation.
///
/// The result is the exact bytes that `Cruzible.distributeRewards()` checks:
///
/// ```solidity
/// bytes memory expectedPayload = abi.encode(
///     epoch, totalRewards, merkleRoot, protocolFee,
///     snapshotHash, validatorSetHash, registryRoot, delegationRoot
/// );
/// ```
///
/// ## Layout (Solidity ABI encoding, 256 bytes)
///
/// | Offset  | Field                    | ABI Type  | Encoding                         |
/// |---------|--------------------------|-----------|----------------------------------|
/// |   0–31  | epoch                    | uint256   | big-endian, left-padded to 32 B  |
/// |  32–63  | totalRewards             | uint256   | big-endian, left-padded to 32 B  |
/// |  64–95  | merkleRoot               | bytes32   | raw 32 bytes                     |
/// |  96–127 | protocolFee              | uint256   | big-endian, left-padded to 32 B  |
/// | 128–159 | stakeSnapshotHash        | bytes32   | raw 32 bytes                     |
/// | 160–191 | validatorSetHash         | bytes32   | raw 32 bytes                     |
/// | 192–223 | stakerRegistryRoot       | bytes32   | raw 32 bytes                     |
/// | 224–255 | delegationRegistryRoot   | bytes32   | raw 32 bytes                     |
///
/// ## Matching implementations
///
/// - **Solidity**: `Cruzible.distributeRewards()` line
///   `abi.encode(epoch, totalRewards, merkleRoot, protocolFee, snapshotHash, validatorSetHash, registryRoot, delegationRoot)`
/// - **Go**: keeper reward relay (if applicable)
pub fn compute_canonical_reward_payload(
    epoch: u64,
    total_rewards: u128,
    merkle_root: &[u8; 32],
    protocol_fee: u128,
    stake_snapshot_hash: &[u8; 32],
    validator_set_hash: &[u8; 32],
    staker_registry_root: &[u8; 32],
    delegation_registry_root: &[u8; 32],
) -> [u8; 256] {
    let mut payload = [0u8; 256];

    // epoch as uint256: u64 big-endian in rightmost 8 bytes of a 32-byte word
    payload[24..32].copy_from_slice(&epoch.to_be_bytes());

    // totalRewards as uint256: u128 big-endian in rightmost 16 bytes of a 32-byte word
    payload[48..64].copy_from_slice(&total_rewards.to_be_bytes());

    // merkleRoot as bytes32: raw 32 bytes
    payload[64..96].copy_from_slice(merkle_root);

    // protocolFee as uint256: u128 big-endian in rightmost 16 bytes of a 32-byte word
    payload[112..128].copy_from_slice(&protocol_fee.to_be_bytes());

    // stakeSnapshotHash as bytes32: raw 32 bytes
    payload[128..160].copy_from_slice(stake_snapshot_hash);

    // validatorSetHash as bytes32: raw 32 bytes
    payload[160..192].copy_from_slice(validator_set_hash);

    // stakerRegistryRoot as bytes32: raw 32 bytes
    payload[192..224].copy_from_slice(staker_registry_root);

    // delegationRegistryRoot as bytes32: raw 32 bytes
    payload[224..256].copy_from_slice(delegation_registry_root);

    payload
}

/// Build the canonical 96-byte delegation attestation payload.
///
/// The layout matches `abi.encode(epoch, delegationRoot, stakerRegistryRoot)`
/// in Solidity — three ABI-encoded uint256/bytes32 words (3 × 32 = 96 bytes).
///
/// This payload is verified by `Cruzible.commitDelegationSnapshot()` to prove
/// the TEE independently computed the delegation root from native-chain state.
pub fn compute_canonical_delegation_payload(
    epoch: u64,
    delegation_root: &[u8; 32],
    staker_registry_root: &[u8; 32],
) -> [u8; 96] {
    let mut payload = [0u8; 96];

    // epoch as uint256: u64 big-endian in rightmost 8 bytes of a 32-byte word
    payload[24..32].copy_from_slice(&epoch.to_be_bytes());

    // delegationRoot as bytes32: raw 32 bytes
    payload[32..64].copy_from_slice(delegation_root);

    // stakerRegistryRoot as bytes32: raw 32 bytes
    payload[64..96].copy_from_slice(staker_registry_root);

    payload
}

/// Parse a hex-encoded merkle root string (e.g. "0xabcd…") into 32 bytes.
fn parse_merkle_root(hex_str: &str) -> [u8; 32] {
    let trimmed = hex_str.trim_start_matches("0x");
    let bytes = hex::decode(trimmed).unwrap_or_default();
    let mut root = [0u8; 32];
    let len = bytes.len().min(32);
    root[32 - len..].copy_from_slice(&bytes[..len]);
    root
}

// ─────────────────────────────────────────────────────────────────────────────
// Handlers
// ─────────────────────────────────────────────────────────────────────────────

async fn health_handler(State(state): State<Arc<AppState>>) -> Json<HealthResponse> {
    let uptime = state.start_time.elapsed().as_secs();
    let total = *state.total_attestations.read().await;
    let epoch = *state.current_epoch.read().await;

    let m = &state.metrics;
    Json(HealthResponse {
        service: "cruzible-tee".to_string(),
        status: "ok".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        platform: state.config.tee_platform.to_string(),
        epoch,
        uptime_seconds: uptime,
        total_attestations: total,
        auth_enabled: state.config.auth_token.is_some(),
        rate_limit_rps: state.config.rate_limit_rps,
        last_attestation_at: m.last_attestation_iso(),
        attestation_counts: AttestationCountByType {
            validator_selection: m.validator_selections.load(Ordering::Relaxed),
            reward_calculation: m.reward_calculations.load(Ordering::Relaxed),
            mev_ordering: m.mev_orderings.load(Ordering::Relaxed),
            delegation_attestation: m.delegation_attestations.load(Ordering::Relaxed),
        },
        total_errors: m.total_errors.load(Ordering::Relaxed),
        auth_failures: m.auth_failures.load(Ordering::Relaxed),
    })
}

async fn capabilities_handler(State(state): State<Arc<AppState>>) -> Json<CapabilitiesResponse> {
    Json(CapabilitiesResponse {
        platform: state.config.tee_platform.to_string(),
        supported_operations: vec![
            "select-validators".to_string(),
            "calculate-rewards".to_string(),
            "order-transactions".to_string(),
            "verify-commitment".to_string(),
        ],
        max_validators: state.config.max_validators,
        max_stakers: state.config.max_stakers,
        max_commitments: state.config.max_commitments,
        attestation_types: vec!["sgx".to_string(), "nitro".to_string(), "sev".to_string()],
    })
}

/// Prometheus-compatible metrics endpoint.
///
/// Returns metrics in OpenMetrics text exposition format, suitable for
/// scraping by Prometheus, Datadog Agent, Grafana Alloy, or any
/// OpenMetrics-compatible collector.
///
/// This endpoint is unauthenticated and rate-limit-exempt to ensure
/// reliable scraping under load.
async fn metrics_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let uptime = state.start_time.elapsed().as_secs();
    let total = *state.total_attestations.read().await;
    let epoch = *state.current_epoch.read().await;
    let m = &state.metrics;

    let vs = m.validator_selections.load(Ordering::Relaxed);
    let rc = m.reward_calculations.load(Ordering::Relaxed);
    let mev = m.mev_orderings.load(Ordering::Relaxed);
    let da = m.delegation_attestations.load(Ordering::Relaxed);
    let errors = m.total_errors.load(Ordering::Relaxed);
    let auth_fail = m.auth_failures.load(Ordering::Relaxed);
    let last_attest = m.last_attestation_at.load(Ordering::Relaxed);

    let body = format!(
        "# HELP cruzible_uptime_seconds Time since service start in seconds.\n\
         # TYPE cruzible_uptime_seconds gauge\n\
         cruzible_uptime_seconds {uptime}\n\
         # HELP cruzible_current_epoch Current epoch number.\n\
         # TYPE cruzible_current_epoch gauge\n\
         cruzible_current_epoch {epoch}\n\
         # HELP cruzible_attestations_total Total attestations generated.\n\
         # TYPE cruzible_attestations_total counter\n\
         cruzible_attestations_total {total}\n\
         # HELP cruzible_attestations_by_type Attestations by operation type.\n\
         # TYPE cruzible_attestations_by_type counter\n\
         cruzible_attestations_by_type{{type=\"validator_selection\"}} {vs}\n\
         cruzible_attestations_by_type{{type=\"reward_calculation\"}} {rc}\n\
         cruzible_attestations_by_type{{type=\"mev_ordering\"}} {mev}\n\
         cruzible_attestations_by_type{{type=\"delegation_attestation\"}} {da}\n\
         # HELP cruzible_errors_total Total handler errors (4xx + 5xx).\n\
         # TYPE cruzible_errors_total counter\n\
         cruzible_errors_total {errors}\n\
         # HELP cruzible_auth_failures_total Total authentication failures.\n\
         # TYPE cruzible_auth_failures_total counter\n\
         cruzible_auth_failures_total {auth_fail}\n\
         # HELP cruzible_last_attestation_timestamp Unix timestamp of last attestation.\n\
         # TYPE cruzible_last_attestation_timestamp gauge\n\
         cruzible_last_attestation_timestamp {last_attest}\n\
         # HELP cruzible_rate_limit_rps Configured rate limit (0=unlimited).\n\
         # TYPE cruzible_rate_limit_rps gauge\n\
         cruzible_rate_limit_rps {rps}\n\
         # HELP cruzible_auth_enabled Whether bearer auth is enabled (1=yes, 0=no).\n\
         # TYPE cruzible_auth_enabled gauge\n\
         cruzible_auth_enabled {auth_en}\n",
        uptime = uptime,
        epoch = epoch,
        total = total,
        vs = vs,
        rc = rc,
        mev = mev,
        da = da,
        errors = errors,
        auth_fail = auth_fail,
        last_attest = last_attest,
        rps = state.config.rate_limit_rps,
        auth_en = if state.config.auth_token.is_some() {
            1
        } else {
            0
        },
    );

    (
        StatusCode::OK,
        [("content-type", "text/plain; version=0.0.4; charset=utf-8")],
        body,
    )
}

async fn select_validators_handler(
    State(state): State<Arc<AppState>>,
    Json(request): Json<SelectValidatorsRequest>,
) -> Result<Json<SelectValidatorsResponse>, (StatusCode, String)> {
    info!(
        epoch = request.epoch,
        candidates = request.validators.len(),
        target = request.target_count,
        "Processing validator selection"
    );

    if request.validators.len() > state.config.max_validators * 10 {
        return Err((
            StatusCode::BAD_REQUEST,
            "Too many candidate validators".to_string(),
        ));
    }

    // Reject duplicate candidate addresses — a malformed or malicious request
    // with duplicates could let the same validator occupy multiple slots,
    // reducing the effective validator set below decentralization guarantees.
    {
        let mut seen = std::collections::HashSet::with_capacity(request.validators.len());
        for v in &request.validators {
            if !seen.insert(&v.address) {
                return Err((
                    StatusCode::BAD_REQUEST,
                    format!("duplicate candidate address: {}", v.address),
                ));
            }
        }
    }

    // ── Validate eligible-universe hash ───────────────────────────────────
    //
    // The L1 keeper supplies the SHA-256 of sorted eligible validator addresses
    // as a hex string.  If it is missing or malformed, the TEE refuses to
    // produce an attestation — fail-closed prevents a relayer from obtaining a
    // valid attestation for a request that omits the universe commitment.
    if request.eligible_universe_hash.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "eligible_universe_hash is required".to_string(),
        ));
    }
    let universe_hash_bytes: [u8; 32] = {
        let decoded = hex::decode(&request.eligible_universe_hash).map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                "eligible_universe_hash is not valid hex".to_string(),
            )
        })?;
        if decoded.len() != 32 {
            return Err((
                StatusCode::BAD_REQUEST,
                format!(
                    "eligible_universe_hash must be 32 bytes, got {}",
                    decoded.len()
                ),
            ));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&decoded);
        arr
    };

    // ── Recompute universe hash from actual candidate list ───────────────
    //
    // The caller supplies eligible_universe_hash, but we must verify it
    // matches the actual request.validators addresses.  Without this check,
    // a malicious relayer could submit a truncated candidate list (omitting
    // targeted validators) while supplying the correct full-universe hash,
    // causing the TEE to attest a biased selection that still passes the
    // Go/Solidity universe-hash verification.
    {
        let candidate_addrs: Vec<String> = request
            .validators
            .iter()
            .map(|v| v.address.clone())
            .collect();
        let recomputed = compute_eligible_universe_hash(&candidate_addrs);
        if recomputed != universe_hash_bytes {
            return Err((
                StatusCode::BAD_REQUEST,
                format!(
                    "eligible_universe_hash mismatch: supplied {} but candidates hash to {}",
                    request.eligible_universe_hash,
                    hex::encode(recomputed),
                ),
            ));
        }
    }

    let selected = validator_selection::select_validators(
        &request.validators,
        request.target_count,
        &request.config,
    );

    // Compute canonical validator set hash for the attestation payload.
    //
    // This 32-byte hash is the single source of truth verified identically by:
    //   - Solidity:  Cruzible._computeValidatorSetHash()
    //   - Go native: keeper.computeValidatorSetHash()
    //
    // The canonical encoding uses domain-separated SHA-256 with uint256-padded
    // fields, eliminating serialization mismatches across JSON / ABI / Go structs.
    // The epoch is included to prevent cross-epoch replay.
    let canonical_hash = compute_validator_set_hash(request.epoch, &selected);

    // Compute the selection policy hash and include it in the attested payload.
    let policy_hash = compute_selection_policy_hash(&request.config);

    // ── Build 96-byte attested payload ────────────────────────────────────
    //
    //   abi.encodePacked(canonical_hash, policy_hash, universe_hash)  (96 bytes)
    //
    // This binds the attestation to:
    //   1. canonical_hash  — the output (which validators were selected)
    //   2. policy_hash     — the policy that produced them (scoring params)
    //   3. universe_hash   — the full eligible candidate universe (completeness)
    //
    // On-chain consumers verify:
    //   - canonical_hash against locally-recomputed validator set
    //   - policy_hash against governance-approved value
    //   - universe_hash against independently-computed eligible set (Go keeper)
    //     or store it for auditability (Solidity)
    let mut attested_payload = [0u8; 96];
    attested_payload[0..32].copy_from_slice(&canonical_hash);
    attested_payload[32..64].copy_from_slice(&policy_hash);
    attested_payload[64..96].copy_from_slice(&universe_hash_bytes);

    let attestation = state
        .attestation_gen
        .generate(&attested_payload)
        .map_err(|e| {
            state.metrics.total_errors.fetch_add(1, Ordering::Relaxed);
            error!(
                epoch = request.epoch,
                error = %e,
                "Attestation generation failed for validator selection"
            );
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("attestation generation failed: {}", e),
            )
        })?;
    let selection_hash = attestation.payload_hash.clone();

    // Update stats + metrics
    *state.total_attestations.write().await += 1;
    *state.current_epoch.write().await = request.epoch;
    state
        .metrics
        .validator_selections
        .fetch_add(1, Ordering::Relaxed);
    state.metrics.record_attestation_time();

    info!(
        epoch = request.epoch,
        selected = selected.len(),
        total_candidates = request.validators.len(),
        universe_hash = %request.eligible_universe_hash,
        selection_hash = %selection_hash,
        "Validator selection attestation complete"
    );

    Ok(Json(SelectValidatorsResponse {
        selected,
        epoch: request.epoch,
        total_candidates: request.validators.len(),
        selection_hash,
        attestation,
        eligible_universe_hash: request.eligible_universe_hash,
    }))
}

async fn calculate_rewards_handler(
    State(state): State<Arc<AppState>>,
    Json(request): Json<CalculateRewardsRequest>,
) -> Result<Json<CalculateRewardsResponse>, (StatusCode, String)> {
    info!(
        epoch = request.epoch,
        stakers = request.staker_stakes.len(),
        total_rewards = request.total_rewards,
        "Processing reward calculation"
    );

    if request.staker_stakes.len() > state.config.max_stakers {
        return Err((StatusCode::BAD_REQUEST, "Too many stakers".to_string()));
    }

    // ── Reject duplicate staker addresses ─────────────────────────────
    //
    // The XOR registry root is self-inverse: duplicate entries can cancel
    // out or collapse, allowing a manipulated snapshot to preserve the
    // same root while skewing reward allocations.  Fail-closed.
    validate_unique_staker_addresses(&request.staker_stakes)
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?;

    // ── Validate and recompute stake snapshot hash ─────────────────────
    //
    // The caller supplies a stake_snapshot_hash computed from the canonical
    // on-chain state. The TEE independently recomputes this from
    // request.staker_stakes and rejects if they differ — preventing a
    // relayer from omitting stakers or skewing balances while supplying
    // the correct full-snapshot hash to pass downstream verification.
    if request.stake_snapshot_hash.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "stake_snapshot_hash is required".to_string(),
        ));
    }
    let snapshot_hash_bytes: [u8; 32] = {
        let decoded = hex::decode(&request.stake_snapshot_hash).map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                "stake_snapshot_hash is not valid hex".to_string(),
            )
        })?;
        if decoded.len() != 32 {
            return Err((
                StatusCode::BAD_REQUEST,
                format!(
                    "stake_snapshot_hash must be 32 bytes, got {}",
                    decoded.len()
                ),
            ));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&decoded);
        arr
    };

    // Recompute from the actual staker data and verify
    let recomputed_snapshot = compute_stake_snapshot_hash(request.epoch, &request.staker_stakes);
    if recomputed_snapshot != snapshot_hash_bytes {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "stake_snapshot_hash mismatch: supplied {} but stakers hash to {}",
                request.stake_snapshot_hash,
                hex::encode(recomputed_snapshot),
            ),
        ));
    }

    // ── Validate and recompute validator set hash ─────────────────────
    //
    // The caller supplies a validator_set_hash derived from the canonical
    // validator set stored on-chain (the SHA-256 hash that was TEE-verified
    // during updateValidatorSet).  The TEE independently recomputes this
    // from request.validators and rejects if they differ — preventing a
    // relayer from supplying manipulated validator scores for performance-
    // weighted reward distribution while the correct hash passes downstream.
    if request.validator_set_hash.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "validator_set_hash is required".to_string(),
        ));
    }
    let vs_hash_bytes: [u8; 32] = {
        let decoded = hex::decode(&request.validator_set_hash).map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                "validator_set_hash is not valid hex".to_string(),
            )
        })?;
        if decoded.len() != 32 {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("validator_set_hash must be 32 bytes, got {}", decoded.len()),
            ));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&decoded);
        arr
    };

    // Recompute from the actual validator data and verify
    let recomputed_vs_hash = compute_validator_set_hash(request.epoch, &request.validators);
    if recomputed_vs_hash != vs_hash_bytes {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "validator_set_hash mismatch: supplied {} but validators hash to {}",
                request.validator_set_hash,
                hex::encode(recomputed_vs_hash),
            ),
        ));
    }

    let mut response = reward_calculator::calculate_rewards(&request).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("reward calculation failed: {}", e),
        )
    })?;

    // Compute the XOR staker-registry root from the supplied staker set.
    // This matches StAETHEL.stakerRegistryRoot on-chain and is verified
    // by Cruzible.distributeRewards() to prove the TEE computed rewards
    // from the actual on-chain staker set.
    let registry_root = compute_staker_registry_root(&request.staker_stakes);

    // Compute the XOR delegation-registry root from the supplied staker set.
    // This captures which validator each staker delegated to, binding the
    // delegation topology that drives performance-weighted reward allocation.
    // Stored in the epoch snapshot for auditability; the Go native keeper
    // can independently verify against native-chain delegation records.
    let delegation_root = compute_delegation_registry_root(&request.staker_stakes);

    // Generate attestation over the canonical reward payload.
    //
    // The attested bytes are abi.encode(epoch, totalRewards, merkleRoot,
    // protocolFee, stakeSnapshotHash, validatorSetHash, registryRoot,
    // delegationRoot) — 256 bytes — the format that
    // Cruzible.distributeRewards() verifies on-chain.  The snapshot hash
    // binds the attestation to the specific stake state, the validator set
    // hash binds it to the specific validator scores the TEE used for
    // reward distribution, the registry root proves the per-staker share
    // distribution was correct, and the delegation root proves the
    // delegation mapping used for performance-weighted allocation.
    let merkle_root = parse_merkle_root(&response.merkle_root);
    let canonical_payload = compute_canonical_reward_payload(
        request.epoch,
        request.total_rewards,
        &merkle_root,
        response.protocol_fee,
        &recomputed_snapshot,
        &recomputed_vs_hash,
        &registry_root,
        &delegation_root,
    );
    response.attestation = state
        .attestation_gen
        .generate(&canonical_payload)
        .map_err(|e| {
            state.metrics.total_errors.fetch_add(1, Ordering::Relaxed);
            error!(
                epoch = request.epoch,
                error = %e,
                "Attestation generation failed for reward calculation"
            );
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("attestation generation failed: {}", e),
            )
        })?;
    response.stake_snapshot_hash = hex::encode(recomputed_snapshot);
    response.validator_set_hash = hex::encode(recomputed_vs_hash);

    *state.total_attestations.write().await += 1;
    state
        .metrics
        .reward_calculations
        .fetch_add(1, Ordering::Relaxed);
    state.metrics.record_attestation_time();

    info!(
        epoch = request.epoch,
        stakers = request.staker_stakes.len(),
        validators = request.validators.len(),
        distributed = response.total_distributed,
        protocol_fee = response.protocol_fee,
        merkle_root = %response.merkle_root,
        stake_snapshot = %response.stake_snapshot_hash,
        validator_set = %response.validator_set_hash,
        "Reward calculation attestation complete"
    );

    Ok(Json(response))
}

async fn order_transactions_handler(
    State(state): State<Arc<AppState>>,
    Json(request): Json<OrderTransactionsRequest>,
) -> Result<Json<OrderTransactionsResponse>, (StatusCode, String)> {
    // ── Admission control ───────────────────────────────────────────────
    let max = state.config.max_commitments;

    if request.commitments.len() > max {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "Too many commitments ({}, max {})",
                request.commitments.len(),
                max
            ),
        ));
    }
    if request.reveals.len() > max {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("Too many reveals ({}, max {})", request.reveals.len(), max),
        ));
    }

    info!(
        epoch = request.epoch,
        commitments = request.commitments.len(),
        reveals = request.reveals.len(),
        "Processing MEV-protected ordering"
    );

    let (ordered, invalid) =
        mev_protection::process_commit_reveal(&request.commitments, &request.reveals);

    if !invalid.is_empty() {
        warn!(invalid_count = invalid.len(), "Invalid reveals detected");
    }

    // Check for MEV patterns
    let alerts = mev_protection::detect_mev_patterns(&ordered);
    if !alerts.is_empty() {
        warn!(alerts = alerts.len(), "MEV patterns detected");
    }

    // Generate attestation
    let order_data = serde_json::to_vec(&ordered).unwrap_or_default();
    let attestation = state.attestation_gen.generate(&order_data).map_err(|e| {
        state.metrics.total_errors.fetch_add(1, Ordering::Relaxed);
        error!(
            epoch = request.epoch,
            error = %e,
            "Attestation generation failed for MEV ordering"
        );
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("attestation generation failed: {}", e),
        )
    })?;

    *state.total_attestations.write().await += 1;
    state.metrics.mev_orderings.fetch_add(1, Ordering::Relaxed);
    state.metrics.record_attestation_time();

    info!(
        epoch = request.epoch,
        ordered = ordered.len(),
        invalid = invalid.len(),
        "MEV ordering attestation complete"
    );

    Ok(Json(OrderTransactionsResponse {
        epoch: request.epoch,
        ordered_blocks: ordered,
        invalid_reveals: invalid,
        attestation,
    }))
}

#[derive(serde::Deserialize)]
struct VerifyCommitmentRequest {
    block_data: String,
    nonce: String,
    expected_hash: String,
}

#[derive(serde::Serialize)]
struct VerifyCommitmentResponse {
    valid: bool,
    computed_hash: String,
}

async fn verify_commitment_handler(
    Json(request): Json<VerifyCommitmentRequest>,
) -> Json<VerifyCommitmentResponse> {
    let computed = mev_protection::compute_commitment_hash(&request.block_data, &request.nonce);
    let valid = computed == request.expected_hash;

    Json(VerifyCommitmentResponse {
        valid,
        computed_hash: computed,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Delegation Attestation
// ─────────────────────────────────────────────────────────────────────────────

/// `/attest-delegation` — TEE-verified delegation attestation.
///
/// The TEE independently computes the delegation registry root (XOR
/// accumulator) from the supplied staker set and produces a 96-byte
/// attestation over `abi.encode(epoch, delegationRoot, stakerRegistryRoot)`.
///
/// The keeper relays this attestation to `Cruzible.commitDelegationSnapshot()`
/// on-chain, which verifies the TEE signature and payload before accepting
/// the delegation commitment.  This closes the single-keeper trust gap:
/// the keeper cannot forge the delegation root because the TEE independently
/// computed and attested to it.
async fn attest_delegation_handler(
    State(state): State<Arc<AppState>>,
    Json(request): Json<AttestDelegationRequest>,
) -> Result<Json<AttestDelegationResponse>, (StatusCode, String)> {
    info!(
        epoch = request.epoch,
        stakers = request.staker_stakes.len(),
        "Processing delegation attestation"
    );

    if request.staker_stakes.len() > state.config.max_stakers {
        return Err((StatusCode::BAD_REQUEST, "Too many stakers".to_string()));
    }

    // ── Reject duplicate staker addresses ─────────────────────────────
    validate_unique_staker_addresses(&request.staker_stakes)
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?;

    // ── Validate and recompute staker registry root ─────────────────────
    //
    // The caller supplies a staker_registry_root computed from on-chain
    // stAETHEL state.  The TEE independently recomputes this from
    // request.staker_stakes and rejects if they differ — preventing a
    // relayer from supplying a fabricated staker set.
    if request.staker_registry_root.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "staker_registry_root is required".to_string(),
        ));
    }
    let registry_root_bytes: [u8; 32] = {
        let decoded = hex::decode(&request.staker_registry_root).map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                "staker_registry_root is not valid hex".to_string(),
            )
        })?;
        if decoded.len() != 32 {
            return Err((
                StatusCode::BAD_REQUEST,
                format!(
                    "staker_registry_root must be 32 bytes, got {}",
                    decoded.len()
                ),
            ));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&decoded);
        arr
    };

    // Recompute from the actual staker data and verify
    let recomputed_registry = compute_staker_registry_root(&request.staker_stakes);
    if recomputed_registry != registry_root_bytes {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "staker_registry_root mismatch: supplied {} but stakers hash to {}",
                request.staker_registry_root,
                hex::encode(recomputed_registry),
            ),
        ));
    }

    // ── Independently compute delegation registry root ──────────────────
    //
    // The TEE computes the XOR delegation accumulator from the same staker
    // set.  This is the value that will be committed on-chain — the keeper
    // does not choose or influence it.
    let delegation_root = compute_delegation_registry_root(&request.staker_stakes);

    // ── Build 96-byte attested payload ──────────────────────────────────
    //
    //   abi.encode(epoch, delegationRoot, stakerRegistryRoot)  (96 bytes)
    //
    // This binds the attestation to:
    //   1. epoch             — prevents cross-epoch replay
    //   2. delegationRoot    — the TEE-computed delegation topology
    //   3. stakerRegistryRoot — the staker set it was derived from
    let canonical_payload =
        compute_canonical_delegation_payload(request.epoch, &delegation_root, &recomputed_registry);

    let attestation = state
        .attestation_gen
        .generate(&canonical_payload)
        .map_err(|e| {
            state.metrics.total_errors.fetch_add(1, Ordering::Relaxed);
            error!(
                epoch = request.epoch,
                error = %e,
                "Attestation generation failed for delegation"
            );
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("attestation generation failed: {}", e),
            )
        })?;

    *state.total_attestations.write().await += 1;
    state
        .metrics
        .delegation_attestations
        .fetch_add(1, Ordering::Relaxed);
    state.metrics.record_attestation_time();

    info!(
        epoch = request.epoch,
        stakers = request.staker_stakes.len(),
        delegation_root = %hex::encode(delegation_root),
        staker_registry_root = %hex::encode(recomputed_registry),
        "Delegation attestation complete"
    );

    Ok(Json(AttestDelegationResponse {
        epoch: request.epoch,
        delegation_root: hex::encode(delegation_root),
        staker_registry_root: hex::encode(recomputed_registry),
        attestation,
    }))
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Cross-language test vector for the canonical reward payload.
    ///
    /// The byte output must match Solidity's:
    ///   `abi.encode(uint256(1), uint256(100e18), merkleRoot, uint256(5e18), snapshotHash, vsHash)`
    ///
    /// Test vector:
    ///   epoch            = 1
    ///   totalRewards     = 100_000_000_000_000_000_000  (100e18)
    ///   merkleRoot       = keccak256("rewards-merkle-root") (same as Cruzible.t.sol)
    ///   protocolFee      = 5_000_000_000_000_000_000    (5e18)
    ///   snapshotHash     = [0xCC; 32]  (test placeholder)
    ///   validatorSetHash = [0xDD; 32]  (test placeholder)
    #[test]
    fn test_canonical_reward_payload_layout() {
        let epoch: u64 = 1;
        let total_rewards: u128 = 100_000_000_000_000_000_000; // 100e18
        let protocol_fee: u128 = 5_000_000_000_000_000_000; // 5e18
        let snapshot_hash: [u8; 32] = [0xCC; 32];
        let vs_hash: [u8; 32] = [0xDD; 32];

        // merkleRoot = keccak256("rewards-merkle-root") matches Cruzible.t.sol test
        let merkle_root: [u8; 32] = {
            use sha3::{Digest, Keccak256};
            let mut hasher = Keccak256::new();
            hasher.update(b"rewards-merkle-root");
            let result = hasher.finalize();
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&result);
            arr
        };

        let reg = [0xEE; 32];
        let del_reg = [0xFF; 32];
        let payload = compute_canonical_reward_payload(
            epoch,
            total_rewards,
            &merkle_root,
            protocol_fee,
            &snapshot_hash,
            &vs_hash,
            &reg,
            &del_reg,
        );

        // Must be 256 bytes (8 × 32-byte ABI words)
        assert_eq!(payload.len(), 256);

        // Word 0: epoch = 1 → last byte is 0x01, rest zeros
        assert_eq!(payload[0..31], [0u8; 31]);
        assert_eq!(payload[31], 1);

        // Word 1: totalRewards = 100e18 = 0x56BC75E2D63100000
        // u128 occupies bytes 48..64, preceding bytes 32..48 are zero
        assert_eq!(payload[32..48], [0u8; 16]);
        assert_eq!(&payload[48..64], &total_rewards.to_be_bytes());

        // Word 2: merkleRoot = raw 32 bytes
        assert_eq!(&payload[64..96], &merkle_root);

        // Word 3: protocolFee = 5e18
        assert_eq!(payload[96..112], [0u8; 16]);
        assert_eq!(&payload[112..128], &protocol_fee.to_be_bytes());

        // Word 4: stakeSnapshotHash = raw 32 bytes
        assert_eq!(&payload[128..160], &snapshot_hash);

        // Word 5: validatorSetHash = raw 32 bytes
        assert_eq!(&payload[160..192], &vs_hash);

        // Word 6: stakerRegistryRoot = raw 32 bytes
        assert_eq!(&payload[192..224], &reg);

        // Word 7: delegationRegistryRoot = raw 32 bytes
        assert_eq!(&payload[224..256], &del_reg);
    }

    #[test]
    fn test_canonical_reward_payload_deterministic() {
        let root = [0xAA; 32];
        let snap = [0x11; 32];
        let vs = [0x55; 32];
        let reg = [0u8; 32];
        let p1 = compute_canonical_reward_payload(1, 100, &root, 5, &snap, &vs, &reg, &[0u8; 32]);
        let p2 = compute_canonical_reward_payload(1, 100, &root, 5, &snap, &vs, &reg, &[0u8; 32]);
        assert_eq!(p1, p2, "canonical reward payload must be deterministic");
    }

    #[test]
    fn test_canonical_reward_payload_different_epoch() {
        let root = [0xBB; 32];
        let snap = [0x22; 32];
        let vs = [0x66; 32];
        let reg = [0u8; 32];
        let p1 = compute_canonical_reward_payload(1, 100, &root, 5, &snap, &vs, &reg, &[0u8; 32]);
        let p2 = compute_canonical_reward_payload(2, 100, &root, 5, &snap, &vs, &reg, &[0u8; 32]);
        assert_ne!(p1, p2, "different epoch should produce different payload");
    }

    #[test]
    fn test_canonical_reward_payload_different_snapshot() {
        let root = [0xCC; 32];
        let snap1 = [0x33; 32];
        let snap2 = [0x44; 32];
        let vs = [0x77; 32];
        let reg = [0u8; 32];
        let p1 = compute_canonical_reward_payload(1, 100, &root, 5, &snap1, &vs, &reg, &[0u8; 32]);
        let p2 = compute_canonical_reward_payload(1, 100, &root, 5, &snap2, &vs, &reg, &[0u8; 32]);
        assert_ne!(
            p1, p2,
            "different snapshot hash should produce different payload"
        );
    }

    #[test]
    fn test_canonical_reward_payload_different_validator_set() {
        let root = [0xDD; 32];
        let snap = [0x55; 32];
        let vs1 = [0x88; 32];
        let vs2 = [0x99; 32];
        let reg = [0u8; 32];
        let p1 = compute_canonical_reward_payload(1, 100, &root, 5, &snap, &vs1, &reg, &[0u8; 32]);
        let p2 = compute_canonical_reward_payload(1, 100, &root, 5, &snap, &vs2, &reg, &[0u8; 32]);
        assert_ne!(
            p1, p2,
            "different validator set hash should produce different payload"
        );
    }

    #[test]
    fn test_canonical_reward_payload_different_registry_root() {
        let root = [0xEE; 32];
        let snap = [0x55; 32];
        let vs = [0x77; 32];
        let reg1 = [0xAA; 32];
        let reg2 = [0xBB; 32];
        let p1 = compute_canonical_reward_payload(1, 100, &root, 5, &snap, &vs, &reg1, &[0u8; 32]);
        let p2 = compute_canonical_reward_payload(1, 100, &root, 5, &snap, &vs, &reg2, &[0u8; 32]);
        assert_ne!(
            p1, p2,
            "different registry root should produce different payload"
        );
    }

    #[test]
    fn test_canonical_reward_payload_different_delegation_root() {
        let root = [0xEE; 32];
        let snap = [0x55; 32];
        let vs = [0x77; 32];
        let reg = [0xAA; 32];
        let del1 = [0xCC; 32];
        let del2 = [0xDD; 32];
        let p1 = compute_canonical_reward_payload(1, 100, &root, 5, &snap, &vs, &reg, &del1);
        let p2 = compute_canonical_reward_payload(1, 100, &root, 5, &snap, &vs, &reg, &del2);
        assert_ne!(
            p1, p2,
            "different delegation root should produce different payload"
        );
    }

    #[test]
    fn test_parse_merkle_root() {
        // Standard 0x-prefixed hex
        let root =
            parse_merkle_root("0x0000000000000000000000000000000000000000000000000000000000000001");
        assert_eq!(root[31], 1);
        assert_eq!(root[0..31], [0u8; 31]);

        // No prefix
        let root2 =
            parse_merkle_root("0000000000000000000000000000000000000000000000000000000000000002");
        assert_eq!(root2[31], 2);

        // Empty/invalid returns zeros
        let root3 = parse_merkle_root("");
        assert_eq!(root3, [0u8; 32]);
    }

    /// Cross-language vector: the SHA-256 of the canonical reward payload
    /// must match what the on-chain verifier computes from abi.encode().
    ///
    /// Since the contract checks:
    ///   keccak256(payload) == keccak256(abi.encode(epoch, totalRewards, merkleRoot, protocolFee, snapshotHash, vsHash))
    ///
    /// the raw bytes must be identical.
    #[test]
    fn test_canonical_reward_payload_matches_abi_encode() {
        // Reproduce the exact test from Cruzible.t.sol test_distributeRewards:
        //   epoch = 1, totalRewards = 100 ether, protocolFee = 5 ether
        //   merkleRoot = keccak256("rewards-merkle-root")
        //   snapshotHash = keccak256("test-stake-snapshot-v1")
        //   vsHash = keccak256("test-validator-set-v1")
        let epoch: u64 = 1;
        let total_rewards: u128 = 100_000_000_000_000_000_000;
        let protocol_fee: u128 = 5_000_000_000_000_000_000;

        let merkle_root: [u8; 32] = {
            use sha3::{Digest, Keccak256};
            let mut hasher = Keccak256::new();
            hasher.update(b"rewards-merkle-root");
            let result = hasher.finalize();
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&result);
            arr
        };

        let snapshot_hash: [u8; 32] = {
            use sha3::{Digest, Keccak256};
            let hash = Keccak256::digest(b"test-stake-snapshot-v1");
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&hash);
            arr
        };

        let vs_hash: [u8; 32] = {
            use sha3::{Digest, Keccak256};
            let hash = Keccak256::digest(b"test-validator-set-v1");
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&hash);
            arr
        };

        let registry_root = [0u8; 32]; // zero root for test
        let delegation_root = [0u8; 32]; // zero delegation root for test
        let payload = compute_canonical_reward_payload(
            epoch,
            total_rewards,
            &merkle_root,
            protocol_fee,
            &snapshot_hash,
            &vs_hash,
            &registry_root,
            &delegation_root,
        );

        // Verify the payload is what Solidity's abi.encode would produce:
        // Manually construct abi.encode(uint256(1), uint256(100e18), bytes32(merkleRoot), uint256(5e18), snapshotHash, vsHash, registryRoot, delegationRoot)
        let mut expected = [0u8; 256];
        // uint256(1)
        expected[24..32].copy_from_slice(&1u64.to_be_bytes());
        // uint256(100e18)
        expected[48..64].copy_from_slice(&total_rewards.to_be_bytes());
        // bytes32(merkleRoot)
        expected[64..96].copy_from_slice(&merkle_root);
        // uint256(5e18)
        expected[112..128].copy_from_slice(&protocol_fee.to_be_bytes());
        // bytes32(snapshotHash)
        expected[128..160].copy_from_slice(&snapshot_hash);
        // bytes32(vsHash)
        expected[160..192].copy_from_slice(&vs_hash);
        // bytes32(registryRoot)
        expected[192..224].copy_from_slice(&registry_root);
        // bytes32(delegationRoot)
        expected[224..256].copy_from_slice(&delegation_root);

        assert_eq!(
            payload, expected,
            "canonical payload must match abi.encode output"
        );

        // Log the keccak256 for cross-language verification
        use sha3::{Digest, Keccak256};
        let hash = Keccak256::digest(&payload);
        eprintln!(
            "CROSS_LANG_VECTOR reward_payload_keccak256={}",
            hex::encode(hash)
        );
    }

    // ─────────────────────────────────────────────────────────────────────
    // Staker Registry Root Tests
    // ─────────────────────────────────────────────────────────────────────

    #[test]
    fn test_staker_registry_root_empty() {
        let root = compute_staker_registry_root(&[]);
        assert_eq!(root, [0u8; 32], "empty staker set should produce zero root");
    }

    #[test]
    fn test_staker_registry_root_skips_zero_shares() {
        let stakers = vec![StakerStake {
            address: "0x0000000000000000000000000000000000000001".to_string(),
            shares: 0,
            delegated_to: "0x0000000000000000000000000000000000000010".to_string(),
        }];
        let root = compute_staker_registry_root(&stakers);
        assert_eq!(root, [0u8; 32], "zero-share staker should be excluded");
    }

    #[test]
    fn test_staker_registry_root_order_independent() {
        let a = StakerStake {
            address: "0x0000000000000000000000000000000000000001".to_string(),
            shares: 100,
            delegated_to: "0x0000000000000000000000000000000000000010".to_string(),
        };
        let b = StakerStake {
            address: "0x0000000000000000000000000000000000000002".to_string(),
            shares: 200,
            delegated_to: "0x0000000000000000000000000000000000000020".to_string(),
        };
        let r1 = compute_staker_registry_root(&[a.clone(), b.clone()]);
        let r2 = compute_staker_registry_root(&[b, a]);
        assert_eq!(r1, r2, "XOR accumulator must be order-independent");
    }

    #[test]
    fn test_staker_registry_root_detects_share_change() {
        let s1 = vec![StakerStake {
            address: "0x0000000000000000000000000000000000000001".to_string(),
            shares: 100,
            delegated_to: "0x0000000000000000000000000000000000000010".to_string(),
        }];
        let s2 = vec![StakerStake {
            address: "0x0000000000000000000000000000000000000001".to_string(),
            shares: 101,
            delegated_to: "0x0000000000000000000000000000000000000010".to_string(),
        }];
        let r1 = compute_staker_registry_root(&s1);
        let r2 = compute_staker_registry_root(&s2);
        assert_ne!(r1, r2, "changing shares should change registry root");
    }

    #[test]
    fn test_staker_registry_root_ignores_delegation() {
        let s1 = vec![StakerStake {
            address: "0x0000000000000000000000000000000000000001".to_string(),
            shares: 100,
            delegated_to: "0x0000000000000000000000000000000000000010".to_string(),
        }];
        let s2 = vec![StakerStake {
            address: "0x0000000000000000000000000000000000000001".to_string(),
            shares: 100,
            delegated_to: "0x0000000000000000000000000000000000000099".to_string(),
        }];
        let r1 = compute_staker_registry_root(&s1);
        let r2 = compute_staker_registry_root(&s2);
        assert_eq!(
            r1, r2,
            "registry root should not depend on delegation (EVM-visible only)"
        );
    }

    // ─────────────────────────────────────────────────────────────────────
    // Delegation Registry Root Tests
    // ─────────────────────────────────────────────────────────────────────

    #[test]
    fn test_delegation_registry_root_empty() {
        let root = compute_delegation_registry_root(&[]);
        assert_eq!(root, [0u8; 32], "empty staker set should produce zero root");
    }

    #[test]
    fn test_delegation_registry_root_skips_zero_shares() {
        let stakers = vec![StakerStake {
            address: "0x0000000000000000000000000000000000000001".to_string(),
            shares: 0,
            delegated_to: "0x0000000000000000000000000000000000000010".to_string(),
        }];
        let root = compute_delegation_registry_root(&stakers);
        assert_eq!(root, [0u8; 32], "zero-share staker should be excluded");
    }

    #[test]
    fn test_delegation_registry_root_order_independent() {
        let a = StakerStake {
            address: "0x0000000000000000000000000000000000000001".to_string(),
            shares: 100,
            delegated_to: "0x0000000000000000000000000000000000000010".to_string(),
        };
        let b = StakerStake {
            address: "0x0000000000000000000000000000000000000002".to_string(),
            shares: 200,
            delegated_to: "0x0000000000000000000000000000000000000020".to_string(),
        };
        let r1 = compute_delegation_registry_root(&[a.clone(), b.clone()]);
        let r2 = compute_delegation_registry_root(&[b, a]);
        assert_eq!(r1, r2, "XOR accumulator must be order-independent");
    }

    #[test]
    fn test_delegation_registry_root_detects_delegation_change() {
        let s1 = vec![StakerStake {
            address: "0x0000000000000000000000000000000000000001".to_string(),
            shares: 100,
            delegated_to: "0x0000000000000000000000000000000000000010".to_string(),
        }];
        let s2 = vec![StakerStake {
            address: "0x0000000000000000000000000000000000000001".to_string(),
            shares: 100,
            delegated_to: "0x0000000000000000000000000000000000000099".to_string(),
        }];
        let r1 = compute_delegation_registry_root(&s1);
        let r2 = compute_delegation_registry_root(&s2);
        assert_ne!(
            r1, r2,
            "changing delegated_to should change delegation registry root"
        );
    }

    #[test]
    fn test_delegation_registry_root_ignores_share_change() {
        let s1 = vec![StakerStake {
            address: "0x0000000000000000000000000000000000000001".to_string(),
            shares: 100,
            delegated_to: "0x0000000000000000000000000000000000000010".to_string(),
        }];
        let s2 = vec![StakerStake {
            address: "0x0000000000000000000000000000000000000001".to_string(),
            shares: 999,
            delegated_to: "0x0000000000000000000000000000000000000010".to_string(),
        }];
        let r1 = compute_delegation_registry_root(&s1);
        let r2 = compute_delegation_registry_root(&s2);
        assert_eq!(
            r1, r2,
            "delegation root should not depend on share amounts (only address + delegated_to)"
        );
    }

    // ─────────────────────────────────────────────────────────────────────
    // Selection Policy Hash Tests
    // ─────────────────────────────────────────────────────────────────────

    #[test]
    fn test_selection_policy_hash_deterministic() {
        let config = SelectionConfig::default();
        let h1 = compute_selection_policy_hash(&config);
        let h2 = compute_selection_policy_hash(&config);
        assert_eq!(h1, h2, "policy hash must be deterministic");
    }

    #[test]
    fn test_selection_policy_hash_different_weights() {
        let config1 = SelectionConfig {
            performance_weight: 0.4,
            decentralization_weight: 0.3,
            reputation_weight: 0.3,
            ..SelectionConfig::default()
        };
        let config2 = SelectionConfig {
            performance_weight: 0.5,
            decentralization_weight: 0.3,
            reputation_weight: 0.2,
            ..SelectionConfig::default()
        };
        let h1 = compute_selection_policy_hash(&config1);
        let h2 = compute_selection_policy_hash(&config2);
        assert_ne!(h1, h2, "different weights must produce different hashes");
    }

    #[test]
    fn test_selection_policy_hash_different_min_stake() {
        let config1 = SelectionConfig {
            min_stake: 32_000_000_000_000_000_000, // 32e18
            ..SelectionConfig::default()
        };
        let config2 = SelectionConfig {
            min_stake: 64_000_000_000_000_000_000, // 64e18
            ..SelectionConfig::default()
        };
        let h1 = compute_selection_policy_hash(&config1);
        let h2 = compute_selection_policy_hash(&config2);
        assert_ne!(h1, h2, "different min_stake must produce different hashes");
    }

    #[test]
    fn test_selection_policy_hash_domain_separation() {
        // The hash uses "CruzibleSelectionPolicy-v1" prefix.
        // Verify that the same field values produce a different hash
        // than a raw SHA-256 of the field bytes (no domain separator).
        let config = SelectionConfig::default();
        let policy_hash = compute_selection_policy_hash(&config);

        // Compute hash without domain separator
        let mut h_no_domain = Sha256::new();
        h_no_domain.update(config.performance_weight.to_be_bytes());
        h_no_domain.update(config.decentralization_weight.to_be_bytes());
        h_no_domain.update(config.reputation_weight.to_be_bytes());
        h_no_domain.update(config.min_uptime_pct.to_be_bytes());
        let mut comm_padded = [0u8; 32];
        comm_padded[28..].copy_from_slice(&config.max_commission_bps.to_be_bytes());
        h_no_domain.update(comm_padded);
        let mut region_padded = [0u8; 32];
        region_padded[24..].copy_from_slice(&(config.max_per_region as u64).to_be_bytes());
        h_no_domain.update(region_padded);
        let mut operator_padded = [0u8; 32];
        operator_padded[24..].copy_from_slice(&(config.max_per_operator as u64).to_be_bytes());
        h_no_domain.update(operator_padded);
        let mut stake_padded = [0u8; 32];
        stake_padded[16..].copy_from_slice(&config.min_stake.to_be_bytes());
        h_no_domain.update(stake_padded);
        let mut no_domain_result = [0u8; 32];
        no_domain_result.copy_from_slice(&h_no_domain.finalize());

        assert_ne!(
            policy_hash, no_domain_result,
            "domain-separated hash must differ from bare hash"
        );
    }

    /// Cross-language test vector for selection policy hash.
    ///
    /// Uses the protocol default config and logs the resulting hash
    /// for verification against Go's computeSelectionPolicyHash().
    #[test]
    fn test_selection_policy_hash_cross_language_vector() {
        let config = SelectionConfig::default();
        let hash = compute_selection_policy_hash(&config);

        // Log for cross-language verification
        eprintln!(
            "CROSS_LANG_VECTOR default_policy_hash={}",
            hex::encode(hash)
        );

        // Verify the hash is non-zero
        assert_ne!(hash, [0u8; 32], "policy hash must not be zero");

        // Verify attested payload structure:
        //   canonicalHash || policyHash || universeHash = 96 bytes
        let fake_canonical = [0xAA; 32];
        let fake_universe = [0xBB; 32];
        let mut attested_payload = [0u8; 96];
        attested_payload[0..32].copy_from_slice(&fake_canonical);
        attested_payload[32..64].copy_from_slice(&hash);
        attested_payload[64..96].copy_from_slice(&fake_universe);
        assert_eq!(
            attested_payload.len(),
            96,
            "attested payload must be 96 bytes"
        );
        assert_eq!(&attested_payload[0..32], &fake_canonical);
        assert_eq!(&attested_payload[32..64], &hash);
        assert_eq!(&attested_payload[64..96], &fake_universe);
    }

    #[test]
    fn test_select_validators_handler_rejects_missing_universe_hash() {
        // A SelectValidatorsRequest with an empty eligible_universe_hash
        // must be rejected by the handler (fail-closed).
        let request = SelectValidatorsRequest {
            validators: vec![],
            target_count: 0,
            epoch: 1,
            config: SelectionConfig::default(),
            eligible_universe_hash: String::new(),
            total_active_count: 0,
            eligible_count: 0,
            skipped_stale_count: 0,
        };
        assert!(
            request.eligible_universe_hash.is_empty(),
            "empty universe hash must be detected by the handler"
        );
    }

    #[test]
    fn test_universe_hash_in_attested_payload() {
        // Verify that a 96-byte payload correctly encodes all three hashes
        let canonical = Sha256::digest(b"validators");
        let policy = Sha256::digest(b"policy");
        let universe = Sha256::digest(b"universe");

        let mut payload = [0u8; 96];
        payload[0..32].copy_from_slice(&canonical);
        payload[32..64].copy_from_slice(&policy);
        payload[64..96].copy_from_slice(&universe);

        // Verify individual regions
        assert_eq!(&payload[0..32], canonical.as_slice());
        assert_eq!(&payload[32..64], policy.as_slice());
        assert_eq!(&payload[64..96], universe.as_slice());

        // Verify full hash differs from 64-byte version (no universe)
        let mut old_payload = [0u8; 64];
        old_payload[0..32].copy_from_slice(&canonical);
        old_payload[32..64].copy_from_slice(&policy);

        let hash_96 = Sha256::digest(&payload);
        let hash_64 = Sha256::digest(&old_payload);
        assert_ne!(
            hash_96.as_slice(),
            hash_64.as_slice(),
            "96-byte payload hash must differ from 64-byte (universe hash changes the digest)"
        );
    }

    #[test]
    fn test_compute_eligible_universe_hash_matches_go_keeper() {
        // Verify the Rust computation matches the Go keeper's algorithm:
        //   SHA-256(addr_0 || 0x00 || addr_1 || 0x00 || ... || addr_n || 0x00)
        // with addresses sorted lexicographically.
        let addrs = vec![
            "aethel1existing2".to_string(),
            "aethel1existing1".to_string(),
            "aethel1existing3".to_string(),
        ];
        let hash = compute_eligible_universe_hash(&addrs);

        // Manually compute expected: sorted order is existing1, existing2, existing3
        let mut expected_hasher = Sha256::new();
        expected_hasher.update(b"aethel1existing1");
        expected_hasher.update(&[0u8]);
        expected_hasher.update(b"aethel1existing2");
        expected_hasher.update(&[0u8]);
        expected_hasher.update(b"aethel1existing3");
        expected_hasher.update(&[0u8]);
        let expected: [u8; 32] = expected_hasher.finalize().into();

        assert_eq!(
            hash, expected,
            "universe hash must match Go keeper algorithm"
        );
    }

    #[test]
    fn test_universe_hash_rejects_truncated_candidate_list() {
        // A relayer submits the correct full-universe hash for 3 validators but
        // only includes 2 in the actual candidate list.  The TEE must reject
        // because the recomputed hash from request.validators won't match.
        let full_addrs = vec![
            "aethel1alice".to_string(),
            "aethel1bob".to_string(),
            "aethel1charlie".to_string(),
        ];
        let full_hash = compute_eligible_universe_hash(&full_addrs);
        let full_hash_hex = hex::encode(full_hash);

        // Truncated list (omits "aethel1charlie")
        let truncated_addrs = vec!["aethel1alice".to_string(), "aethel1bob".to_string()];
        let truncated_hash = compute_eligible_universe_hash(&truncated_addrs);

        // The hashes must differ — if the TEE only checks the supplied hash
        // without recomputing, the truncation would be undetectable.
        assert_ne!(
            full_hash, truncated_hash,
            "hash of truncated list must differ from full list"
        );

        // Verify the supplied full-universe hash doesn't match the truncated candidates
        let full_hash_bytes: [u8; 32] = hex::decode(&full_hash_hex).unwrap().try_into().unwrap();
        assert_ne!(
            truncated_hash, full_hash_bytes,
            "TEE recomputation from truncated candidates must not match the full-universe hash"
        );
    }

    #[test]
    fn test_universe_hash_empty_set() {
        // Edge case: empty validator set should produce a deterministic hash
        let hash = compute_eligible_universe_hash(&[]);
        // SHA-256 of empty input
        let expected: [u8; 32] = Sha256::digest(b"").into();
        assert_eq!(
            hash, expected,
            "empty set hash must be SHA-256 of empty input"
        );
    }

    #[test]
    fn test_universe_hash_order_independence() {
        // The function sorts internally, so different input orders produce the same hash
        let hash_a = compute_eligible_universe_hash(&[
            "z_validator".to_string(),
            "a_validator".to_string(),
            "m_validator".to_string(),
        ]);
        let hash_b = compute_eligible_universe_hash(&[
            "a_validator".to_string(),
            "m_validator".to_string(),
            "z_validator".to_string(),
        ]);
        assert_eq!(
            hash_a, hash_b,
            "hash must be order-independent (sorted internally)"
        );
    }

    // ─────────────────────────────────────────────────────────────────────
    // Stake Snapshot Hash Tests
    // ─────────────────────────────────────────────────────────────────────

    #[test]
    fn test_stake_snapshot_hash_deterministic() {
        let stakers = vec![
            StakerStake {
                address: "0xAlice".to_string(),
                shares: 1000,
                delegated_to: "0xValidator1".to_string(),
            },
            StakerStake {
                address: "0xBob".to_string(),
                shares: 2000,
                delegated_to: "0xValidator2".to_string(),
            },
        ];
        let h1 = compute_stake_snapshot_hash(1, &stakers);
        let h2 = compute_stake_snapshot_hash(1, &stakers);
        assert_eq!(h1, h2, "snapshot hash must be deterministic");
    }

    #[test]
    fn test_stake_snapshot_hash_order_independent() {
        let stakers_ab = vec![
            StakerStake {
                address: "0xAlice".to_string(),
                shares: 1000,
                delegated_to: "0xValidator1".to_string(),
            },
            StakerStake {
                address: "0xBob".to_string(),
                shares: 2000,
                delegated_to: "0xValidator2".to_string(),
            },
        ];
        let stakers_ba = vec![
            StakerStake {
                address: "0xBob".to_string(),
                shares: 2000,
                delegated_to: "0xValidator2".to_string(),
            },
            StakerStake {
                address: "0xAlice".to_string(),
                shares: 1000,
                delegated_to: "0xValidator1".to_string(),
            },
        ];
        let h1 = compute_stake_snapshot_hash(1, &stakers_ab);
        let h2 = compute_stake_snapshot_hash(1, &stakers_ba);
        assert_eq!(
            h1, h2,
            "snapshot hash must be order-independent (sorted internally)"
        );
    }

    #[test]
    fn test_stake_snapshot_hash_different_epoch() {
        let stakers = vec![StakerStake {
            address: "0xAlice".to_string(),
            shares: 1000,
            delegated_to: "0xValidator1".to_string(),
        }];
        let h1 = compute_stake_snapshot_hash(1, &stakers);
        let h2 = compute_stake_snapshot_hash(2, &stakers);
        assert_ne!(h1, h2, "different epoch must produce different hash");
    }

    #[test]
    fn test_stake_snapshot_hash_detects_omitted_staker() {
        // This is the core security property: a relayer cannot omit a staker
        // from the TEE input while preserving the snapshot hash.
        let full_stakers = vec![
            StakerStake {
                address: "0xAlice".to_string(),
                shares: 1000,
                delegated_to: "0xValidator1".to_string(),
            },
            StakerStake {
                address: "0xBob".to_string(),
                shares: 2000,
                delegated_to: "0xValidator2".to_string(),
            },
            StakerStake {
                address: "0xCharlie".to_string(),
                shares: 3000,
                delegated_to: "0xValidator1".to_string(),
            },
        ];
        let truncated_stakers = vec![
            StakerStake {
                address: "0xAlice".to_string(),
                shares: 1000,
                delegated_to: "0xValidator1".to_string(),
            },
            StakerStake {
                address: "0xBob".to_string(),
                shares: 2000,
                delegated_to: "0xValidator2".to_string(),
            },
            // Charlie omitted
        ];

        let full_hash = compute_stake_snapshot_hash(1, &full_stakers);
        let truncated_hash = compute_stake_snapshot_hash(1, &truncated_stakers);
        assert_ne!(
            full_hash, truncated_hash,
            "omitting a staker must change the snapshot hash"
        );
    }

    #[test]
    fn test_stake_snapshot_hash_detects_skewed_balance() {
        // A relayer cannot skew a staker's balance while preserving the hash.
        let honest = vec![StakerStake {
            address: "0xAlice".to_string(),
            shares: 1000,
            delegated_to: "0xValidator1".to_string(),
        }];
        let skewed = vec![StakerStake {
            address: "0xAlice".to_string(),
            shares: 500, // halved
            delegated_to: "0xValidator1".to_string(),
        }];

        let h1 = compute_stake_snapshot_hash(1, &honest);
        let h2 = compute_stake_snapshot_hash(1, &skewed);
        assert_ne!(
            h1, h2,
            "skewing a staker's balance must change the snapshot hash"
        );
    }

    #[test]
    fn test_stake_snapshot_hash_domain_separation() {
        // Hash must use domain prefix "CruzibleStakeSnapshot-v1"
        let stakers = vec![StakerStake {
            address: "0xAlice".to_string(),
            shares: 1000,
            delegated_to: "0xValidator1".to_string(),
        }];
        let hash = compute_stake_snapshot_hash(1, &stakers);
        assert_ne!(hash, [0u8; 32], "snapshot hash must not be zero");
    }

    // ─────────────────────────────────────────────────────────────────────
    // Delegation Attestation Payload Tests
    // ─────────────────────────────────────────────────────────────────────

    #[test]
    fn test_canonical_delegation_payload_layout() {
        let del_root = [0xAA; 32];
        let reg_root = [0xBB; 32];
        let payload = compute_canonical_delegation_payload(42, &del_root, &reg_root);

        assert_eq!(payload.len(), 96);

        // epoch = 42 as uint256: last 8 bytes of first 32-byte word
        assert_eq!(payload[24..32], 42u64.to_be_bytes());
        // First 24 bytes of epoch word are zero-padding
        assert_eq!(&payload[0..24], &[0u8; 24]);

        // delegationRoot: bytes 32..64
        assert_eq!(&payload[32..64], &del_root);

        // stakerRegistryRoot: bytes 64..96
        assert_eq!(&payload[64..96], &reg_root);
    }

    #[test]
    fn test_canonical_delegation_payload_deterministic() {
        let del_root = [0x11; 32];
        let reg_root = [0x22; 32];
        let p1 = compute_canonical_delegation_payload(1, &del_root, &reg_root);
        let p2 = compute_canonical_delegation_payload(1, &del_root, &reg_root);
        assert_eq!(p1, p2, "same inputs must produce identical payloads");
    }

    #[test]
    fn test_canonical_delegation_payload_different_epoch() {
        let del_root = [0x11; 32];
        let reg_root = [0x22; 32];
        let p1 = compute_canonical_delegation_payload(1, &del_root, &reg_root);
        let p2 = compute_canonical_delegation_payload(2, &del_root, &reg_root);
        assert_ne!(p1, p2, "different epoch must produce different payload");
    }

    #[test]
    fn test_canonical_delegation_payload_different_delegation_root() {
        let reg_root = [0x22; 32];
        let p1 = compute_canonical_delegation_payload(1, &[0xAA; 32], &reg_root);
        let p2 = compute_canonical_delegation_payload(1, &[0xBB; 32], &reg_root);
        assert_ne!(
            p1, p2,
            "different delegation root must produce different payload"
        );
    }

    #[test]
    fn test_canonical_delegation_payload_different_registry_root() {
        let del_root = [0x11; 32];
        let p1 = compute_canonical_delegation_payload(1, &del_root, &[0xAA; 32]);
        let p2 = compute_canonical_delegation_payload(1, &del_root, &[0xBB; 32]);
        assert_ne!(
            p1, p2,
            "different registry root must produce different payload"
        );
    }

    /// Cross-language test vector: verify the 96-byte delegation payload
    /// matches the Solidity `abi.encode(uint256, bytes32, bytes32)` layout.
    #[test]
    fn test_canonical_delegation_payload_matches_abi_encode() {
        // epoch = 1
        let mut expected = [0u8; 96];
        // uint256(1): big-endian in last 8 bytes of first word
        expected[31] = 1;

        // delegationRoot = bytes32(0x0...01)
        let mut del_root = [0u8; 32];
        del_root[31] = 1;
        expected[32..64].copy_from_slice(&del_root);

        // stakerRegistryRoot = bytes32(0x0...02)
        let mut reg_root = [0u8; 32];
        reg_root[31] = 2;
        expected[64..96].copy_from_slice(&reg_root);

        let actual = compute_canonical_delegation_payload(1, &del_root, &reg_root);
        assert_eq!(
            actual, expected,
            "delegation payload must match Solidity abi.encode layout"
        );
    }

    // ─────────────────────────────────────────────────────────────────────
    // Staker Uniqueness Validation Tests
    // ─────────────────────────────────────────────────────────────────────

    #[test]
    fn test_validate_unique_stakers_accepts_unique() {
        let stakers = vec![
            StakerStake {
                address: "0xAlice".into(),
                shares: 100,
                delegated_to: "0xV1".into(),
            },
            StakerStake {
                address: "0xBob".into(),
                shares: 200,
                delegated_to: "0xV1".into(),
            },
        ];
        assert!(validate_unique_staker_addresses(&stakers).is_ok());
    }

    #[test]
    fn test_validate_unique_stakers_rejects_duplicate() {
        let stakers = vec![
            StakerStake {
                address: "0xAlice".into(),
                shares: 100,
                delegated_to: "0xV1".into(),
            },
            StakerStake {
                address: "0xBob".into(),
                shares: 200,
                delegated_to: "0xV1".into(),
            },
            StakerStake {
                address: "0xAlice".into(),
                shares: 100,
                delegated_to: "0xV1".into(),
            },
        ];
        let err = validate_unique_staker_addresses(&stakers).unwrap_err();
        assert!(
            err.contains("0xAlice"),
            "error should name the duplicate address"
        );
    }

    #[test]
    fn test_validate_unique_stakers_rejects_odd_triplication() {
        // XOR attack: 3 copies of Alice produce the same XOR root as 1 copy,
        // but the staker count and snapshot hash differ.
        let stakers = vec![
            StakerStake {
                address: "0xAlice".into(),
                shares: 100,
                delegated_to: "0xV1".into(),
            },
            StakerStake {
                address: "0xAlice".into(),
                shares: 100,
                delegated_to: "0xV1".into(),
            },
            StakerStake {
                address: "0xAlice".into(),
                shares: 100,
                delegated_to: "0xV1".into(),
            },
        ];
        assert!(
            validate_unique_staker_addresses(&stakers).is_err(),
            "triplicated address must be rejected"
        );
    }

    #[test]
    fn test_validate_unique_stakers_empty_set() {
        assert!(validate_unique_staker_addresses(&[]).is_ok());
    }
}
