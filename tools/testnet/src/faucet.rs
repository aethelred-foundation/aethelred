//! Test Token Faucet
//!
//! A sophisticated test token faucet with multi-layer anti-abuse protection,
//! rate limiting, captcha verification, and developer-friendly features.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// ============================================================================
// Faucet Configuration
// ============================================================================

/// Configuration for the test token faucet
#[derive(Debug, Clone)]
pub struct FaucetConfig {
    /// Amount of tokens to drip per request (in wei)
    pub drip_amount: String,
    /// Maximum amount per day per address
    pub max_daily_per_address: String,
    /// Maximum amount per day per IP
    pub max_daily_per_ip: String,
    /// Cooldown between requests (seconds)
    pub cooldown_seconds: u64,
    /// Require captcha verification
    pub require_captcha: bool,
    /// Require social verification (Twitter/GitHub)
    pub require_social: bool,
    /// Enable developer tier (higher limits)
    pub developer_tier_enabled: bool,
    /// Developer tier drip amount
    pub developer_drip_amount: String,
    /// Enable bulk requests for verified developers
    pub bulk_requests_enabled: bool,
    /// Maximum bulk request count
    pub max_bulk_count: usize,
    /// Supported token types
    pub supported_tokens: Vec<TokenConfig>,
    /// Enable queue for high-demand periods
    pub queue_enabled: bool,
    /// Queue timeout (seconds)
    pub queue_timeout_seconds: u64,
}

#[derive(Debug, Clone)]
pub struct TokenConfig {
    pub symbol: String,
    pub name: String,
    pub contract_address: Option<String>,
    pub drip_amount: String,
    pub decimals: u8,
    pub is_native: bool,
}

impl Default for FaucetConfig {
    fn default() -> Self {
        FaucetConfig {
            drip_amount: "10000000000000000000".to_string(), // 10 tAETH
            max_daily_per_address: "100000000000000000000".to_string(), // 100 tAETH
            max_daily_per_ip: "500000000000000000000".to_string(), // 500 tAETH
            cooldown_seconds: 60, // 1 minute
            require_captcha: true,
            require_social: false,
            developer_tier_enabled: true,
            developer_drip_amount: "100000000000000000000".to_string(), // 100 tAETH
            bulk_requests_enabled: true,
            max_bulk_count: 10,
            supported_tokens: vec![
                TokenConfig {
                    symbol: "tAETH".to_string(),
                    name: "Testnet Aethelred Token".to_string(),
                    contract_address: None,
                    drip_amount: "10000000000000000000".to_string(),
                    decimals: 18,
                    is_native: true,
                },
                TokenConfig {
                    symbol: "tUSDC".to_string(),
                    name: "Testnet USDC".to_string(),
                    contract_address: Some("0x1234567890123456789012345678901234567890".to_string()),
                    drip_amount: "1000000000".to_string(), // 1000 USDC
                    decimals: 6,
                    is_native: false,
                },
                TokenConfig {
                    symbol: "tWBTC".to_string(),
                    name: "Testnet Wrapped Bitcoin".to_string(),
                    contract_address: Some("0x2345678901234567890123456789012345678901".to_string()),
                    drip_amount: "100000000".to_string(), // 1 BTC
                    decimals: 8,
                    is_native: false,
                },
            ],
            queue_enabled: true,
            queue_timeout_seconds: 300, // 5 minutes
        }
    }
}

// ============================================================================
// Faucet Service
// ============================================================================

/// Main faucet service
pub struct Faucet {
    config: FaucetConfig,
    /// Request tracking by address
    address_requests: HashMap<String, Vec<FaucetRequest>>,
    /// Request tracking by IP
    ip_requests: HashMap<String, Vec<FaucetRequest>>,
    /// Verified developers
    verified_developers: HashMap<String, DeveloperProfile>,
    /// Pending requests queue
    request_queue: Vec<QueuedRequest>,
    /// Blocklisted addresses
    blocklist: HashMap<String, BlocklistEntry>,
    /// Statistics
    stats: FaucetStats,
    /// Rate limiter
    rate_limiter: RateLimiter,
}

#[derive(Debug, Clone)]
pub struct FaucetRequest {
    pub id: String,
    pub address: String,
    pub amount: String,
    pub token: String,
    pub ip_address: String,
    pub timestamp: u64,
    pub tx_hash: Option<String>,
    pub status: RequestStatus,
    pub verification: VerificationMethod,
}

#[derive(Debug, Clone)]
pub enum RequestStatus {
    Pending,
    Processing,
    Completed,
    Failed(String),
    Queued,
}

#[derive(Debug, Clone)]
pub enum VerificationMethod {
    None,
    Captcha,
    Twitter(String),
    GitHub(String),
    Email(String),
    ApiKey(String),
}

#[derive(Debug, Clone)]
pub struct DeveloperProfile {
    pub address: String,
    pub name: Option<String>,
    pub email: Option<String>,
    pub github: Option<String>,
    pub twitter: Option<String>,
    pub tier: DeveloperTier,
    pub api_key: String,
    pub created_at: u64,
    pub total_claimed: String,
    pub last_claim: Option<u64>,
    pub verified: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub enum DeveloperTier {
    Basic,
    Verified,
    Premium,
    Enterprise,
}

impl DeveloperTier {
    pub fn drip_multiplier(&self) -> u64 {
        match self {
            DeveloperTier::Basic => 1,
            DeveloperTier::Verified => 10,
            DeveloperTier::Premium => 50,
            DeveloperTier::Enterprise => 100,
        }
    }

    pub fn cooldown_divisor(&self) -> u64 {
        match self {
            DeveloperTier::Basic => 1,
            DeveloperTier::Verified => 2,
            DeveloperTier::Premium => 5,
            DeveloperTier::Enterprise => 10,
        }
    }
}

#[derive(Debug, Clone)]
pub struct QueuedRequest {
    pub request: FaucetRequest,
    pub position: usize,
    pub queued_at: u64,
    pub estimated_wait_seconds: u64,
}

#[derive(Debug, Clone)]
pub struct BlocklistEntry {
    pub address: String,
    pub reason: String,
    pub blocked_at: u64,
    pub expires_at: Option<u64>,
    pub blocked_by: String,
}

#[derive(Debug, Clone, Default)]
pub struct FaucetStats {
    pub total_requests: u64,
    pub successful_requests: u64,
    pub failed_requests: u64,
    pub total_dripped: String,
    pub unique_addresses: u64,
    pub unique_ips: u64,
    pub blocked_attempts: u64,
    pub queue_peak_size: usize,
    pub average_wait_time_seconds: f64,
}

impl Faucet {
    pub fn new(config: FaucetConfig) -> Self {
        Faucet {
            config,
            address_requests: HashMap::new(),
            ip_requests: HashMap::new(),
            verified_developers: HashMap::new(),
            request_queue: Vec::new(),
            blocklist: HashMap::new(),
            stats: FaucetStats::default(),
            rate_limiter: RateLimiter::new(),
        }
    }

    /// Request tokens from the faucet
    pub fn request_tokens(&mut self, request: FaucetRequest) -> Result<FaucetResponse, FaucetError> {
        // Check blocklist
        if let Some(entry) = self.blocklist.get(&request.address) {
            if entry.expires_at.map_or(true, |exp| exp > Self::current_timestamp()) {
                return Err(FaucetError::Blocked {
                    reason: entry.reason.clone(),
                });
            }
        }

        // Check IP blocklist
        if let Some(entry) = self.blocklist.get(&request.ip_address) {
            if entry.expires_at.map_or(true, |exp| exp > Self::current_timestamp()) {
                return Err(FaucetError::Blocked {
                    reason: entry.reason.clone(),
                });
            }
        }

        // Check rate limits
        if let Err(e) = self.check_rate_limits(&request) {
            return Err(e);
        }

        // Check verification if required
        if self.config.require_captcha {
            match &request.verification {
                VerificationMethod::None => {
                    return Err(FaucetError::VerificationRequired {
                        method: "captcha".to_string(),
                    });
                }
                _ => {}
            }
        }

        // Determine tier and amounts
        let tier = self.get_tier(&request.address);
        let amount = self.calculate_drip_amount(&request.token, &tier);

        // Queue if under high load
        if self.config.queue_enabled && self.should_queue() {
            let position = self.request_queue.len() + 1;
            let estimated_wait = position as u64 * 5; // 5 seconds per request

            self.request_queue.push(QueuedRequest {
                request: request.clone(),
                position,
                queued_at: Self::current_timestamp(),
                estimated_wait_seconds: estimated_wait,
            });

            return Ok(FaucetResponse::Queued {
                position,
                estimated_wait_seconds: estimated_wait,
                queue_id: format!("queue-{}", uuid::Uuid::new_v4()),
            });
        }

        // Process request
        let tx_hash = self.execute_drip(&request.address, &amount, &request.token)?;

        // Record request
        let completed_request = FaucetRequest {
            tx_hash: Some(tx_hash.clone()),
            status: RequestStatus::Completed,
            ..request.clone()
        };

        self.record_request(&completed_request);
        self.update_stats(&completed_request, &amount);

        Ok(FaucetResponse::Success {
            tx_hash,
            amount,
            token: request.token,
            cooldown_seconds: self.get_cooldown(&tier),
        })
    }

    /// Request tokens for multiple addresses (bulk request)
    pub fn bulk_request(
        &mut self,
        addresses: Vec<String>,
        token: String,
        requester: String,
        ip_address: String,
    ) -> Result<BulkFaucetResponse, FaucetError> {
        // Verify requester has bulk access
        let developer = self.verified_developers.get(&requester)
            .ok_or(FaucetError::Unauthorized)?;

        if developer.tier != DeveloperTier::Premium && developer.tier != DeveloperTier::Enterprise {
            return Err(FaucetError::InsufficientTier {
                required: DeveloperTier::Premium,
                current: developer.tier.clone(),
            });
        }

        if addresses.len() > self.config.max_bulk_count {
            return Err(FaucetError::BulkLimitExceeded {
                max: self.config.max_bulk_count,
                requested: addresses.len(),
            });
        }

        let mut results = Vec::new();
        let mut success_count = 0;
        let mut failed_count = 0;

        for address in addresses {
            let request = FaucetRequest {
                id: uuid::Uuid::new_v4().to_string(),
                address: address.clone(),
                amount: self.config.drip_amount.clone(),
                token: token.clone(),
                ip_address: ip_address.clone(),
                timestamp: Self::current_timestamp(),
                tx_hash: None,
                status: RequestStatus::Pending,
                verification: VerificationMethod::ApiKey(developer.api_key.clone()),
            };

            match self.request_tokens(request) {
                Ok(response) => {
                    results.push(BulkRequestResult {
                        address,
                        success: true,
                        tx_hash: match response {
                            FaucetResponse::Success { tx_hash, .. } => Some(tx_hash),
                            _ => None,
                        },
                        error: None,
                    });
                    success_count += 1;
                }
                Err(e) => {
                    results.push(BulkRequestResult {
                        address,
                        success: false,
                        tx_hash: None,
                        error: Some(format!("{:?}", e)),
                    });
                    failed_count += 1;
                }
            }
        }

        Ok(BulkFaucetResponse {
            total_requested: results.len(),
            success_count,
            failed_count,
            results,
        })
    }

    /// Register as a verified developer
    pub fn register_developer(&mut self, profile: DeveloperProfile) -> Result<String, FaucetError> {
        if self.verified_developers.contains_key(&profile.address) {
            return Err(FaucetError::AlreadyRegistered);
        }

        let api_key = format!("aeth_test_{}", uuid::Uuid::new_v4().to_string().replace("-", ""));

        let new_profile = DeveloperProfile {
            api_key: api_key.clone(),
            created_at: Self::current_timestamp(),
            verified: false,
            tier: DeveloperTier::Basic,
            ..profile
        };

        self.verified_developers.insert(new_profile.address.clone(), new_profile);
        Ok(api_key)
    }

    /// Upgrade developer tier
    pub fn upgrade_tier(&mut self, address: &str, new_tier: DeveloperTier) -> Result<(), FaucetError> {
        let profile = self.verified_developers.get_mut(address)
            .ok_or(FaucetError::DeveloperNotFound)?;

        profile.tier = new_tier;
        profile.verified = true;
        Ok(())
    }

    /// Get queue status
    pub fn get_queue_status(&self, queue_id: &str) -> Option<QueueStatus> {
        self.request_queue.iter()
            .find(|q| format!("queue-{}", q.request.id) == queue_id)
            .map(|q| QueueStatus {
                queue_id: queue_id.to_string(),
                position: q.position,
                estimated_wait_seconds: q.estimated_wait_seconds,
                status: q.request.status.clone(),
            })
    }

    /// Get faucet statistics
    pub fn get_stats(&self) -> FaucetStats {
        self.stats.clone()
    }

    /// Get address history
    pub fn get_address_history(&self, address: &str) -> Vec<FaucetRequest> {
        self.address_requests
            .get(address)
            .cloned()
            .unwrap_or_default()
    }

    /// Add address to blocklist
    pub fn blocklist_address(&mut self, entry: BlocklistEntry) {
        self.blocklist.insert(entry.address.clone(), entry);
    }

    /// Remove address from blocklist
    pub fn unblock_address(&mut self, address: &str) -> bool {
        self.blocklist.remove(address).is_some()
    }

    // Private helper methods

    fn check_rate_limits(&self, request: &FaucetRequest) -> Result<(), FaucetError> {
        let now = Self::current_timestamp();
        let tier = self.get_tier(&request.address);
        let cooldown = self.get_cooldown(&tier);

        // Check address cooldown
        if let Some(requests) = self.address_requests.get(&request.address) {
            if let Some(last) = requests.last() {
                let elapsed = now - last.timestamp;
                if elapsed < cooldown {
                    return Err(FaucetError::RateLimited {
                        wait_seconds: cooldown - elapsed,
                    });
                }
            }
        }

        // Check daily limit for address
        if let Some(requests) = self.address_requests.get(&request.address) {
            let day_start = now - (now % 86400);
            let daily_total: u128 = requests.iter()
                .filter(|r| r.timestamp >= day_start)
                .filter_map(|r| r.amount.parse::<u128>().ok())
                .sum();

            let max_daily: u128 = self.config.max_daily_per_address.parse().unwrap_or(0);
            if daily_total >= max_daily {
                return Err(FaucetError::DailyLimitExceeded {
                    limit: self.config.max_daily_per_address.clone(),
                });
            }
        }

        // Check daily limit for IP
        if let Some(requests) = self.ip_requests.get(&request.ip_address) {
            let day_start = now - (now % 86400);
            let daily_total: u128 = requests.iter()
                .filter(|r| r.timestamp >= day_start)
                .filter_map(|r| r.amount.parse::<u128>().ok())
                .sum();

            let max_daily: u128 = self.config.max_daily_per_ip.parse().unwrap_or(0);
            if daily_total >= max_daily {
                return Err(FaucetError::IpLimitExceeded {
                    limit: self.config.max_daily_per_ip.clone(),
                });
            }
        }

        Ok(())
    }

    fn get_tier(&self, address: &str) -> DeveloperTier {
        self.verified_developers
            .get(address)
            .map(|d| d.tier.clone())
            .unwrap_or(DeveloperTier::Basic)
    }

    fn get_cooldown(&self, tier: &DeveloperTier) -> u64 {
        self.config.cooldown_seconds / tier.cooldown_divisor()
    }

    fn calculate_drip_amount(&self, token: &str, tier: &DeveloperTier) -> String {
        let token_config = self.config.supported_tokens.iter()
            .find(|t| t.symbol == token)
            .unwrap_or(&self.config.supported_tokens[0]);

        let base: u128 = token_config.drip_amount.parse().unwrap_or(0);
        let multiplied = base * tier.drip_multiplier() as u128;
        multiplied.to_string()
    }

    fn should_queue(&self) -> bool {
        // Queue if request rate is high
        self.request_queue.len() > 10
    }

    fn execute_drip(&self, address: &str, amount: &str, token: &str) -> Result<String, FaucetError> {
        // In production, this would send the actual transaction
        // For now, generate a mock transaction hash
        Ok(format!("0x{:064x}", rand::random::<u64>()))
    }

    fn record_request(&mut self, request: &FaucetRequest) {
        self.address_requests
            .entry(request.address.clone())
            .or_insert_with(Vec::new)
            .push(request.clone());

        self.ip_requests
            .entry(request.ip_address.clone())
            .or_insert_with(Vec::new)
            .push(request.clone());
    }

    fn update_stats(&mut self, request: &FaucetRequest, amount: &str) {
        self.stats.total_requests += 1;

        match &request.status {
            RequestStatus::Completed => self.stats.successful_requests += 1,
            RequestStatus::Failed(_) => self.stats.failed_requests += 1,
            _ => {}
        }

        // Update total dripped
        let current: u128 = self.stats.total_dripped.parse().unwrap_or(0);
        let added: u128 = amount.parse().unwrap_or(0);
        self.stats.total_dripped = (current + added).to_string();

        self.stats.unique_addresses = self.address_requests.len() as u64;
        self.stats.unique_ips = self.ip_requests.len() as u64;
    }

    fn current_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }
}

// ============================================================================
// Rate Limiter
// ============================================================================

pub struct RateLimiter {
    windows: HashMap<String, SlidingWindow>,
}

struct SlidingWindow {
    requests: Vec<u64>,
    window_size_seconds: u64,
    max_requests: usize,
}

impl RateLimiter {
    pub fn new() -> Self {
        RateLimiter {
            windows: HashMap::new(),
        }
    }

    pub fn check(&mut self, key: &str, window_size: u64, max_requests: usize) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let window = self.windows.entry(key.to_string()).or_insert_with(|| {
            SlidingWindow {
                requests: Vec::new(),
                window_size_seconds: window_size,
                max_requests,
            }
        });

        // Remove old requests
        window.requests.retain(|&t| now - t < window_size);

        if window.requests.len() < max_requests {
            window.requests.push(now);
            true
        } else {
            false
        }
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Response Types
// ============================================================================

#[derive(Debug, Clone)]
pub enum FaucetResponse {
    Success {
        tx_hash: String,
        amount: String,
        token: String,
        cooldown_seconds: u64,
    },
    Queued {
        position: usize,
        estimated_wait_seconds: u64,
        queue_id: String,
    },
}

#[derive(Debug, Clone)]
pub struct BulkFaucetResponse {
    pub total_requested: usize,
    pub success_count: usize,
    pub failed_count: usize,
    pub results: Vec<BulkRequestResult>,
}

#[derive(Debug, Clone)]
pub struct BulkRequestResult {
    pub address: String,
    pub success: bool,
    pub tx_hash: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct QueueStatus {
    pub queue_id: String,
    pub position: usize,
    pub estimated_wait_seconds: u64,
    pub status: RequestStatus,
}

// ============================================================================
// Error Types
// ============================================================================

#[derive(Debug, Clone)]
pub enum FaucetError {
    Blocked { reason: String },
    RateLimited { wait_seconds: u64 },
    DailyLimitExceeded { limit: String },
    IpLimitExceeded { limit: String },
    VerificationRequired { method: String },
    InvalidAddress,
    InvalidToken,
    TransactionFailed { reason: String },
    QueueTimeout,
    AlreadyRegistered,
    DeveloperNotFound,
    Unauthorized,
    InsufficientTier { required: DeveloperTier, current: DeveloperTier },
    BulkLimitExceeded { max: usize, requested: usize },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_faucet_request() {
        let config = FaucetConfig {
            require_captcha: false,
            ..Default::default()
        };
        let mut faucet = Faucet::new(config);

        let request = FaucetRequest {
            id: "test-1".to_string(),
            address: "0x1234567890123456789012345678901234567890".to_string(),
            amount: "10000000000000000000".to_string(),
            token: "tAETH".to_string(),
            ip_address: "127.0.0.1".to_string(),
            timestamp: Faucet::current_timestamp(),
            tx_hash: None,
            status: RequestStatus::Pending,
            verification: VerificationMethod::None,
        };

        let result = faucet.request_tokens(request);
        assert!(result.is_ok());
    }

    #[test]
    fn test_rate_limiting() {
        let config = FaucetConfig {
            require_captcha: false,
            cooldown_seconds: 60,
            ..Default::default()
        };
        let mut faucet = Faucet::new(config);

        // First request should succeed
        let request1 = FaucetRequest {
            id: "test-1".to_string(),
            address: "0x1234567890123456789012345678901234567890".to_string(),
            amount: "10000000000000000000".to_string(),
            token: "tAETH".to_string(),
            ip_address: "127.0.0.1".to_string(),
            timestamp: Faucet::current_timestamp(),
            tx_hash: None,
            status: RequestStatus::Pending,
            verification: VerificationMethod::None,
        };

        let result1 = faucet.request_tokens(request1);
        assert!(result1.is_ok());

        // Second request should be rate limited
        let request2 = FaucetRequest {
            id: "test-2".to_string(),
            address: "0x1234567890123456789012345678901234567890".to_string(),
            amount: "10000000000000000000".to_string(),
            token: "tAETH".to_string(),
            ip_address: "127.0.0.1".to_string(),
            timestamp: Faucet::current_timestamp(),
            tx_hash: None,
            status: RequestStatus::Pending,
            verification: VerificationMethod::None,
        };

        let result2 = faucet.request_tokens(request2);
        assert!(matches!(result2, Err(FaucetError::RateLimited { .. })));
    }

    #[test]
    fn test_developer_registration() {
        let mut faucet = Faucet::new(FaucetConfig::default());

        let profile = DeveloperProfile {
            address: "0x1234567890123456789012345678901234567890".to_string(),
            name: Some("Test Developer".to_string()),
            email: Some("test@example.com".to_string()),
            github: Some("testdev".to_string()),
            twitter: None,
            tier: DeveloperTier::Basic,
            api_key: String::new(),
            created_at: 0,
            total_claimed: "0".to_string(),
            last_claim: None,
            verified: false,
        };

        let result = faucet.register_developer(profile);
        assert!(result.is_ok());
        assert!(result.unwrap().starts_with("aeth_test_"));
    }
}
