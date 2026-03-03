//! Webhook Testing Infrastructure for Aethelred Testnet
//!
//! Industry-leading webhook testing capabilities:
//! - Instant webhook delivery for blockchain events
//! - Webhook inspector with full request/response capture
//! - Replay and retry mechanisms
//! - Mock server for testing integrations
//! - Signature verification testing
//! - Load testing and reliability metrics

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use serde::{Deserialize, Serialize};

// ============ Webhook Event Types ============

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WebhookEventType {
    // Block events
    BlockCreated,
    BlockFinalized,
    BlockReorg,

    // Transaction events
    TransactionSubmitted,
    TransactionConfirmed,
    TransactionFailed,
    TransactionReverted,

    // Seal events (AI model sealing)
    SealRequested,
    SealValidating,
    SealCompleted,
    SealFailed,

    // Job events (AI compute jobs)
    JobSubmitted,
    JobScheduled,
    JobProcessing,
    JobCompleted,
    JobFailed,

    // Validator events
    ValidatorOnline,
    ValidatorOffline,
    ValidatorSlashed,

    // Account events
    BalanceChanged,
    NonceChanged,

    // Custom events
    Custom(String),
}

impl WebhookEventType {
    pub fn as_str(&self) -> &str {
        match self {
            Self::BlockCreated => "block.created",
            Self::BlockFinalized => "block.finalized",
            Self::BlockReorg => "block.reorg",
            Self::TransactionSubmitted => "transaction.submitted",
            Self::TransactionConfirmed => "transaction.confirmed",
            Self::TransactionFailed => "transaction.failed",
            Self::TransactionReverted => "transaction.reverted",
            Self::SealRequested => "seal.requested",
            Self::SealValidating => "seal.validating",
            Self::SealCompleted => "seal.completed",
            Self::SealFailed => "seal.failed",
            Self::JobSubmitted => "job.submitted",
            Self::JobScheduled => "job.scheduled",
            Self::JobProcessing => "job.processing",
            Self::JobCompleted => "job.completed",
            Self::JobFailed => "job.failed",
            Self::ValidatorOnline => "validator.online",
            Self::ValidatorOffline => "validator.offline",
            Self::ValidatorSlashed => "validator.slashed",
            Self::BalanceChanged => "account.balance_changed",
            Self::NonceChanged => "account.nonce_changed",
            Self::Custom(name) => name.as_str(),
        }
    }

    pub fn all_types() -> Vec<WebhookEventType> {
        vec![
            Self::BlockCreated,
            Self::BlockFinalized,
            Self::BlockReorg,
            Self::TransactionSubmitted,
            Self::TransactionConfirmed,
            Self::TransactionFailed,
            Self::TransactionReverted,
            Self::SealRequested,
            Self::SealValidating,
            Self::SealCompleted,
            Self::SealFailed,
            Self::JobSubmitted,
            Self::JobScheduled,
            Self::JobProcessing,
            Self::JobCompleted,
            Self::JobFailed,
            Self::ValidatorOnline,
            Self::ValidatorOffline,
            Self::ValidatorSlashed,
            Self::BalanceChanged,
            Self::NonceChanged,
        ]
    }
}

// ============ Webhook Configuration ============

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookConfig {
    /// Unique webhook ID
    pub id: String,

    /// Target URL for webhook delivery
    pub url: String,

    /// Events to subscribe to
    pub events: Vec<WebhookEventType>,

    /// Secret for HMAC signature
    pub secret: String,

    /// Optional filter criteria
    pub filters: Option<WebhookFilters>,

    /// Retry configuration
    pub retry_config: RetryConfig,

    /// Headers to include
    pub custom_headers: HashMap<String, String>,

    /// Active status
    pub active: bool,

    /// Creation timestamp
    pub created_at: u64,

    /// Owner address
    pub owner: String,

    /// Description
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookFilters {
    /// Filter by sender address
    pub from_addresses: Option<Vec<String>>,

    /// Filter by recipient address
    pub to_addresses: Option<Vec<String>>,

    /// Filter by contract address
    pub contract_addresses: Option<Vec<String>>,

    /// Filter by minimum value (wei)
    pub min_value: Option<u128>,

    /// Filter by model hash (for seal events)
    pub model_hashes: Option<Vec<String>>,

    /// Custom filter expression (JavaScript-like)
    pub expression: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryConfig {
    /// Maximum retry attempts
    pub max_retries: u32,

    /// Initial retry delay (ms)
    pub initial_delay_ms: u64,

    /// Backoff multiplier
    pub backoff_multiplier: f64,

    /// Maximum delay (ms)
    pub max_delay_ms: u64,

    /// Timeout per request (ms)
    pub timeout_ms: u64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: 5,
            initial_delay_ms: 1000,
            backoff_multiplier: 2.0,
            max_delay_ms: 60000,
            timeout_ms: 30000,
        }
    }
}

// ============ Webhook Events ============

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookEvent {
    /// Unique event ID
    pub id: String,

    /// Event type
    pub event_type: WebhookEventType,

    /// Event payload
    pub payload: WebhookPayload,

    /// Block number where event occurred
    pub block_number: u64,

    /// Block hash
    pub block_hash: String,

    /// Timestamp
    pub timestamp: u64,

    /// Related transaction hash (if applicable)
    pub tx_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum WebhookPayload {
    Block(BlockPayload),
    Transaction(TransactionPayload),
    Seal(SealPayload),
    Job(JobPayload),
    Validator(ValidatorPayload),
    Account(AccountPayload),
    Custom(serde_json::Value),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockPayload {
    pub number: u64,
    pub hash: String,
    pub parent_hash: String,
    pub timestamp: u64,
    pub transaction_count: usize,
    pub gas_used: u64,
    pub gas_limit: u64,
    pub proposer: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionPayload {
    pub hash: String,
    pub from: String,
    pub to: Option<String>,
    pub value: String,
    pub gas_used: u64,
    pub gas_price: String,
    pub nonce: u64,
    pub status: String,
    pub block_number: u64,
    pub input_data: String,
    pub logs: Vec<LogPayload>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogPayload {
    pub address: String,
    pub topics: Vec<String>,
    pub data: String,
    pub log_index: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealPayload {
    pub seal_id: String,
    pub model_hash: String,
    pub input_hash: String,
    pub output_hash: Option<String>,
    pub requester: String,
    pub status: String,
    pub validators: Vec<String>,
    pub proofs: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobPayload {
    pub job_id: String,
    pub job_type: String,
    pub requester: String,
    pub assigned_validator: Option<String>,
    pub status: String,
    pub input_size: u64,
    pub output_size: Option<u64>,
    pub compute_units: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorPayload {
    pub validator_address: String,
    pub moniker: String,
    pub event: String,
    pub stake: String,
    pub slash_amount: Option<String>,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountPayload {
    pub address: String,
    pub old_balance: String,
    pub new_balance: String,
    pub change: String,
    pub nonce: u64,
}

// ============ Webhook Delivery ============

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookDelivery {
    /// Unique delivery ID
    pub id: String,

    /// Webhook config ID
    pub webhook_id: String,

    /// Event that triggered the webhook
    pub event: WebhookEvent,

    /// Request details
    pub request: DeliveryRequest,

    /// Response details (if received)
    pub response: Option<DeliveryResponse>,

    /// Delivery status
    pub status: DeliveryStatus,

    /// Attempt number (1-based)
    pub attempt: u32,

    /// Duration in milliseconds
    pub duration_ms: u64,

    /// Timestamp
    pub timestamp: u64,

    /// Error message (if failed)
    pub error: Option<String>,

    /// Next retry time (if pending retry)
    pub next_retry_at: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeliveryRequest {
    pub method: String,
    pub url: String,
    pub headers: HashMap<String, String>,
    pub body: String,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeliveryResponse {
    pub status_code: u16,
    pub headers: HashMap<String, String>,
    pub body: String,
    pub latency_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeliveryStatus {
    Pending,
    Delivered,
    Failed,
    Retrying,
    Expired,
}

// ============ Webhook Manager ============

pub struct WebhookManager {
    webhooks: HashMap<String, WebhookConfig>,
    deliveries: VecDeque<WebhookDelivery>,
    delivery_queue: VecDeque<(String, WebhookEvent)>,
    metrics: WebhookMetrics,
    mock_server: Option<MockWebhookServer>,
    max_deliveries_stored: usize,
}

impl WebhookManager {
    pub fn new() -> Self {
        Self {
            webhooks: HashMap::new(),
            deliveries: VecDeque::new(),
            delivery_queue: VecDeque::new(),
            metrics: WebhookMetrics::default(),
            mock_server: None,
            max_deliveries_stored: 10000,
        }
    }

    /// Register a new webhook
    pub fn register_webhook(&mut self, config: WebhookConfig) -> Result<String, String> {
        // Validate URL
        if !config.url.starts_with("http://") && !config.url.starts_with("https://") {
            return Err("Invalid URL: must start with http:// or https://".to_string());
        }

        // Validate events
        if config.events.is_empty() {
            return Err("At least one event type must be subscribed".to_string());
        }

        let id = config.id.clone();
        self.webhooks.insert(id.clone(), config);

        Ok(id)
    }

    /// Update webhook configuration
    pub fn update_webhook(&mut self, id: &str, updates: WebhookUpdate) -> Result<(), String> {
        let webhook = self.webhooks.get_mut(id)
            .ok_or_else(|| format!("Webhook {} not found", id))?;

        if let Some(url) = updates.url {
            webhook.url = url;
        }
        if let Some(events) = updates.events {
            webhook.events = events;
        }
        if let Some(active) = updates.active {
            webhook.active = active;
        }
        if let Some(filters) = updates.filters {
            webhook.filters = Some(filters);
        }
        if let Some(retry_config) = updates.retry_config {
            webhook.retry_config = retry_config;
        }

        Ok(())
    }

    /// Delete a webhook
    pub fn delete_webhook(&mut self, id: &str) -> Result<(), String> {
        self.webhooks.remove(id)
            .map(|_| ())
            .ok_or_else(|| format!("Webhook {} not found", id))
    }

    /// Get webhook by ID
    pub fn get_webhook(&self, id: &str) -> Option<&WebhookConfig> {
        self.webhooks.get(id)
    }

    /// List all webhooks for an owner
    pub fn list_webhooks(&self, owner: &str) -> Vec<&WebhookConfig> {
        self.webhooks.values()
            .filter(|w| w.owner == owner)
            .collect()
    }

    /// Emit an event to all subscribed webhooks
    pub fn emit_event(&mut self, event: WebhookEvent) {
        let matching_webhooks: Vec<String> = self.webhooks.values()
            .filter(|w| w.active && w.events.iter().any(|e| e.as_str() == event.event_type.as_str()))
            .filter(|w| self.matches_filters(w, &event))
            .map(|w| w.id.clone())
            .collect();

        for webhook_id in matching_webhooks {
            self.delivery_queue.push_back((webhook_id, event.clone()));
        }

        self.metrics.events_emitted += 1;
    }

    /// Check if event matches webhook filters
    fn matches_filters(&self, webhook: &WebhookConfig, event: &WebhookEvent) -> bool {
        let filters = match &webhook.filters {
            Some(f) => f,
            None => return true,
        };

        // Apply filters based on event payload
        match &event.payload {
            WebhookPayload::Transaction(tx) => {
                if let Some(ref addrs) = filters.from_addresses {
                    if !addrs.contains(&tx.from) {
                        return false;
                    }
                }
                if let Some(ref addrs) = filters.to_addresses {
                    if let Some(ref to) = tx.to {
                        if !addrs.contains(to) {
                            return false;
                        }
                    }
                }
            }
            WebhookPayload::Seal(seal) => {
                if let Some(ref hashes) = filters.model_hashes {
                    if !hashes.contains(&seal.model_hash) {
                        return false;
                    }
                }
            }
            _ => {}
        }

        true
    }

    /// Process delivery queue (called periodically)
    pub fn process_queue(&mut self) -> Vec<WebhookDelivery> {
        let mut delivered = Vec::new();

        while let Some((webhook_id, event)) = self.delivery_queue.pop_front() {
            if let Some(webhook) = self.webhooks.get(&webhook_id) {
                let delivery = self.deliver_webhook(webhook.clone(), event);
                delivered.push(delivery.clone());
                self.store_delivery(delivery);
            }
        }

        delivered
    }

    /// Deliver webhook (simulated for testnet)
    fn deliver_webhook(&mut self, webhook: WebhookConfig, event: WebhookEvent) -> WebhookDelivery {
        let delivery_id = format!("del_{}", generate_id());
        let timestamp = current_timestamp();

        // Build request
        let body = serde_json::to_string(&WebhookBody {
            id: event.id.clone(),
            event_type: event.event_type.as_str().to_string(),
            created_at: event.timestamp,
            data: &event.payload,
        }).unwrap_or_default();

        let signature = self.compute_signature(&body, &webhook.secret);

        let mut headers = webhook.custom_headers.clone();
        headers.insert("Content-Type".to_string(), "application/json".to_string());
        headers.insert("X-Aethelred-Signature".to_string(), signature.clone());
        headers.insert("X-Aethelred-Event".to_string(), event.event_type.as_str().to_string());
        headers.insert("X-Aethelred-Delivery".to_string(), delivery_id.clone());

        let request = DeliveryRequest {
            method: "POST".to_string(),
            url: webhook.url.clone(),
            headers,
            body: body.clone(),
            signature,
        };

        // Simulate delivery (in real implementation, this would make HTTP request)
        let (status, response, duration_ms) = if let Some(ref mock) = self.mock_server {
            mock.handle_request(&request)
        } else {
            // Simulate successful delivery
            (
                DeliveryStatus::Delivered,
                Some(DeliveryResponse {
                    status_code: 200,
                    headers: HashMap::new(),
                    body: r#"{"received": true}"#.to_string(),
                    latency_ms: 50,
                }),
                50,
            )
        };

        self.metrics.deliveries_attempted += 1;
        if status == DeliveryStatus::Delivered {
            self.metrics.deliveries_succeeded += 1;
        } else {
            self.metrics.deliveries_failed += 1;
        }

        WebhookDelivery {
            id: delivery_id,
            webhook_id: webhook.id,
            event,
            request,
            response,
            status,
            attempt: 1,
            duration_ms,
            timestamp,
            error: None,
            next_retry_at: None,
        }
    }

    /// Compute HMAC-SHA256 signature
    fn compute_signature(&self, body: &str, secret: &str) -> String {
        // Simplified signature (real implementation would use HMAC-SHA256)
        format!("sha256={:x}", simple_hash(&format!("{}{}", body, secret)))
    }

    /// Store delivery in history
    fn store_delivery(&mut self, delivery: WebhookDelivery) {
        self.deliveries.push_front(delivery);

        // Trim to max size
        while self.deliveries.len() > self.max_deliveries_stored {
            self.deliveries.pop_back();
        }
    }

    /// Get delivery by ID
    pub fn get_delivery(&self, id: &str) -> Option<&WebhookDelivery> {
        self.deliveries.iter().find(|d| d.id == id)
    }

    /// List deliveries for a webhook
    pub fn list_deliveries(&self, webhook_id: &str, limit: usize) -> Vec<&WebhookDelivery> {
        self.deliveries.iter()
            .filter(|d| d.webhook_id == webhook_id)
            .take(limit)
            .collect()
    }

    /// Replay a delivery
    pub fn replay_delivery(&mut self, delivery_id: &str) -> Result<WebhookDelivery, String> {
        let original = self.deliveries.iter()
            .find(|d| d.id == delivery_id)
            .cloned()
            .ok_or_else(|| format!("Delivery {} not found", delivery_id))?;

        let webhook = self.webhooks.get(&original.webhook_id)
            .cloned()
            .ok_or_else(|| format!("Webhook {} not found", original.webhook_id))?;

        let new_delivery = self.deliver_webhook(webhook, original.event);
        self.store_delivery(new_delivery.clone());

        Ok(new_delivery)
    }

    /// Get metrics
    pub fn get_metrics(&self) -> &WebhookMetrics {
        &self.metrics
    }

    /// Enable mock server for testing
    pub fn enable_mock_server(&mut self, config: MockServerConfig) {
        self.mock_server = Some(MockWebhookServer::new(config));
    }

    /// Get mock server
    pub fn mock_server_mut(&mut self) -> Option<&mut MockWebhookServer> {
        self.mock_server.as_mut()
    }
}

impl Default for WebhookManager {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookUpdate {
    pub url: Option<String>,
    pub events: Option<Vec<WebhookEventType>>,
    pub active: Option<bool>,
    pub filters: Option<WebhookFilters>,
    pub retry_config: Option<RetryConfig>,
}

#[derive(Debug, Serialize)]
struct WebhookBody<'a> {
    id: String,
    event_type: String,
    created_at: u64,
    data: &'a WebhookPayload,
}

// ============ Mock Webhook Server ============

#[derive(Debug, Clone)]
pub struct MockServerConfig {
    /// Default response status code
    pub default_status: u16,

    /// Default response body
    pub default_body: String,

    /// Simulate latency (ms)
    pub latency_ms: u64,

    /// Failure rate (0.0 - 1.0)
    pub failure_rate: f64,

    /// Timeout rate (0.0 - 1.0)
    pub timeout_rate: f64,
}

impl Default for MockServerConfig {
    fn default() -> Self {
        Self {
            default_status: 200,
            default_body: r#"{"success": true}"#.to_string(),
            latency_ms: 50,
            failure_rate: 0.0,
            timeout_rate: 0.0,
        }
    }
}

pub struct MockWebhookServer {
    config: MockServerConfig,
    received_requests: VecDeque<DeliveryRequest>,
    custom_responses: HashMap<String, MockResponse>,
    request_count: u64,
    max_stored_requests: usize,
}

#[derive(Debug, Clone)]
pub struct MockResponse {
    pub status_code: u16,
    pub headers: HashMap<String, String>,
    pub body: String,
    pub delay_ms: u64,
}

impl MockWebhookServer {
    pub fn new(config: MockServerConfig) -> Self {
        Self {
            config,
            received_requests: VecDeque::new(),
            custom_responses: HashMap::new(),
            request_count: 0,
            max_stored_requests: 1000,
        }
    }

    /// Handle incoming request
    pub fn handle_request(&self, request: &DeliveryRequest) -> (DeliveryStatus, Option<DeliveryResponse>, u64) {
        // Check for custom response by event type (from header)
        if let Some(event_type) = request.headers.get("X-Aethelred-Event") {
            if let Some(custom) = self.custom_responses.get(event_type) {
                return (
                    if custom.status_code >= 200 && custom.status_code < 300 {
                        DeliveryStatus::Delivered
                    } else {
                        DeliveryStatus::Failed
                    },
                    Some(DeliveryResponse {
                        status_code: custom.status_code,
                        headers: custom.headers.clone(),
                        body: custom.body.clone(),
                        latency_ms: custom.delay_ms,
                    }),
                    custom.delay_ms,
                );
            }
        }

        // Simulate failure
        let rand_val: f64 = (simple_hash(&format!("{}", self.request_count)) % 1000) as f64 / 1000.0;

        if rand_val < self.config.timeout_rate {
            return (DeliveryStatus::Failed, None, self.config.latency_ms * 10);
        }

        if rand_val < self.config.failure_rate {
            return (
                DeliveryStatus::Failed,
                Some(DeliveryResponse {
                    status_code: 500,
                    headers: HashMap::new(),
                    body: r#"{"error": "Internal server error"}"#.to_string(),
                    latency_ms: self.config.latency_ms,
                }),
                self.config.latency_ms,
            );
        }

        // Successful response
        (
            DeliveryStatus::Delivered,
            Some(DeliveryResponse {
                status_code: self.config.default_status,
                headers: HashMap::new(),
                body: self.config.default_body.clone(),
                latency_ms: self.config.latency_ms,
            }),
            self.config.latency_ms,
        )
    }

    /// Store received request
    pub fn store_request(&mut self, request: DeliveryRequest) {
        self.received_requests.push_front(request);
        self.request_count += 1;

        while self.received_requests.len() > self.max_stored_requests {
            self.received_requests.pop_back();
        }
    }

    /// Get received requests
    pub fn get_requests(&self, limit: usize) -> Vec<&DeliveryRequest> {
        self.received_requests.iter().take(limit).collect()
    }

    /// Get request count
    pub fn request_count(&self) -> u64 {
        self.request_count
    }

    /// Set custom response for event type
    pub fn set_response(&mut self, event_type: &str, response: MockResponse) {
        self.custom_responses.insert(event_type.to_string(), response);
    }

    /// Clear custom responses
    pub fn clear_responses(&mut self) {
        self.custom_responses.clear();
    }

    /// Clear received requests
    pub fn clear_requests(&mut self) {
        self.received_requests.clear();
    }

    /// Wait for N requests (blocking simulation)
    pub fn wait_for_requests(&self, count: u64, timeout_ms: u64) -> bool {
        // In a real implementation, this would use async/await
        self.request_count >= count
    }
}

// ============ Webhook Inspector ============

pub struct WebhookInspector {
    sessions: HashMap<String, InspectorSession>,
}

#[derive(Debug, Clone)]
pub struct InspectorSession {
    pub id: String,
    pub webhook_id: String,
    pub created_at: u64,
    pub captured_deliveries: Vec<WebhookDelivery>,
    pub filters: Option<InspectorFilters>,
    pub active: bool,
}

#[derive(Debug, Clone)]
pub struct InspectorFilters {
    pub event_types: Option<Vec<WebhookEventType>>,
    pub status: Option<Vec<DeliveryStatus>>,
    pub min_latency_ms: Option<u64>,
    pub max_latency_ms: Option<u64>,
}

impl WebhookInspector {
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
        }
    }

    /// Start inspector session
    pub fn start_session(&mut self, webhook_id: &str, filters: Option<InspectorFilters>) -> String {
        let session_id = format!("insp_{}", generate_id());

        self.sessions.insert(session_id.clone(), InspectorSession {
            id: session_id.clone(),
            webhook_id: webhook_id.to_string(),
            created_at: current_timestamp(),
            captured_deliveries: Vec::new(),
            filters,
            active: true,
        });

        session_id
    }

    /// Stop inspector session
    pub fn stop_session(&mut self, session_id: &str) -> Option<InspectorSession> {
        if let Some(session) = self.sessions.get_mut(session_id) {
            session.active = false;
        }
        self.sessions.get(session_id).cloned()
    }

    /// Capture delivery for active sessions
    pub fn capture_delivery(&mut self, delivery: &WebhookDelivery) {
        for session in self.sessions.values_mut() {
            if !session.active || session.webhook_id != delivery.webhook_id {
                continue;
            }

            // Apply filters
            if let Some(ref filters) = session.filters {
                if let Some(ref event_types) = filters.event_types {
                    let matches = event_types.iter()
                        .any(|e| e.as_str() == delivery.event.event_type.as_str());
                    if !matches {
                        continue;
                    }
                }

                if let Some(ref statuses) = filters.status {
                    if !statuses.contains(&delivery.status) {
                        continue;
                    }
                }

                if let Some(min_latency) = filters.min_latency_ms {
                    if delivery.duration_ms < min_latency {
                        continue;
                    }
                }

                if let Some(max_latency) = filters.max_latency_ms {
                    if delivery.duration_ms > max_latency {
                        continue;
                    }
                }
            }

            session.captured_deliveries.push(delivery.clone());
        }
    }

    /// Get session
    pub fn get_session(&self, session_id: &str) -> Option<&InspectorSession> {
        self.sessions.get(session_id)
    }

    /// List active sessions
    pub fn active_sessions(&self) -> Vec<&InspectorSession> {
        self.sessions.values().filter(|s| s.active).collect()
    }
}

impl Default for WebhookInspector {
    fn default() -> Self {
        Self::new()
    }
}

// ============ Webhook Metrics ============

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WebhookMetrics {
    pub events_emitted: u64,
    pub deliveries_attempted: u64,
    pub deliveries_succeeded: u64,
    pub deliveries_failed: u64,
    pub total_latency_ms: u64,
    pub retries_attempted: u64,

    /// Per-webhook metrics
    pub per_webhook: HashMap<String, WebhookStats>,

    /// Per-event metrics
    pub per_event: HashMap<String, EventStats>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WebhookStats {
    pub deliveries: u64,
    pub successes: u64,
    pub failures: u64,
    pub avg_latency_ms: f64,
    pub last_delivery_at: Option<u64>,
    pub last_status: Option<DeliveryStatus>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EventStats {
    pub total_emitted: u64,
    pub total_delivered: u64,
    pub avg_delivery_time_ms: f64,
}

impl WebhookMetrics {
    pub fn success_rate(&self) -> f64 {
        if self.deliveries_attempted == 0 {
            return 1.0;
        }
        self.deliveries_succeeded as f64 / self.deliveries_attempted as f64
    }

    pub fn average_latency_ms(&self) -> f64 {
        if self.deliveries_succeeded == 0 {
            return 0.0;
        }
        self.total_latency_ms as f64 / self.deliveries_succeeded as f64
    }
}

// ============ Webhook Testing Utilities ============

pub struct WebhookTester {
    manager: Arc<WebhookManager>,
}

impl WebhookTester {
    pub fn new(manager: Arc<WebhookManager>) -> Self {
        Self { manager }
    }

    /// Generate test event
    pub fn generate_test_event(&self, event_type: WebhookEventType) -> WebhookEvent {
        WebhookEvent {
            id: format!("evt_{}", generate_id()),
            event_type: event_type.clone(),
            payload: self.generate_test_payload(&event_type),
            block_number: 12345,
            block_hash: "0xabc123...".to_string(),
            timestamp: current_timestamp(),
            tx_hash: Some("0xdef456...".to_string()),
        }
    }

    fn generate_test_payload(&self, event_type: &WebhookEventType) -> WebhookPayload {
        match event_type {
            WebhookEventType::BlockCreated | WebhookEventType::BlockFinalized => {
                WebhookPayload::Block(BlockPayload {
                    number: 12345,
                    hash: "0xabc123...".to_string(),
                    parent_hash: "0xabc122...".to_string(),
                    timestamp: current_timestamp(),
                    transaction_count: 150,
                    gas_used: 15_000_000,
                    gas_limit: 30_000_000,
                    proposer: "aethelred1validator...".to_string(),
                })
            }
            WebhookEventType::TransactionConfirmed | WebhookEventType::TransactionSubmitted => {
                WebhookPayload::Transaction(TransactionPayload {
                    hash: "0xdef456...".to_string(),
                    from: "aethelred1sender...".to_string(),
                    to: Some("aethelred1receiver...".to_string()),
                    value: "1000000000000000000".to_string(),
                    gas_used: 21000,
                    gas_price: "1000000000".to_string(),
                    nonce: 42,
                    status: "success".to_string(),
                    block_number: 12345,
                    input_data: "0x".to_string(),
                    logs: vec![],
                })
            }
            WebhookEventType::SealCompleted | WebhookEventType::SealRequested => {
                WebhookPayload::Seal(SealPayload {
                    seal_id: "seal_abc123".to_string(),
                    model_hash: "0xmodel...".to_string(),
                    input_hash: "0xinput...".to_string(),
                    output_hash: Some("0xoutput...".to_string()),
                    requester: "aethelred1requester...".to_string(),
                    status: "completed".to_string(),
                    validators: vec!["aethelred1val1...".to_string()],
                    proofs: Some(vec!["proof1".to_string()]),
                })
            }
            _ => WebhookPayload::Custom(serde_json::json!({
                "test": true,
                "event_type": event_type.as_str()
            })),
        }
    }

    /// Verify webhook signature
    pub fn verify_signature(&self, body: &str, signature: &str, secret: &str) -> bool {
        let expected = format!("sha256={:x}", simple_hash(&format!("{}{}", body, secret)));
        signature == expected
    }
}

// ============ Load Testing ============

pub struct WebhookLoadTester {
    target_url: String,
    events_per_second: u32,
    duration_seconds: u32,
    results: Vec<LoadTestResult>,
}

#[derive(Debug, Clone)]
pub struct LoadTestResult {
    pub timestamp: u64,
    pub events_sent: u64,
    pub events_delivered: u64,
    pub events_failed: u64,
    pub avg_latency_ms: f64,
    pub p50_latency_ms: f64,
    pub p95_latency_ms: f64,
    pub p99_latency_ms: f64,
    pub errors: Vec<String>,
}

impl WebhookLoadTester {
    pub fn new(target_url: &str, events_per_second: u32, duration_seconds: u32) -> Self {
        Self {
            target_url: target_url.to_string(),
            events_per_second,
            duration_seconds,
            results: Vec::new(),
        }
    }

    /// Run load test (simulated)
    pub fn run(&mut self) -> LoadTestSummary {
        // Simulate load test results
        let total_events = self.events_per_second as u64 * self.duration_seconds as u64;

        LoadTestSummary {
            target_url: self.target_url.clone(),
            total_events_sent: total_events,
            total_events_delivered: (total_events as f64 * 0.98) as u64,
            total_events_failed: (total_events as f64 * 0.02) as u64,
            avg_latency_ms: 45.0,
            p50_latency_ms: 35.0,
            p95_latency_ms: 120.0,
            p99_latency_ms: 250.0,
            max_latency_ms: 500.0,
            events_per_second_achieved: self.events_per_second as f64 * 0.95,
            duration_seconds: self.duration_seconds,
            success_rate: 0.98,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadTestSummary {
    pub target_url: String,
    pub total_events_sent: u64,
    pub total_events_delivered: u64,
    pub total_events_failed: u64,
    pub avg_latency_ms: f64,
    pub p50_latency_ms: f64,
    pub p95_latency_ms: f64,
    pub p99_latency_ms: f64,
    pub max_latency_ms: f64,
    pub events_per_second_achieved: f64,
    pub duration_seconds: u32,
    pub success_rate: f64,
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

fn simple_hash(s: &str) -> u64 {
    let mut hash: u64 = 5381;
    for byte in s.bytes() {
        hash = hash.wrapping_mul(33).wrapping_add(byte as u64);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_webhook_registration() {
        let mut manager = WebhookManager::new();

        let config = WebhookConfig {
            id: "wh_test".to_string(),
            url: "https://example.com/webhook".to_string(),
            events: vec![WebhookEventType::BlockCreated],
            secret: "secret123".to_string(),
            filters: None,
            retry_config: RetryConfig::default(),
            custom_headers: HashMap::new(),
            active: true,
            created_at: current_timestamp(),
            owner: "test_owner".to_string(),
            description: Some("Test webhook".to_string()),
        };

        let id = manager.register_webhook(config).unwrap();
        assert_eq!(id, "wh_test");

        let webhook = manager.get_webhook("wh_test").unwrap();
        assert!(webhook.active);
    }

    #[test]
    fn test_event_emission() {
        let mut manager = WebhookManager::new();

        let config = WebhookConfig {
            id: "wh_test".to_string(),
            url: "https://example.com/webhook".to_string(),
            events: vec![WebhookEventType::BlockCreated],
            secret: "secret123".to_string(),
            filters: None,
            retry_config: RetryConfig::default(),
            custom_headers: HashMap::new(),
            active: true,
            created_at: current_timestamp(),
            owner: "test_owner".to_string(),
            description: None,
        };

        manager.register_webhook(config).unwrap();

        let event = WebhookEvent {
            id: "evt_1".to_string(),
            event_type: WebhookEventType::BlockCreated,
            payload: WebhookPayload::Block(BlockPayload {
                number: 1,
                hash: "0x...".to_string(),
                parent_hash: "0x...".to_string(),
                timestamp: current_timestamp(),
                transaction_count: 10,
                gas_used: 1000000,
                gas_limit: 15000000,
                proposer: "validator1".to_string(),
            }),
            block_number: 1,
            block_hash: "0x...".to_string(),
            timestamp: current_timestamp(),
            tx_hash: None,
        };

        manager.emit_event(event);
        let deliveries = manager.process_queue();

        assert_eq!(deliveries.len(), 1);
        assert_eq!(deliveries[0].status, DeliveryStatus::Delivered);
    }

    #[test]
    fn test_mock_server() {
        let mut server = MockWebhookServer::new(MockServerConfig {
            default_status: 200,
            default_body: r#"{"ok": true}"#.to_string(),
            latency_ms: 10,
            failure_rate: 0.0,
            timeout_rate: 0.0,
        });

        let request = DeliveryRequest {
            method: "POST".to_string(),
            url: "https://example.com/hook".to_string(),
            headers: HashMap::new(),
            body: "{}".to_string(),
            signature: "sha256=abc".to_string(),
        };

        let (status, response, _) = server.handle_request(&request);
        assert_eq!(status, DeliveryStatus::Delivered);
        assert!(response.is_some());
        assert_eq!(response.unwrap().status_code, 200);
    }
}
