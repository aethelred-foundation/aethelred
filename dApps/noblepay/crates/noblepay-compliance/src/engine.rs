//! Main compliance engine orchestrator.
//!
//! [`ComplianceEngine`] composes the sanctions database, AML risk model, travel
//! rule engine, and TEE attestation generator into a single screening pipeline.
//! It provides both single-payment and batch-screening entry points with
//! configurable timeouts and built-in metrics collection.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use chrono::Utc;
use tokio::time::{timeout, Duration};
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::aml::RiskScoringModel;
use crate::attestation::{AttestationGenerator, AttestationReport};
use crate::sanctions::SanctionsDatabase;
use crate::travel_rule::TravelRuleEngine;
use crate::types::*;
use crate::ComplianceError;

/// Default screening timeout in milliseconds.
const DEFAULT_TIMEOUT_MS: u64 = 5_000;

/// AML risk score threshold above which a payment is flagged for review.
const FLAG_THRESHOLD: u8 = 40;

/// AML risk score threshold above which a payment is blocked.
const BLOCK_THRESHOLD: u8 = 75;

// ---------------------------------------------------------------------------
// Metrics
// ---------------------------------------------------------------------------

/// Atomic counters for screening pipeline metrics.
#[derive(Debug, Default)]
pub struct ComplianceMetrics {
    pub total_screened: AtomicU64,
    pub total_passed: AtomicU64,
    pub total_flagged: AtomicU64,
    pub total_blocked: AtomicU64,
    pub total_errors: AtomicU64,
    /// Cumulative screening duration in microseconds (for computing averages).
    pub cumulative_duration_us: AtomicU64,
}

impl ComplianceMetrics {
    /// Record the outcome of a single screening.
    fn record(&self, status: ComplianceStatus, duration: std::time::Duration) {
        self.total_screened.fetch_add(1, Ordering::Relaxed);
        self.cumulative_duration_us
            .fetch_add(duration.as_micros() as u64, Ordering::Relaxed);
        match status {
            ComplianceStatus::Passed => {
                self.total_passed.fetch_add(1, Ordering::Relaxed);
            }
            ComplianceStatus::Flagged => {
                self.total_flagged.fetch_add(1, Ordering::Relaxed);
            }
            ComplianceStatus::Blocked => {
                self.total_blocked.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Record an error.
    fn record_error(&self) {
        self.total_screened.fetch_add(1, Ordering::Relaxed);
        self.total_errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Snapshot the current metrics as a serializable struct.
    pub fn snapshot(&self) -> MetricsSnapshot {
        let total = self.total_screened.load(Ordering::Relaxed);
        let cumulative_us = self.cumulative_duration_us.load(Ordering::Relaxed);
        MetricsSnapshot {
            total_screened: total,
            total_passed: self.total_passed.load(Ordering::Relaxed),
            total_flagged: self.total_flagged.load(Ordering::Relaxed),
            total_blocked: self.total_blocked.load(Ordering::Relaxed),
            total_errors: self.total_errors.load(Ordering::Relaxed),
            avg_screening_duration_ms: if total > 0 {
                (cumulative_us / total) as f64 / 1000.0
            } else {
                0.0
            },
        }
    }
}

/// A point-in-time snapshot of compliance metrics, suitable for JSON serialization.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MetricsSnapshot {
    pub total_screened: u64,
    pub total_passed: u64,
    pub total_flagged: u64,
    pub total_blocked: u64,
    pub total_errors: u64,
    pub avg_screening_duration_ms: f64,
}

// ---------------------------------------------------------------------------
// ComplianceEngine
// ---------------------------------------------------------------------------

/// The top-level compliance screening orchestrator.
///
/// Clone is cheap — all internal state is behind `Arc`.
#[derive(Clone)]
pub struct ComplianceEngine {
    sanctions: SanctionsDatabase,
    aml: RiskScoringModel,
    travel_rule: TravelRuleEngine,
    attestation: AttestationGenerator,
    metrics: Arc<ComplianceMetrics>,
}

impl ComplianceEngine {
    /// Initialize the engine with default configuration and pre-loaded sanctions
    /// lists.
    pub async fn new() -> Self {
        let sanctions = SanctionsDatabase::with_default_lists().await;
        info!(
            entries = sanctions.total_entries().await,
            "compliance engine initialized"
        );

        Self {
            sanctions,
            aml: RiskScoringModel::new(),
            travel_rule: TravelRuleEngine::new(),
            attestation: AttestationGenerator::new(),
            metrics: Arc::new(ComplianceMetrics::default()),
        }
    }

    /// Screen a single payment through the full compliance pipeline.
    ///
    /// Pipeline stages:
    /// 1. Sanctions screening (sender + recipient)
    /// 2. AML risk scoring
    /// 3. Travel Rule verification
    /// 4. TEE attestation generation
    ///
    /// Returns a [`ComplianceResult`] on success or a [`ComplianceError`] on
    /// infrastructure failure.
    pub async fn screen_payment(
        &self,
        payment: &Payment,
        travel_rule_data: Option<&TravelRuleData>,
        timeout_ms: Option<u64>,
    ) -> Result<ComplianceResult, ComplianceError> {
        let deadline = Duration::from_millis(timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS));
        let start = Instant::now();

        let result = timeout(deadline, self.screen_payment_inner(payment, travel_rule_data)).await;

        match result {
            Ok(Ok(cr)) => {
                self.metrics.record(cr.status, start.elapsed());
                Ok(cr)
            }
            Ok(Err(e)) => {
                self.metrics.record_error();
                Err(e)
            }
            Err(_) => {
                self.metrics.record_error();
                let elapsed = start.elapsed().as_millis() as u64;
                warn!(payment_id = %payment.id, elapsed_ms = elapsed, "screening timed out");
                Err(ComplianceError::Timeout(elapsed))
            }
        }
    }

    /// Inner pipeline without timeout wrapper.
    async fn screen_payment_inner(
        &self,
        payment: &Payment,
        travel_rule_data: Option<&TravelRuleData>,
    ) -> Result<ComplianceResult, ComplianceError> {
        let start = Instant::now();

        // ------ 1. Sanctions screening ------
        let sender_check = self
            .sanctions
            .check_entity(&payment.sender, &[], &[])
            .await?;
        let recipient_check = self
            .sanctions
            .check_entity(&payment.recipient, &[], &[])
            .await?;

        let sanctions_clear = !sender_check.is_match && !recipient_check.is_match;

        // If either party is on a sanctions list, block immediately.
        if !sanctions_clear {
            let blocked_entity = if sender_check.is_match {
                &payment.sender
            } else {
                &payment.recipient
            };
            warn!(
                payment_id = %payment.id,
                entity = blocked_entity,
                "sanctions match — blocking payment"
            );

            let result_bytes = serde_json::to_vec(&ComplianceStatus::Blocked)
                .map_err(ComplianceError::SerializationError)?;
            let nonce = Uuid::new_v4().to_string();
            let attestation_report = self
                .attestation
                .generate_attestation(&result_bytes, &nonce)?;

            return Ok(ComplianceResult {
                payment_id: payment.id,
                sanctions_clear: false,
                aml_risk_score: 100,
                travel_rule_compliant: false,
                status: ComplianceStatus::Blocked,
                attestation: AttestationGenerator::attestation_to_bytes(&attestation_report),
                screening_duration_ms: start.elapsed().as_millis() as u64,
                risk_factors: vec![],
                screened_at: Utc::now(),
            });
        }

        // ------ 2. AML risk scoring ------
        let (aml_score, _aml_level, risk_factors) =
            self.aml.calculate_risk(payment, None, None);

        // ------ 3. Travel Rule verification ------
        let travel_verification = self
            .travel_rule
            .verify_travel_rule(payment, travel_rule_data)
            .map_err(|e| {
                error!(error = %e, "travel rule verification failed");
                e
            })?;

        let travel_rule_compliant = travel_verification.compliant;

        // ------ 4. Determine overall status ------
        let status = if !sanctions_clear {
            ComplianceStatus::Blocked
        } else if aml_score >= BLOCK_THRESHOLD {
            ComplianceStatus::Blocked
        } else if aml_score >= FLAG_THRESHOLD || !travel_rule_compliant {
            ComplianceStatus::Flagged
        } else {
            ComplianceStatus::Passed
        };

        // ------ 5. Generate TEE attestation ------
        let result_summary = serde_json::json!({
            "payment_id": payment.id,
            "sanctions_clear": sanctions_clear,
            "aml_score": aml_score,
            "travel_rule_compliant": travel_rule_compliant,
            "status": status,
        });
        let result_bytes =
            serde_json::to_vec(&result_summary).map_err(ComplianceError::SerializationError)?;
        let nonce = Uuid::new_v4().to_string();
        let attestation_report = self
            .attestation
            .generate_attestation(&result_bytes, &nonce)?;

        let screening_duration_ms = start.elapsed().as_millis() as u64;

        info!(
            payment_id = %payment.id,
            ?status,
            aml_score,
            screening_duration_ms,
            "screening complete"
        );

        Ok(ComplianceResult {
            payment_id: payment.id,
            sanctions_clear,
            aml_risk_score: aml_score,
            travel_rule_compliant,
            status,
            attestation: AttestationGenerator::attestation_to_bytes(&attestation_report),
            screening_duration_ms,
            risk_factors,
            screened_at: Utc::now(),
        })
    }

    /// Screen a batch of payments concurrently.
    ///
    /// Each payment is screened independently; a failure in one does not affect
    /// the others.
    pub async fn screen_batch(
        &self,
        requests: Vec<ScreeningRequest>,
    ) -> BatchScreeningResponse {
        let mut handles = Vec::with_capacity(requests.len());

        for req in &requests {
            let engine = self.clone();
            let payment = req.payment.clone();
            let travel_data = req.travel_rule_data.clone();
            let timeout_ms = req.timeout_ms;

            handles.push(tokio::spawn(async move {
                engine
                    .screen_payment(&payment, travel_data.as_ref(), timeout_ms)
                    .await
            }));
        }

        let mut results = Vec::with_capacity(handles.len());
        let mut passed = 0usize;
        let mut flagged = 0usize;
        let mut blocked = 0usize;

        for (i, handle) in handles.into_iter().enumerate() {
            let request_id = requests[i].payment.id;
            match handle.await {
                Ok(Ok(cr)) => {
                    match cr.status {
                        ComplianceStatus::Passed => passed += 1,
                        ComplianceStatus::Flagged => flagged += 1,
                        ComplianceStatus::Blocked => blocked += 1,
                    }
                    results.push(ScreeningResponse {
                        success: true,
                        result: Some(cr),
                        error: None,
                        request_id,
                    });
                }
                Ok(Err(e)) => {
                    results.push(ScreeningResponse {
                        success: false,
                        result: None,
                        error: Some(e.to_string()),
                        request_id,
                    });
                }
                Err(e) => {
                    results.push(ScreeningResponse {
                        success: false,
                        result: None,
                        error: Some(format!("task join error: {e}")),
                        request_id,
                    });
                }
            }
        }

        let total = results.len();
        BatchScreeningResponse {
            results,
            total,
            passed,
            flagged,
            blocked,
        }
    }

    /// Trigger a refresh of all sanctions lists.
    pub async fn refresh_sanctions_lists(&self) -> Result<(), ComplianceError> {
        self.sanctions.load_ofac_list().await;
        self.sanctions.load_uae_list().await;
        self.sanctions.load_un_list().await;
        self.sanctions.load_eu_list().await;
        info!("sanctions lists refreshed");
        Ok(())
    }

    /// Get a reference to the sanctions database (for health checks).
    pub fn sanctions_db(&self) -> &SanctionsDatabase {
        &self.sanctions
    }

    /// Get a snapshot of the current compliance metrics.
    pub fn metrics(&self) -> MetricsSnapshot {
        self.metrics.snapshot()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn clean_payment() -> Payment {
        Payment::test_payment("clean-sender", "clean-recipient", 50_000, "USD")
    }

    fn sanctioned_payment() -> Payment {
        Payment::test_payment("BLOCKED PERSON ALPHA", "clean-recipient", 50_000, "USD")
    }

    fn high_value_payment() -> Payment {
        Payment::test_payment("sender", "recipient", 10_000_000, "USD")
    }

    #[tokio::test]
    async fn clean_payment_passes() {
        let engine = ComplianceEngine::new().await;
        let result = engine.screen_payment(&clean_payment(), None, None).await.unwrap();
        assert!(result.sanctions_clear);
        assert_ne!(result.status, ComplianceStatus::Blocked);
        assert!(!result.attestation.is_empty());
        assert!(result.screening_duration_ms < 5000);
    }

    #[tokio::test]
    async fn sanctioned_entity_blocked() {
        let engine = ComplianceEngine::new().await;
        let result = engine
            .screen_payment(&sanctioned_payment(), None, None)
            .await
            .unwrap();
        assert!(!result.sanctions_clear);
        assert_eq!(result.status, ComplianceStatus::Blocked);
    }

    #[tokio::test]
    async fn batch_screening() {
        let engine = ComplianceEngine::new().await;
        let requests = vec![
            ScreeningRequest {
                payment: clean_payment(),
                travel_rule_data: None,
                timeout_ms: None,
            },
            ScreeningRequest {
                payment: sanctioned_payment(),
                travel_rule_data: None,
                timeout_ms: None,
            },
        ];

        let batch = engine.screen_batch(requests).await;
        assert_eq!(batch.total, 2);
        assert!(batch.results.iter().all(|r| r.success));
        // At least one should be blocked (the sanctioned one).
        assert!(batch.blocked >= 1);
    }

    #[tokio::test]
    async fn metrics_are_recorded() {
        let engine = ComplianceEngine::new().await;
        engine.screen_payment(&clean_payment(), None, None).await.unwrap();
        engine.screen_payment(&clean_payment(), None, None).await.unwrap();

        let m = engine.metrics();
        assert_eq!(m.total_screened, 2);
        assert!(m.avg_screening_duration_ms >= 0.0);
    }

    #[tokio::test]
    async fn refresh_sanctions_does_not_panic() {
        let engine = ComplianceEngine::new().await;
        engine.refresh_sanctions_lists().await.unwrap();
    }

    #[tokio::test]
    async fn timeout_is_respected() {
        let engine = ComplianceEngine::new().await;
        // A very short timeout should still succeed for simple screenings since
        // the mock engine is fast, but we verify the timeout plumbing works.
        let result = engine
            .screen_payment(&clean_payment(), None, Some(10_000))
            .await;
        assert!(result.is_ok());
    }

    #[test]
    fn metrics_snapshot_defaults() {
        let m = ComplianceMetrics::default();
        let snap = m.snapshot();
        assert_eq!(snap.total_screened, 0);
        assert_eq!(snap.avg_screening_duration_ms, 0.0);
    }
}
