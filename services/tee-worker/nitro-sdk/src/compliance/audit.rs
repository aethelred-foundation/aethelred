//! # Audit Trail
//!
//! Immutable audit logging for compliance verification.

use super::*;
use std::collections::VecDeque;
use std::sync::{Arc, RwLock};
use std::time::SystemTime;

// ============================================================================
// Audit Trail
// ============================================================================

/// Audit trail for compliance operations
#[derive(Debug)]
pub struct AuditTrail {
    /// Audit entries
    entries: Arc<RwLock<VecDeque<AuditEntry>>>,

    /// Maximum entries to keep in memory
    max_entries: usize,

    /// Persistence backend (if configured)
    backend: Option<AuditBackend>,
}

impl AuditTrail {
    /// Create a new audit trail
    pub fn new() -> Self {
        AuditTrail {
            entries: Arc::new(RwLock::new(VecDeque::new())),
            max_entries: 10000,
            backend: None,
        }
    }

    /// Create with custom max entries
    pub fn with_max_entries(max_entries: usize) -> Self {
        AuditTrail {
            entries: Arc::new(RwLock::new(VecDeque::new())),
            max_entries,
            backend: None,
        }
    }

    /// Record an audit entry
    pub fn record(&self, entry: AuditEntry) {
        let mut entries = self.entries.write().unwrap();

        // Add entry
        entries.push_back(entry.clone());

        // Trim if necessary
        while entries.len() > self.max_entries {
            entries.pop_front();
        }

        // Persist if backend configured
        if let Some(ref backend) = self.backend {
            backend.persist(&entry);
        }
    }

    /// Get recent entries
    pub fn recent(&self, count: usize) -> Vec<AuditEntry> {
        let entries = self.entries.read().unwrap();
        entries.iter().rev().take(count).cloned().collect()
    }

    /// Search entries
    pub fn search(&self, query: &AuditQuery) -> Vec<AuditEntry> {
        let entries = self.entries.read().unwrap();

        entries
            .iter()
            .filter(|e| self.matches_query(e, query))
            .cloned()
            .collect()
    }

    /// Check if entry matches query
    fn matches_query(&self, entry: &AuditEntry, query: &AuditQuery) -> bool {
        // Check time range
        if let Some(from) = query.from {
            if entry.timestamp < from {
                return false;
            }
        }
        if let Some(to) = query.to {
            if entry.timestamp > to {
                return false;
            }
        }

        // Check actor
        if let Some(ref actor) = query.actor {
            if !entry.actor.contains(actor) {
                return false;
            }
        }

        // Check operation
        if let Some(ref operation) = query.operation {
            if !entry.operation.contains(operation) {
                return false;
            }
        }

        // Check jurisdiction
        if let Some(jurisdiction) = query.jurisdiction {
            if entry.jurisdiction != jurisdiction {
                return false;
            }
        }

        // Check result
        if let Some(result) = &query.result {
            if &entry.result != result {
                return false;
            }
        }

        true
    }

    /// Generate audit report
    pub fn generate_report(&self, config: &ReportConfig) -> AuditReport {
        let entries = self.search(&AuditQuery {
            from: config.from,
            to: config.to,
            actor: None,
            operation: None,
            jurisdiction: config.jurisdiction,
            result: None,
        });

        let total_operations = entries.len();
        let allowed_operations = entries
            .iter()
            .filter(|e| e.result == AuditResult::Allowed)
            .count();
        let denied_operations = entries
            .iter()
            .filter(|e| e.result == AuditResult::Denied)
            .count();

        // Count violations by type
        let mut violations_by_type = std::collections::HashMap::new();
        for entry in &entries {
            for violation in &entry.violations {
                *violations_by_type
                    .entry(violation.code.clone())
                    .or_insert(0) += 1;
            }
        }

        // Count by jurisdiction
        let mut by_jurisdiction = std::collections::HashMap::new();
        for entry in &entries {
            *by_jurisdiction.entry(entry.jurisdiction).or_insert(0) += 1;
        }

        // Count by actor
        let mut by_actor = std::collections::HashMap::new();
        for entry in &entries {
            *by_actor.entry(entry.actor.clone()).or_insert(0) += 1;
        }

        AuditReport {
            generated_at: SystemTime::now(),
            period_from: config.from,
            period_to: config.to,
            total_operations,
            allowed_operations,
            denied_operations,
            violations_by_type,
            operations_by_jurisdiction: by_jurisdiction,
            operations_by_actor: by_actor,
            sample_violations: entries
                .iter()
                .filter(|e| !e.violations.is_empty())
                .take(10)
                .cloned()
                .collect(),
        }
    }

    /// Export to JSON
    pub fn export_json(&self, query: &AuditQuery) -> String {
        let entries = self.search(query);
        serde_json::to_string_pretty(&entries).unwrap_or_default()
    }

    /// Get entry count
    pub fn count(&self) -> usize {
        self.entries.read().unwrap().len()
    }

    /// Clear all entries (use with caution!)
    pub fn clear(&self) {
        self.entries.write().unwrap().clear();
    }
}

impl Default for AuditTrail {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for AuditTrail {
    fn clone(&self) -> Self {
        AuditTrail {
            entries: Arc::clone(&self.entries),
            max_entries: self.max_entries,
            backend: None, // Backend not cloned
        }
    }
}

// ============================================================================
// Audit Entry
// ============================================================================

/// Single audit entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Timestamp
    pub timestamp: SystemTime,

    /// Operation type
    pub operation: String,

    /// Jurisdiction
    pub jurisdiction: Jurisdiction,

    /// Result
    pub result: AuditResult,

    /// Violations (if any)
    pub violations: Vec<ComplianceViolation>,

    /// Actor (user/service)
    pub actor: String,

    /// Additional metadata
    #[serde(default)]
    pub metadata: std::collections::HashMap<String, String>,
}

/// Audit result
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditResult {
    /// Operation was allowed
    Allowed,

    /// Operation was denied
    Denied,

    /// Operation was allowed with warnings
    AllowedWithWarnings,

    /// Operation requires review
    PendingReview,
}

// ============================================================================
// Audit Query
// ============================================================================

/// Query for searching audit entries
#[derive(Debug, Clone, Default)]
pub struct AuditQuery {
    /// Start time
    pub from: Option<SystemTime>,

    /// End time
    pub to: Option<SystemTime>,

    /// Actor filter
    pub actor: Option<String>,

    /// Operation filter
    pub operation: Option<String>,

    /// Jurisdiction filter
    pub jurisdiction: Option<Jurisdiction>,

    /// Result filter
    pub result: Option<AuditResult>,
}

impl AuditQuery {
    /// Create a new query
    pub fn new() -> Self {
        Self::default()
    }

    /// Filter by time range
    pub fn time_range(mut self, from: SystemTime, to: SystemTime) -> Self {
        self.from = Some(from);
        self.to = Some(to);
        self
    }

    /// Filter by actor
    pub fn actor(mut self, actor: &str) -> Self {
        self.actor = Some(actor.to_string());
        self
    }

    /// Filter by operation
    pub fn operation(mut self, operation: &str) -> Self {
        self.operation = Some(operation.to_string());
        self
    }

    /// Filter by jurisdiction
    pub fn jurisdiction(mut self, jurisdiction: Jurisdiction) -> Self {
        self.jurisdiction = Some(jurisdiction);
        self
    }

    /// Filter by result
    pub fn result(mut self, result: AuditResult) -> Self {
        self.result = Some(result);
        self
    }
}

// ============================================================================
// Audit Report
// ============================================================================

/// Configuration for generating reports
#[derive(Debug, Clone)]
pub struct ReportConfig {
    /// Start time
    pub from: Option<SystemTime>,

    /// End time
    pub to: Option<SystemTime>,

    /// Filter by jurisdiction
    pub jurisdiction: Option<Jurisdiction>,

    /// Include sample violations
    pub include_samples: bool,

    /// Maximum sample count
    pub max_samples: usize,
}

impl Default for ReportConfig {
    fn default() -> Self {
        ReportConfig {
            from: None,
            to: None,
            jurisdiction: None,
            include_samples: true,
            max_samples: 10,
        }
    }
}

/// Generated audit report
#[derive(Debug, Clone)]
pub struct AuditReport {
    /// When report was generated
    pub generated_at: SystemTime,

    /// Period start
    pub period_from: Option<SystemTime>,

    /// Period end
    pub period_to: Option<SystemTime>,

    /// Total operations
    pub total_operations: usize,

    /// Allowed operations
    pub allowed_operations: usize,

    /// Denied operations
    pub denied_operations: usize,

    /// Violations by type
    pub violations_by_type: std::collections::HashMap<String, usize>,

    /// Operations by jurisdiction
    pub operations_by_jurisdiction: std::collections::HashMap<Jurisdiction, usize>,

    /// Operations by actor
    pub operations_by_actor: std::collections::HashMap<String, usize>,

    /// Sample violations
    pub sample_violations: Vec<AuditEntry>,
}

impl AuditReport {
    /// Get compliance rate
    pub fn compliance_rate(&self) -> f64 {
        if self.total_operations == 0 {
            return 1.0;
        }
        self.allowed_operations as f64 / self.total_operations as f64
    }

    /// Generate text summary
    pub fn summary(&self) -> String {
        let mut summary = String::new();

        summary.push_str("=== Audit Report ===\n\n");
        summary.push_str(&format!("Total Operations: {}\n", self.total_operations));
        summary.push_str(&format!(
            "Allowed: {} ({:.1}%)\n",
            self.allowed_operations,
            self.compliance_rate() * 100.0
        ));
        summary.push_str(&format!("Denied: {}\n", self.denied_operations));

        if !self.violations_by_type.is_empty() {
            summary.push_str("\nTop Violations:\n");
            let mut violations: Vec<_> = self.violations_by_type.iter().collect();
            violations.sort_by(|a, b| b.1.cmp(a.1));
            for (code, count) in violations.iter().take(5) {
                summary.push_str(&format!("  - {}: {}\n", code, count));
            }
        }

        if !self.operations_by_jurisdiction.is_empty() {
            summary.push_str("\nBy Jurisdiction:\n");
            for (j, count) in &self.operations_by_jurisdiction {
                summary.push_str(&format!("  - {}: {}\n", j.display_name(), count));
            }
        }

        summary
    }
}

// ============================================================================
// Audit Backend (Persistence)
// ============================================================================

/// Audit persistence backend
#[derive(Debug)]
pub enum AuditBackend {
    /// File-based persistence
    File {
        /// Filesystem path used for audit log persistence.
        path: std::path::PathBuf,
    },

    /// Database persistence
    Database {
        /// Database connection string / DSN.
        connection_string: String,
    },

    /// Blockchain persistence (immutable)
    Blockchain {
        /// RPC/API endpoint for blockchain-backed audit persistence.
        endpoint: String,
    },

    /// Custom backend
    Custom,
}

impl AuditBackend {
    /// Persist an entry
    fn persist(&self, _entry: &AuditEntry) {
        // In production, implement actual persistence
        match self {
            AuditBackend::File { path: _ } => {
                // Append to file
            }
            AuditBackend::Database {
                connection_string: _,
            } => {
                // Insert into database
            }
            AuditBackend::Blockchain { endpoint: _ } => {
                // Submit to blockchain
            }
            AuditBackend::Custom => {
                // Custom implementation
            }
        }
    }
}

// ============================================================================
// Regulation (for serialization)
// ============================================================================

use serde::{Deserialize, Serialize};

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_trail_creation() {
        let trail = AuditTrail::new();
        assert_eq!(trail.count(), 0);
    }

    #[test]
    fn test_record_entry() {
        let trail = AuditTrail::new();

        trail.record(AuditEntry {
            timestamp: SystemTime::now(),
            operation: "process".to_string(),
            jurisdiction: Jurisdiction::UAE,
            result: AuditResult::Allowed,
            violations: vec![],
            actor: "test".to_string(),
            metadata: std::collections::HashMap::new(),
        });

        assert_eq!(trail.count(), 1);
    }

    #[test]
    fn test_search() {
        let trail = AuditTrail::new();

        trail.record(AuditEntry {
            timestamp: SystemTime::now(),
            operation: "process".to_string(),
            jurisdiction: Jurisdiction::UAE,
            result: AuditResult::Allowed,
            violations: vec![],
            actor: "alice".to_string(),
            metadata: std::collections::HashMap::new(),
        });

        trail.record(AuditEntry {
            timestamp: SystemTime::now(),
            operation: "export".to_string(),
            jurisdiction: Jurisdiction::EU,
            result: AuditResult::Denied,
            violations: vec![],
            actor: "bob".to_string(),
            metadata: std::collections::HashMap::new(),
        });

        let results = trail.search(&AuditQuery::new().actor("alice"));
        assert_eq!(results.len(), 1);

        let results = trail.search(&AuditQuery::new().jurisdiction(Jurisdiction::EU));
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_max_entries() {
        let trail = AuditTrail::with_max_entries(2);

        for i in 0..5 {
            trail.record(AuditEntry {
                timestamp: SystemTime::now(),
                operation: format!("op{}", i),
                jurisdiction: Jurisdiction::Global,
                result: AuditResult::Allowed,
                violations: vec![],
                actor: "test".to_string(),
                metadata: std::collections::HashMap::new(),
            });
        }

        assert_eq!(trail.count(), 2);
    }

    #[test]
    fn test_report_generation() {
        let trail = AuditTrail::new();

        for _ in 0..10 {
            trail.record(AuditEntry {
                timestamp: SystemTime::now(),
                operation: "process".to_string(),
                jurisdiction: Jurisdiction::UAE,
                result: AuditResult::Allowed,
                violations: vec![],
                actor: "test".to_string(),
                metadata: std::collections::HashMap::new(),
            });
        }

        let report = trail.generate_report(&ReportConfig::default());
        assert_eq!(report.total_operations, 10);
        assert_eq!(report.compliance_rate(), 1.0);
    }
}
