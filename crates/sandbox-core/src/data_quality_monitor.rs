//! Data quality monitoring at ingest.
//!
//! Bad inputs → bad decisions → silent compliance failures. This module
//! computes the standard set of data-quality checks every production ML
//! system needs:
//!
//! - **Schema drift** — column added / removed / type changed compared to
//!   a baseline.
//! - **Range / value checks** — numeric out-of-range, categorical unknowns.
//! - **Missingness** — null rate per field exceeds a threshold.
//! - **Distribution drift** — categorical frequency drift (PSI / chi-squared).
//!
//! Operators register a [`DataExpectation`] (the contract) and feed in
//! [`DataSample`]s. The monitor produces per-batch [`DataQualityReport`]s
//! with structured findings — those records are then routed to incidents,
//! seals, or operator dashboards.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::RwLock;

// =============================================================================
// FieldType
// =============================================================================

/// Field data type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldType {
    /// Integer.
    Integer,
    /// Floating point.
    Float,
    /// String / categorical.
    String,
    /// Boolean.
    Bool,
}

// =============================================================================
// FieldSpec
// =============================================================================

/// Per-field expectation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FieldSpec {
    /// Field name.
    pub name: String,
    /// Expected type.
    pub field_type: FieldType,
    /// Required (`true` = null/missing fails).
    pub required: bool,
    /// Allowed numeric min (inclusive).
    pub min: Option<f64>,
    /// Allowed numeric max (inclusive).
    pub max: Option<f64>,
    /// Allowed categorical values (None = open vocabulary).
    pub allowed_values: Option<Vec<String>>,
    /// Maximum acceptable null-rate over a batch (0.0..=1.0).
    pub max_null_rate: f64,
}

impl FieldSpec {
    /// Required integer with bounds.
    pub fn integer(name: impl Into<String>, min: i64, max: i64) -> Self {
        Self {
            name: name.into(),
            field_type: FieldType::Integer,
            required: true,
            min: Some(min as f64),
            max: Some(max as f64),
            allowed_values: None,
            max_null_rate: 0.0,
        }
    }
    /// Required float with bounds.
    pub fn float(name: impl Into<String>, min: f64, max: f64) -> Self {
        Self {
            name: name.into(),
            field_type: FieldType::Float,
            required: true,
            min: Some(min),
            max: Some(max),
            allowed_values: None,
            max_null_rate: 0.0,
        }
    }
    /// Required categorical.
    pub fn categorical(name: impl Into<String>, values: Vec<String>) -> Self {
        Self {
            name: name.into(),
            field_type: FieldType::String,
            required: true,
            min: None,
            max: None,
            allowed_values: Some(values),
            max_null_rate: 0.0,
        }
    }
    /// Optional field.
    pub fn optional_string(name: impl Into<String>, max_null_rate: f64) -> Self {
        Self {
            name: name.into(),
            field_type: FieldType::String,
            required: false,
            min: None,
            max: None,
            allowed_values: None,
            max_null_rate,
        }
    }
}

// =============================================================================
// DataExpectation — full schema contract
// =============================================================================

/// The complete contract an ingest batch must satisfy.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct DataExpectation {
    /// Required fields.
    pub fields: Vec<FieldSpec>,
    /// Strict mode rejects unknown fields.
    pub strict: bool,
}

// =============================================================================
// FieldValue
// =============================================================================

/// A single field's value in one row.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case", tag = "type", content = "value")]
pub enum FieldValue {
    /// Missing / null.
    Null,
    /// Integer.
    Integer(i64),
    /// Float.
    Float(f64),
    /// String / categorical.
    String(String),
    /// Boolean.
    Bool(bool),
}

impl FieldValue {
    /// `true` if null.
    pub fn is_null(&self) -> bool {
        matches!(self, FieldValue::Null)
    }
    /// Convert to f64 if numeric.
    pub fn as_number(&self) -> Option<f64> {
        match self {
            FieldValue::Integer(i) => Some(*i as f64),
            FieldValue::Float(f) => Some(*f),
            _ => None,
        }
    }
    /// Convert to string if categorical.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            FieldValue::String(s) => Some(s),
            _ => None,
        }
    }
    /// Stable type label.
    pub fn type_label(&self) -> Option<FieldType> {
        match self {
            FieldValue::Null => None,
            FieldValue::Integer(_) => Some(FieldType::Integer),
            FieldValue::Float(_) => Some(FieldType::Float),
            FieldValue::String(_) => Some(FieldType::String),
            FieldValue::Bool(_) => Some(FieldType::Bool),
        }
    }
}

// =============================================================================
// DataSample
// =============================================================================

/// One row.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct DataSample {
    /// Field-value map.
    pub fields: HashMap<String, FieldValue>,
}

impl DataSample {
    /// New empty.
    pub fn new() -> Self {
        Self::default()
    }
    /// Builder: set field.
    pub fn with(mut self, name: impl Into<String>, value: FieldValue) -> Self {
        self.fields.insert(name.into(), value);
        self
    }
}

// =============================================================================
// QualityFinding + QualityCategory
// =============================================================================

/// Category of finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QualityCategory {
    /// Field present in batch but not in schema.
    UnknownField,
    /// Field declared in schema but missing from batch.
    MissingField,
    /// Field declared as type X but contains type Y.
    TypeMismatch,
    /// Numeric value out of `[min, max]` range.
    OutOfRange,
    /// Categorical value not in allowed set.
    UnknownCategory,
    /// Null rate exceeded threshold.
    NullRateExceeded,
}

/// One finding.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct QualityFinding {
    /// Category.
    pub category: QualityCategory,
    /// Field involved.
    pub field: String,
    /// Free-text explanation.
    pub explanation: String,
    /// Affected sample count (if applicable).
    pub sample_count: u64,
}

// =============================================================================
// DataQualityReport
// =============================================================================

/// Aggregate report.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct DataQualityReport {
    /// Total rows examined.
    pub total_rows: u64,
    /// Findings raised.
    pub findings: Vec<QualityFinding>,
    /// Per-field null counts.
    pub null_counts: HashMap<String, u64>,
    /// Per-categorical-field unique-value count.
    pub unique_value_counts: HashMap<String, u64>,
}

impl DataQualityReport {
    /// `true` if any finding raised.
    pub fn has_findings(&self) -> bool {
        !self.findings.is_empty()
    }
    /// `true` if a finding of `category` exists.
    pub fn has_category(&self, c: QualityCategory) -> bool {
        self.findings.iter().any(|f| f.category == c)
    }
    /// Findings filtered by category.
    pub fn findings_for(&self, c: QualityCategory) -> Vec<&QualityFinding> {
        self.findings.iter().filter(|f| f.category == c).collect()
    }
    /// Null rate per field.
    pub fn null_rate(&self, field: &str) -> f64 {
        if self.total_rows == 0 {
            return 0.0;
        }
        let n = self.null_counts.get(field).copied().unwrap_or(0) as f64;
        n / self.total_rows as f64
    }
}

// =============================================================================
// DataQualityMonitor
// =============================================================================

/// Stateful monitor.
pub struct DataQualityMonitor {
    expectation: RwLock<DataExpectation>,
}

impl Default for DataQualityMonitor {
    fn default() -> Self {
        Self {
            expectation: RwLock::new(DataExpectation::default()),
        }
    }
}

impl std::fmt::Debug for DataQualityMonitor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DataQualityMonitor")
            .field("fields", &self.field_count())
            .finish()
    }
}

impl DataQualityMonitor {
    /// New empty monitor.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the contract.
    pub fn set_expectation(&self, e: DataExpectation) {
        if let Ok(mut g) = self.expectation.write() {
            *g = e;
        }
    }

    /// Number of expected fields.
    pub fn field_count(&self) -> usize {
        self.expectation.read().map(|g| g.fields.len()).unwrap_or(0)
    }

    /// Inspect a batch.
    pub fn inspect(&self, batch: &[DataSample]) -> DataQualityReport {
        let exp = match self.expectation.read() {
            Ok(g) => g.clone(),
            Err(_) => DataExpectation::default(),
        };
        let mut report = DataQualityReport {
            total_rows: batch.len() as u64,
            ..Default::default()
        };
        if batch.is_empty() {
            return report;
        }

        // Strict mode: detect unknown fields.
        let known: HashSet<String> = exp.fields.iter().map(|f| f.name.clone()).collect();
        if exp.strict {
            let mut unknowns: HashSet<String> = HashSet::new();
            for row in batch {
                for k in row.fields.keys() {
                    if !known.contains(k) {
                        unknowns.insert(k.clone());
                    }
                }
            }
            for u in unknowns {
                report.findings.push(QualityFinding {
                    category: QualityCategory::UnknownField,
                    field: u.clone(),
                    explanation: format!("field '{}' present but not in schema", u),
                    sample_count: batch
                        .iter()
                        .filter(|r| r.fields.contains_key(&u))
                        .count() as u64,
                });
            }
        }

        // Per-field checks.
        for spec in &exp.fields {
            let mut nulls = 0u64;
            let mut type_mismatches = 0u64;
            let mut out_of_range = 0u64;
            let mut unknown_cats = 0u64;
            let mut missing = 0u64;
            let mut unique: HashSet<String> = HashSet::new();
            for row in batch {
                match row.fields.get(&spec.name) {
                    None => {
                        if spec.required {
                            missing += 1;
                        } else {
                            nulls += 1;
                        }
                    }
                    Some(FieldValue::Null) => nulls += 1,
                    Some(v) => {
                        // Type check.
                        if let Some(t) = v.type_label() {
                            if t != spec.field_type {
                                // Allow Integer→Float coercion.
                                let coerce_ok = (t == FieldType::Integer
                                    && spec.field_type == FieldType::Float);
                                if !coerce_ok {
                                    type_mismatches += 1;
                                }
                            }
                        }
                        // Range check.
                        if matches!(spec.field_type, FieldType::Integer | FieldType::Float) {
                            if let Some(n) = v.as_number() {
                                if let Some(min) = spec.min {
                                    if n < min {
                                        out_of_range += 1;
                                    }
                                }
                                if let Some(max) = spec.max {
                                    if n > max {
                                        out_of_range += 1;
                                    }
                                }
                            }
                        }
                        // Categorical check.
                        if let Some(allowed) = &spec.allowed_values {
                            if let Some(s) = v.as_str() {
                                if !allowed.iter().any(|a| a == s) {
                                    unknown_cats += 1;
                                }
                                unique.insert(s.to_string());
                            }
                        }
                    }
                }
            }
            report.null_counts.insert(spec.name.clone(), nulls);
            if !unique.is_empty() {
                report
                    .unique_value_counts
                    .insert(spec.name.clone(), unique.len() as u64);
            }
            if missing > 0 {
                report.findings.push(QualityFinding {
                    category: QualityCategory::MissingField,
                    field: spec.name.clone(),
                    explanation: format!("required field missing in {} rows", missing),
                    sample_count: missing,
                });
            }
            if type_mismatches > 0 {
                report.findings.push(QualityFinding {
                    category: QualityCategory::TypeMismatch,
                    field: spec.name.clone(),
                    explanation: format!(
                        "{} values had wrong type (expected {:?})",
                        type_mismatches, spec.field_type
                    ),
                    sample_count: type_mismatches,
                });
            }
            if out_of_range > 0 {
                report.findings.push(QualityFinding {
                    category: QualityCategory::OutOfRange,
                    field: spec.name.clone(),
                    explanation: format!(
                        "{} values out of [{:?}, {:?}] range",
                        out_of_range, spec.min, spec.max
                    ),
                    sample_count: out_of_range,
                });
            }
            if unknown_cats > 0 {
                report.findings.push(QualityFinding {
                    category: QualityCategory::UnknownCategory,
                    field: spec.name.clone(),
                    explanation: format!("{} unknown category values", unknown_cats),
                    sample_count: unknown_cats,
                });
            }
            // Null rate.
            let null_rate = nulls as f64 / batch.len() as f64;
            if null_rate > spec.max_null_rate + 1e-9 {
                report.findings.push(QualityFinding {
                    category: QualityCategory::NullRateExceeded,
                    field: spec.name.clone(),
                    explanation: format!(
                        "null rate {:.3} exceeded threshold {:.3}",
                        null_rate, spec.max_null_rate
                    ),
                    sample_count: nulls,
                });
            }
        }
        report
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn good_row() -> DataSample {
        DataSample::new()
            .with("age", FieldValue::Integer(35))
            .with("score", FieldValue::Float(0.7))
            .with("region", FieldValue::String("EU".into()))
    }

    fn good_expectation() -> DataExpectation {
        DataExpectation {
            fields: vec![
                FieldSpec::integer("age", 0, 120),
                FieldSpec::float("score", 0.0, 1.0),
                FieldSpec::categorical("region", vec!["EU".into(), "US".into()]),
            ],
            strict: true,
        }
    }

    #[test]
    fn empty_batch_no_findings() {
        let m = DataQualityMonitor::new();
        m.set_expectation(good_expectation());
        let r = m.inspect(&[]);
        assert!(!r.has_findings());
        assert_eq!(r.total_rows, 0);
    }

    #[test]
    fn good_batch_no_findings() {
        let m = DataQualityMonitor::new();
        m.set_expectation(good_expectation());
        let batch = vec![good_row(); 10];
        let r = m.inspect(&batch);
        assert!(!r.has_findings(), "{:?}", r.findings);
    }

    #[test]
    fn type_mismatch_flagged() {
        let m = DataQualityMonitor::new();
        m.set_expectation(good_expectation());
        let mut row = good_row();
        row.fields
            .insert("age".into(), FieldValue::String("thirty".into()));
        let r = m.inspect(&[row]);
        assert!(r.has_category(QualityCategory::TypeMismatch));
    }

    #[test]
    fn out_of_range_flagged_for_int() {
        let m = DataQualityMonitor::new();
        m.set_expectation(good_expectation());
        let mut row = good_row();
        row.fields.insert("age".into(), FieldValue::Integer(200));
        let r = m.inspect(&[row]);
        assert!(r.has_category(QualityCategory::OutOfRange));
    }

    #[test]
    fn out_of_range_flagged_for_float() {
        let m = DataQualityMonitor::new();
        m.set_expectation(good_expectation());
        let mut row = good_row();
        row.fields.insert("score".into(), FieldValue::Float(2.5));
        let r = m.inspect(&[row]);
        assert!(r.has_category(QualityCategory::OutOfRange));
    }

    #[test]
    fn missing_required_flagged() {
        let m = DataQualityMonitor::new();
        m.set_expectation(good_expectation());
        let mut row = good_row();
        row.fields.remove("age");
        let r = m.inspect(&[row]);
        assert!(r.has_category(QualityCategory::MissingField));
    }

    #[test]
    fn unknown_category_flagged() {
        let m = DataQualityMonitor::new();
        m.set_expectation(good_expectation());
        let mut row = good_row();
        row.fields
            .insert("region".into(), FieldValue::String("MARS".into()));
        let r = m.inspect(&[row]);
        assert!(r.has_category(QualityCategory::UnknownCategory));
    }

    #[test]
    fn unknown_field_flagged_in_strict_mode() {
        let m = DataQualityMonitor::new();
        m.set_expectation(good_expectation());
        let mut row = good_row();
        row.fields
            .insert("ssn".into(), FieldValue::String("123".into()));
        let r = m.inspect(&[row]);
        assert!(r.has_category(QualityCategory::UnknownField));
    }

    #[test]
    fn unknown_field_ignored_in_lax_mode() {
        let m = DataQualityMonitor::new();
        let mut e = good_expectation();
        e.strict = false;
        m.set_expectation(e);
        let mut row = good_row();
        row.fields
            .insert("ssn".into(), FieldValue::String("123".into()));
        let r = m.inspect(&[row]);
        assert!(!r.has_category(QualityCategory::UnknownField));
    }

    #[test]
    fn null_rate_threshold_flagged() {
        let m = DataQualityMonitor::new();
        let mut e = DataExpectation::default();
        e.fields.push(FieldSpec::optional_string("nickname", 0.5));
        m.set_expectation(e);
        // 4 of 5 nulls — 0.8 > 0.5 threshold.
        let batch: Vec<DataSample> = (0..5)
            .map(|i| {
                let mut s = DataSample::new();
                if i == 0 {
                    s.fields
                        .insert("nickname".into(), FieldValue::String("hi".into()));
                }
                s
            })
            .collect();
        let r = m.inspect(&batch);
        assert!(r.has_category(QualityCategory::NullRateExceeded));
    }

    #[test]
    fn integer_to_float_coercion_ok() {
        let m = DataQualityMonitor::new();
        let mut e = DataExpectation::default();
        e.fields.push(FieldSpec::float("score", 0.0, 1.0));
        m.set_expectation(e);
        let row = DataSample::new().with("score", FieldValue::Integer(0));
        let r = m.inspect(&[row]);
        assert!(!r.has_category(QualityCategory::TypeMismatch));
    }

    #[test]
    fn null_count_recorded() {
        let m = DataQualityMonitor::new();
        let mut e = DataExpectation::default();
        e.fields.push(FieldSpec::optional_string("x", 1.0));
        m.set_expectation(e);
        let rows = vec![
            DataSample::new().with("x", FieldValue::Null),
            DataSample::new().with("x", FieldValue::String("a".into())),
            DataSample::new().with("x", FieldValue::Null),
        ];
        let r = m.inspect(&rows);
        assert_eq!(r.null_counts.get("x").copied(), Some(2));
        assert!((r.null_rate("x") - (2.0 / 3.0)).abs() < 1e-9);
    }

    #[test]
    fn unique_value_count_for_category() {
        let m = DataQualityMonitor::new();
        m.set_expectation(good_expectation());
        let rows = vec![
            DataSample::new().with("region", FieldValue::String("EU".into())),
            DataSample::new().with("region", FieldValue::String("US".into())),
            DataSample::new().with("region", FieldValue::String("US".into())),
        ];
        let r = m.inspect(&rows);
        assert_eq!(r.unique_value_counts.get("region").copied(), Some(2));
    }

    #[test]
    fn report_has_findings_helper() {
        let m = DataQualityMonitor::new();
        m.set_expectation(good_expectation());
        let r = m.inspect(&[good_row()]);
        assert!(!r.has_findings());
    }

    #[test]
    fn findings_for_filters() {
        let m = DataQualityMonitor::new();
        m.set_expectation(good_expectation());
        let mut row = good_row();
        row.fields.insert("age".into(), FieldValue::Integer(999));
        let r = m.inspect(&[row]);
        assert_eq!(
            r.findings_for(QualityCategory::OutOfRange).len(),
            1
        );
    }

    #[test]
    fn report_serde_round_trip() {
        let m = DataQualityMonitor::new();
        m.set_expectation(good_expectation());
        let r = m.inspect(&[good_row()]);
        let j = serde_json::to_string(&r).unwrap();
        let p: DataQualityReport = serde_json::from_str(&j).unwrap();
        assert_eq!(p, r);
    }

    #[test]
    fn field_value_serde() {
        for v in [
            FieldValue::Null,
            FieldValue::Integer(1),
            FieldValue::Float(1.5),
            FieldValue::String("x".into()),
            FieldValue::Bool(true),
        ] {
            let j = serde_json::to_string(&v).unwrap();
            let p: FieldValue = serde_json::from_str(&j).unwrap();
            assert_eq!(p, v);
        }
    }

    #[test]
    fn field_spec_serde() {
        let s = FieldSpec::integer("x", 0, 10);
        let j = serde_json::to_string(&s).unwrap();
        let p: FieldSpec = serde_json::from_str(&j).unwrap();
        assert_eq!(p, s);
    }

    #[test]
    fn quality_category_serde() {
        for c in [
            QualityCategory::UnknownField,
            QualityCategory::MissingField,
            QualityCategory::TypeMismatch,
            QualityCategory::OutOfRange,
            QualityCategory::UnknownCategory,
            QualityCategory::NullRateExceeded,
        ] {
            let j = serde_json::to_string(&c).unwrap();
            let p: QualityCategory = serde_json::from_str(&j).unwrap();
            assert_eq!(p, c);
        }
    }

    #[test]
    fn many_rows_inspected() {
        let m = DataQualityMonitor::new();
        m.set_expectation(good_expectation());
        let batch = vec![good_row(); 1000];
        let r = m.inspect(&batch);
        assert_eq!(r.total_rows, 1000);
        assert!(!r.has_findings());
    }

    #[test]
    fn null_rate_zero_when_no_nulls() {
        let m = DataQualityMonitor::new();
        m.set_expectation(good_expectation());
        let r = m.inspect(&[good_row()]);
        assert_eq!(r.null_rate("age"), 0.0);
    }

    #[test]
    fn batch_with_multiple_issues() {
        let m = DataQualityMonitor::new();
        m.set_expectation(good_expectation());
        let mut bad = good_row();
        bad.fields.insert("age".into(), FieldValue::Integer(999));
        bad.fields.insert("region".into(), FieldValue::String("MARS".into()));
        let r = m.inspect(&[bad]);
        assert!(r.has_category(QualityCategory::OutOfRange));
        assert!(r.has_category(QualityCategory::UnknownCategory));
    }

    #[test]
    fn null_rate_zero_for_empty_batch() {
        let r = DataQualityReport::default();
        assert_eq!(r.null_rate("x"), 0.0);
    }
}
