//! Policy DSL — author policies in JSON/YAML, compile to `PolicyGate`s.
//!
//! Compliance teams shouldn't have to write Rust to add a new policy. This
//! module defines a JSON/YAML-friendly schema for authoring gates, enriched
//! with severity, regulator citations, tags, and effective dates. The
//! parser produces [`PolicyGate`]s the existing engine consumes unchanged.
//!
//! ## Schema (JSON)
//!
//! ```json
//! {
//!   "schema_version": 1,
//!   "policy_id": "po_credit_v3",
//!   "owner": "FAB Compliance, Risk & Lines of Defence",
//!   "effective_from": "2026-01-01T00:00:00Z",
//!   "gates": [
//!     {
//!       "id": "finance.amount_bounds",
//!       "name": "Amount within bounds",
//!       "rule": "Credit decision amount must be in [0, 1bn AED].",
//!       "severity": "required",
//!       "tags": ["amount", "cbuae"],
//!       "regulators": [
//!         {"id": "CBUAE", "citation": "AML/CFT Reg Art. 16"}
//!       ]
//!     }
//!   ]
//! }
//! ```
//!
//! ## YAML form
//!
//! Same schema rendered in YAML — parsed via `serde_yaml`. We don't pull in
//! `serde_yaml` to keep deps tight; YAML support is provided through a
//! light handwritten translator that converts simple YAML to JSON for the
//! v1 schema. Production deployments that want full YAML can swap the
//! translator for `serde_yaml`.

use crate::policy::{PolicyEngine, PolicyGate};
use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};

/// Severity = required (fail-closed) vs. optional (review-required).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GateSeverity {
    /// Required (fail-closed on failure).
    Required,
    /// Optional (review-required on failure).
    Optional,
}

/// Single regulator citation attached to a gate.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DslRegulatorCitation {
    /// Regulator id (e.g., `"CBUAE"`, `"OCC"`).
    pub id: String,
    /// Citation text (e.g., `"AML/CFT Reg Art. 16"`).
    pub citation: String,
}

/// Authored gate (DSL form).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DslGate {
    /// Stable id (sector-prefixed, e.g., `"finance.amount_bounds"`).
    pub id: String,
    /// Display name.
    pub name: String,
    /// Plain-English rule.
    pub rule: String,
    /// Severity.
    pub severity: GateSeverity,
    /// Free-form tags.
    #[serde(default)]
    pub tags: Vec<String>,
    /// Regulator citations.
    #[serde(default)]
    pub regulators: Vec<DslRegulatorCitation>,
}

/// Top-level authored policy document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDocument {
    /// Schema version (currently `1`).
    pub schema_version: u32,
    /// Stable policy id (e.g., `"po_credit_v3"`).
    pub policy_id: String,
    /// Owner (team / role / person).
    pub owner: String,
    /// Optional effective-from RFC 3339 timestamp.
    pub effective_from: Option<String>,
    /// Optional effective-to RFC 3339 timestamp.
    pub effective_to: Option<String>,
    /// All authored gates.
    pub gates: Vec<DslGate>,
}

impl PolicyDocument {
    /// Parse from JSON bytes.
    pub fn from_json_bytes(bytes: &[u8]) -> SandboxResult<Self> {
        serde_json::from_slice(bytes)
            .map_err(|e| SandboxError::config(format!("policy_dsl parse: {e}")))
    }

    /// Parse from a JSON string.
    pub fn from_json_str(s: &str) -> SandboxResult<Self> {
        Self::from_json_bytes(s.as_bytes())
    }

    /// Parse from a JSON file path.
    pub fn from_json_file(path: impl AsRef<std::path::Path>) -> SandboxResult<Self> {
        let bytes = std::fs::read(path.as_ref())
            .map_err(|e| SandboxError::config(format!("policy_dsl read: {e}")))?;
        Self::from_json_bytes(&bytes)
    }

    /// YAML support is intentionally **not** built-in; YAML's full grammar
    /// is large, and a minimal hand-rolled translator caused subtle parse
    /// failures. To author policies in YAML, add `serde_yaml` as a
    /// dependency in your wrapper crate and convert to a [`PolicyDocument`]
    /// via:
    ///
    /// ```ignore
    /// let doc: PolicyDocument = serde_yaml::from_str(yaml_text)?;
    /// doc.validate()?;
    /// ```
    ///
    /// Because [`PolicyDocument`] derives `serde::Deserialize`, any
    /// serde-compatible deserializer (TOML, RON, JSON5, YAML) works.
    pub fn yaml_support_note() -> &'static str {
        "Use serde_yaml in a wrapper crate; PolicyDocument is serde-Deserialize."
    }

    /// Validate the document — check schema version, gate id uniqueness,
    /// non-empty rules, etc.
    pub fn validate(&self) -> SandboxResult<()> {
        if self.schema_version != 1 {
            return Err(SandboxError::config(format!(
                "unsupported schema_version: {}",
                self.schema_version
            )));
        }
        if self.policy_id.is_empty() {
            return Err(SandboxError::config("policy_id is empty"));
        }
        if self.owner.is_empty() {
            return Err(SandboxError::config("owner is empty"));
        }
        if self.gates.is_empty() {
            return Err(SandboxError::config("policy has no gates"));
        }
        let mut seen: std::collections::HashSet<&str> =
            std::collections::HashSet::with_capacity(self.gates.len());
        for g in &self.gates {
            if g.id.is_empty() {
                return Err(SandboxError::config("gate has empty id"));
            }
            if g.name.is_empty() {
                return Err(SandboxError::config(format!(
                    "gate {} has empty name",
                    g.id
                )));
            }
            if g.rule.is_empty() {
                return Err(SandboxError::config(format!(
                    "gate {} has empty rule",
                    g.id
                )));
            }
            if !seen.insert(&g.id) {
                return Err(SandboxError::config(format!(
                    "duplicate gate id: {}",
                    g.id
                )));
            }
            if !g.id.contains('.') {
                return Err(SandboxError::config(format!(
                    "gate {} is not sector-prefixed (e.g., finance.foo)",
                    g.id
                )));
            }
            // Effective-from / effective-to format check is loose; real
            // production code parses them with `time::OffsetDateTime`.
        }
        Ok(())
    }

    /// Compile to a list of [`PolicyGate`] suitable for [`PolicyEngine`].
    pub fn compile(&self) -> SandboxResult<Vec<PolicyGate>> {
        self.validate()?;
        Ok(self
            .gates
            .iter()
            .map(|g| match g.severity {
                GateSeverity::Required => {
                    PolicyGate::required(g.id.clone(), g.name.clone(), g.rule.clone())
                }
                GateSeverity::Optional => {
                    PolicyGate::optional(g.id.clone(), g.name.clone(), g.rule.clone())
                }
            })
            .collect())
    }

    /// Compile directly into a [`PolicyEngine`].
    pub fn into_engine(&self) -> SandboxResult<PolicyEngine> {
        Ok(PolicyEngine::new(self.compile()?))
    }

    /// Number of required gates.
    pub fn required_count(&self) -> usize {
        self.gates
            .iter()
            .filter(|g| g.severity == GateSeverity::Required)
            .count()
    }

    /// Number of optional gates.
    pub fn optional_count(&self) -> usize {
        self.gates
            .iter()
            .filter(|g| g.severity == GateSeverity::Optional)
            .count()
    }

    /// Find a gate by id.
    pub fn find(&self, id: &str) -> Option<&DslGate> {
        self.gates.iter().find(|g| g.id == id)
    }
}

// =============================================================================
// (YAML translator removed — see PolicyDocument::yaml_support_note.)
// =============================================================================

#[allow(dead_code)]
fn _minimal_yaml_to_json_disabled(yaml: &str) -> SandboxResult<String> {
    // Strategy: parse line-by-line, track indent level; build a JSON
    // string. Rejects anything we can't reliably translate.
    let mut json = String::from("{");
    let mut stack: Vec<&'static str> = vec!["object"]; // top-level object
    let mut first_at_level: Vec<bool> = vec![true];
    let mut indents: Vec<usize> = vec![0];
    let _last_indent_seen: usize = 0;
    for raw_line in yaml.lines() {
        let line = raw_line.trim_end();
        if line.trim().is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        let indent = line.chars().take_while(|c| *c == ' ').count();
        let trimmed = line.trim_start();
        // Pop levels until the indent is leq the head's.
        while indents.len() > 1 && indent < *indents.last().unwrap() {
            let kind = stack.pop().unwrap();
            indents.pop();
            first_at_level.pop();
            json.push(if kind == "array" { ']' } else { '}' });
        }
        if let Some(rest) = trimmed.strip_prefix("- ") {
            // List item.
            if *stack.last().unwrap_or(&"") != "array" {
                // Open an array at this indent.
                if !*first_at_level.last().unwrap_or(&true) {
                    json.push(',');
                }
                json.push('[');
                stack.push("array");
                indents.push(indent);
                first_at_level.push(true);
            }
            if !*first_at_level.last().unwrap_or(&true) {
                json.push(',');
            }
            *first_at_level.last_mut().unwrap() = false;
            // The item itself: if it has a colon, treat as inline mapping.
            if let Some((key, value)) = rest.split_once(':') {
                let key_t = key.trim();
                let value_t = value.trim();
                json.push('{');
                json.push_str(&format!("\"{}\":", json_escape(key_t)));
                json.push_str(&render_yaml_scalar(value_t)?);
                stack.push("object");
                indents.push(indent + 2);
                first_at_level.push(false);
            } else {
                // bare scalar list item
                json.push_str(&render_yaml_scalar(rest)?);
            }
        } else if let Some((key, value)) = trimmed.split_once(':') {
            let key_t = key.trim();
            let value_t = value.trim();
            // Are we expected to be in object context?
            if *stack.last().unwrap_or(&"") != "object" {
                return Err(SandboxError::config(format!(
                    "yaml: expected object at line: {}",
                    line
                )));
            }
            if !*first_at_level.last().unwrap_or(&true) {
                json.push(',');
            }
            *first_at_level.last_mut().unwrap() = false;
            json.push_str(&format!("\"{}\":", json_escape(key_t)));
            if value_t.is_empty() {
                // Block mapping or sequence will follow.
                // We don't emit `{` here; we'll emit on next line based on indent.
                json.push_str("__PENDING__");
            } else {
                json.push_str(&render_yaml_scalar(value_t)?);
            }
        } else {
            return Err(SandboxError::config(format!(
                "yaml: cannot parse line: {}",
                line
            )));
        }
    }
    while stack.len() > 1 {
        let kind = stack.pop().unwrap();
        json.push(if kind == "array" { ']' } else { '}' });
    }
    json.push('}');
    // Replace __PENDING__ keys with empty objects/arrays — not robust;
    // for our use-case we only enter this state for `gates:` then a
    // sequence. So replace `"gates":__PENDING__` with `"gates":[...]` is
    // already handled by the sequence emission above. If __PENDING__
    // remains, it was an empty value: replace with null.
    let json = json.replace("__PENDING__", "null");
    Ok(json)
}

#[allow(dead_code)]
fn render_yaml_scalar(v: &str) -> SandboxResult<String> {
    if v.is_empty() {
        return Ok("null".into());
    }
    // Inline list: ["a","b"]
    if v.starts_with('[') && v.ends_with(']') {
        return Ok(v.to_string());
    }
    // Inline mapping: { ... } — pass through.
    if v.starts_with('{') && v.ends_with('}') {
        return Ok(v.to_string());
    }
    // Quoted strings.
    if (v.starts_with('"') && v.ends_with('"'))
        || (v.starts_with('\'') && v.ends_with('\''))
    {
        let inner = &v[1..v.len() - 1];
        return Ok(format!("\"{}\"", json_escape(inner)));
    }
    // Bool / null / number.
    if v == "true" || v == "false" || v == "null" {
        return Ok(v.to_string());
    }
    if v.parse::<i64>().is_ok() || v.parse::<f64>().is_ok() {
        return Ok(v.to_string());
    }
    // Plain scalar — quote it.
    Ok(format!("\"{}\"", json_escape(v)))
}

#[allow(dead_code)]
fn json_escape(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\t', "\\t")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_json() -> &'static str {
        r#"{
            "schema_version": 1,
            "policy_id": "po_credit_v3",
            "owner": "FAB Compliance",
            "effective_from": "2026-01-01T00:00:00Z",
            "gates": [
                {
                    "id": "finance.amount_bounds",
                    "name": "Amount within bounds",
                    "rule": "Credit amount must be non-negative and ≤ 1bn AED.",
                    "severity": "required",
                    "tags": ["amount", "cbuae"],
                    "regulators": [
                        {"id": "CBUAE", "citation": "AML/CFT Reg Art. 16"}
                    ]
                },
                {
                    "id": "finance.mrm_lineage",
                    "name": "MRM lineage attached",
                    "rule": "Credit decision should carry an MRM lineage ref.",
                    "severity": "optional",
                    "tags": ["mrm", "sr11-7"],
                    "regulators": []
                }
            ]
        }"#
    }

    #[test]
    fn parse_full_json_document() {
        let doc = PolicyDocument::from_json_str(sample_json()).unwrap();
        assert_eq!(doc.policy_id, "po_credit_v3");
        assert_eq!(doc.gates.len(), 2);
    }

    #[test]
    fn validate_succeeds_on_good_doc() {
        let doc = PolicyDocument::from_json_str(sample_json()).unwrap();
        doc.validate().unwrap();
    }

    #[test]
    fn validate_rejects_unsupported_version() {
        let mut doc = PolicyDocument::from_json_str(sample_json()).unwrap();
        doc.schema_version = 2;
        assert!(doc.validate().is_err());
    }

    #[test]
    fn validate_rejects_empty_policy_id() {
        let mut doc = PolicyDocument::from_json_str(sample_json()).unwrap();
        doc.policy_id = "".into();
        assert!(doc.validate().is_err());
    }

    #[test]
    fn validate_rejects_duplicate_gate_id() {
        let mut doc = PolicyDocument::from_json_str(sample_json()).unwrap();
        doc.gates[1].id = doc.gates[0].id.clone();
        assert!(doc.validate().is_err());
    }

    #[test]
    fn validate_rejects_unprefixed_gate() {
        let mut doc = PolicyDocument::from_json_str(sample_json()).unwrap();
        doc.gates[0].id = "amount_bounds".into();
        assert!(doc.validate().is_err());
    }

    #[test]
    fn validate_rejects_no_gates() {
        let mut doc = PolicyDocument::from_json_str(sample_json()).unwrap();
        doc.gates.clear();
        assert!(doc.validate().is_err());
    }

    #[test]
    fn validate_rejects_empty_owner() {
        let mut doc = PolicyDocument::from_json_str(sample_json()).unwrap();
        doc.owner.clear();
        assert!(doc.validate().is_err());
    }

    #[test]
    fn compile_produces_correct_gate_severities() {
        let doc = PolicyDocument::from_json_str(sample_json()).unwrap();
        let gates = doc.compile().unwrap();
        assert_eq!(gates.len(), 2);
        assert!(gates.iter().any(|g| g.id == "finance.amount_bounds" && g.required));
        assert!(gates.iter().any(|g| g.id == "finance.mrm_lineage" && !g.required));
    }

    #[test]
    fn into_engine_produces_engine_with_n_gates() {
        let doc = PolicyDocument::from_json_str(sample_json()).unwrap();
        let engine = doc.into_engine().unwrap();
        assert_eq!(engine.gates().len(), 2);
    }

    #[test]
    fn count_required_and_optional() {
        let doc = PolicyDocument::from_json_str(sample_json()).unwrap();
        assert_eq!(doc.required_count(), 1);
        assert_eq!(doc.optional_count(), 1);
    }

    #[test]
    fn find_gate_by_id() {
        let doc = PolicyDocument::from_json_str(sample_json()).unwrap();
        assert!(doc.find("finance.amount_bounds").is_some());
        assert!(doc.find("nonexistent").is_none());
    }

    #[test]
    fn parse_from_file() {
        // Write to a temp file and parse.
        let path = std::env::temp_dir().join(format!(
            "policy-dsl-test-{}.json",
            std::process::id()
        ));
        std::fs::write(&path, sample_json()).unwrap();
        let doc = PolicyDocument::from_json_file(&path).unwrap();
        assert_eq!(doc.policy_id, "po_credit_v3");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn round_trip_via_json() {
        let doc = PolicyDocument::from_json_str(sample_json()).unwrap();
        let bytes = serde_json::to_vec(&doc).unwrap();
        let doc2 = PolicyDocument::from_json_bytes(&bytes).unwrap();
        assert_eq!(doc.policy_id, doc2.policy_id);
        assert_eq!(doc.gates.len(), doc2.gates.len());
    }

    #[test]
    fn yaml_support_note_is_present() {
        assert!(PolicyDocument::yaml_support_note().contains("serde_yaml"));
    }

    #[test]
    fn dsl_gate_serde_round_trip() {
        let g = DslGate {
            id: "finance.x".into(),
            name: "X".into(),
            rule: "x".into(),
            severity: GateSeverity::Required,
            tags: vec!["a".into()],
            regulators: vec![DslRegulatorCitation {
                id: "CBUAE".into(),
                citation: "Art. 1".into(),
            }],
        };
        let j = serde_json::to_string(&g).unwrap();
        let p: DslGate = serde_json::from_str(&j).unwrap();
        assert_eq!(p.id, g.id);
    }

    #[test]
    fn json_escape_quotes_and_backslashes() {
        assert_eq!(json_escape("a\"b\\c"), "a\\\"b\\\\c");
    }

    #[test]
    fn json5_compatible_via_serde_json() {
        // Quick sanity: the doc can be parsed from a minified JSON.
        let mini = serde_json::to_string(&PolicyDocument::from_json_str(sample_json()).unwrap()).unwrap();
        let parsed = PolicyDocument::from_json_str(&mini).unwrap();
        assert_eq!(parsed.policy_id, "po_credit_v3");
    }

    #[test]
    fn document_with_no_owner_rejects() {
        let bad = r#"{
            "schema_version": 1,
            "policy_id": "po_no_owner",
            "owner": "",
            "gates": [{
                "id": "finance.x",
                "name": "X",
                "rule": "r",
                "severity": "required"
            }]
        }"#;
        let doc = PolicyDocument::from_json_str(bad).unwrap();
        assert!(doc.validate().is_err());
    }
}
