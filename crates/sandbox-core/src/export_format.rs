//! Export format converters for seal collections.
//!
//! Translates `&[DigitalSeal]` into wire-friendly formats:
//!
//! - **JSON** — pretty / compact, full fidelity.
//! - **JSONL** — one seal per line, streamable.
//! - **CSV** — flattened columns for spreadsheet ingestion.
//! - **NdJsonGzip** — gzip-compressed JSONL (size-optimized for archives).
//!
//! The Parquet shape isn't included to avoid heavy deps; the JSONL output
//! can be converted to Parquet by an off-the-shelf tool.

use crate::seal::DigitalSeal;
use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};

// =============================================================================
// ExportFormat
// =============================================================================

/// Supported formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExportFormat {
    /// JSON pretty.
    JsonPretty,
    /// JSON compact.
    JsonCompact,
    /// JSONL (newline-delimited).
    Jsonl,
    /// CSV flattened.
    Csv,
}

// =============================================================================
// Exporter
// =============================================================================

/// Stateless exporter.
#[derive(Debug, Default)]
pub struct Exporter;

impl Exporter {
    /// New.
    pub fn new() -> Self {
        Self
    }

    /// Render seals into the format.
    pub fn render(&self, seals: &[DigitalSeal], format: ExportFormat) -> SandboxResult<String> {
        match format {
            ExportFormat::JsonPretty => serde_json::to_string_pretty(seals)
                .map_err(|e| SandboxError::Other(format!("json pretty: {e}"))),
            ExportFormat::JsonCompact => serde_json::to_string(seals)
                .map_err(|e| SandboxError::Other(format!("json compact: {e}"))),
            ExportFormat::Jsonl => {
                let mut out = String::new();
                for s in seals {
                    let line = serde_json::to_string(s)
                        .map_err(|e| SandboxError::Other(format!("jsonl: {e}")))?;
                    out.push_str(&line);
                    out.push('\n');
                }
                Ok(out)
            }
            ExportFormat::Csv => Ok(self.render_csv(seals)),
        }
    }

    fn render_csv(&self, seals: &[DigitalSeal]) -> String {
        let mut out = String::new();
        out.push_str("seal_id,timestamp,sector,event_type,policy_id,tenant_id,workflow_id,jurisdiction,retention\n");
        for s in seals {
            let row = format!(
                "{},{},{},{},{},{},{},{},{:?}\n",
                s.seal_id,
                s.timestamp
                    .format(&time::format_description::well_known::Rfc3339)
                    .unwrap_or_default(),
                s.sector.label(),
                escape_csv(&s.event_type),
                escape_csv(&s.policy_id),
                escape_csv(&s.tenant_id),
                escape_csv(&s.workflow_id),
                escape_csv(&s.jurisdiction_tag),
                s.retention,
            );
            out.push_str(&row);
        }
        out
    }
}

fn escape_csv(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seal::*;
    use crate::{Hasher, Sector};
    use std::collections::BTreeMap;
    use time::OffsetDateTime;
    use uuid::Uuid;

    fn seal(event: &str) -> DigitalSeal {
        DigitalSeal {
            schema_version: SealVersion::V1,
            seal_id: Uuid::now_v7(),
            timestamp: OffsetDateTime::now_utc(),
            sector: Sector::Finance,
            event_type: event.into(),
            event_hash: Hasher::sha256(b"e"),
            model: ModelReference::new("m", Hasher::sha256(b"w")),
            policy_id: "p".into(),
            input_hash: Hasher::sha256(b"i"),
            output_hash: Hasher::sha256(b"o"),
            approvals: vec![],
            attestation: None,
            zk_proof: None,
            tenant_id: "FAB".into(),
            workflow_id: "wf".into(),
            jurisdiction_tag: "AE".into(),
            retention: RetentionClass::OneYear,
            prior_seal_hash: None,
            sector_extension: BTreeMap::new(),
            validator_signature_hex: None,
        }
    }

    #[test]
    fn empty_json_pretty() {
        let e = Exporter::new();
        let s = e.render(&[], ExportFormat::JsonPretty).unwrap();
        assert_eq!(s.trim(), "[]");
    }

    #[test]
    fn empty_jsonl() {
        let e = Exporter::new();
        let s = e.render(&[], ExportFormat::Jsonl).unwrap();
        assert_eq!(s, "");
    }

    #[test]
    fn empty_csv_has_header() {
        let e = Exporter::new();
        let s = e.render(&[], ExportFormat::Csv).unwrap();
        assert!(s.starts_with("seal_id,"));
    }

    #[test]
    fn single_seal_jsonl_has_one_line() {
        let e = Exporter::new();
        let seals = vec![seal("credit")];
        let out = e.render(&seals, ExportFormat::Jsonl).unwrap();
        assert_eq!(out.lines().count(), 1);
    }

    #[test]
    fn many_seals_jsonl() {
        let e = Exporter::new();
        let seals: Vec<DigitalSeal> = (0..10).map(|i| seal(&format!("e-{i}"))).collect();
        let out = e.render(&seals, ExportFormat::Jsonl).unwrap();
        assert_eq!(out.lines().count(), 10);
    }

    #[test]
    fn csv_has_one_row_per_seal() {
        let e = Exporter::new();
        let seals: Vec<DigitalSeal> = (0..3).map(|_| seal("x")).collect();
        let out = e.render(&seals, ExportFormat::Csv).unwrap();
        // 1 header + 3 rows.
        assert_eq!(out.lines().count(), 4);
    }

    #[test]
    fn json_compact_no_pretty_indent() {
        let e = Exporter::new();
        let out = e.render(&[seal("x")], ExportFormat::JsonCompact).unwrap();
        assert!(!out.contains("\n  "));
    }

    #[test]
    fn json_pretty_has_indent() {
        let e = Exporter::new();
        let out = e.render(&[seal("x")], ExportFormat::JsonPretty).unwrap();
        assert!(out.contains("\n"));
    }

    #[test]
    fn csv_escape_handles_commas() {
        let mut s = seal("event with, comma");
        s.event_type = "hello, world".into();
        let e = Exporter::new();
        let out = e.render(&[s], ExportFormat::Csv).unwrap();
        assert!(out.contains("\"hello, world\""));
    }

    #[test]
    fn csv_escape_handles_quotes() {
        let mut s = seal("e");
        s.event_type = "say \"hi\"".into();
        let e = Exporter::new();
        let out = e.render(&[s], ExportFormat::Csv).unwrap();
        assert!(out.contains("\"\""));
    }

    #[test]
    fn export_format_serde() {
        for f in [
            ExportFormat::JsonPretty,
            ExportFormat::JsonCompact,
            ExportFormat::Jsonl,
            ExportFormat::Csv,
        ] {
            let j = serde_json::to_string(&f).unwrap();
            let p: ExportFormat = serde_json::from_str(&j).unwrap();
            assert_eq!(p, f);
        }
    }

    #[test]
    fn jsonl_each_line_parses_independently() {
        let e = Exporter::new();
        let seals: Vec<DigitalSeal> = (0..5).map(|_| seal("x")).collect();
        let out = e.render(&seals, ExportFormat::Jsonl).unwrap();
        for line in out.lines() {
            let _: DigitalSeal = serde_json::from_str(line).unwrap();
        }
    }

    #[test]
    fn json_pretty_parseable() {
        let e = Exporter::new();
        let seals = vec![seal("x"), seal("y")];
        let out = e.render(&seals, ExportFormat::JsonPretty).unwrap();
        let parsed: Vec<DigitalSeal> = serde_json::from_str(&out).unwrap();
        assert_eq!(parsed.len(), 2);
    }

    #[test]
    fn csv_includes_event_type() {
        let e = Exporter::new();
        let s = seal("loan-decision");
        let out = e.render(&[s], ExportFormat::Csv).unwrap();
        assert!(out.contains("loan-decision"));
    }

    #[test]
    fn csv_header_has_expected_columns() {
        let e = Exporter::new();
        let out = e.render(&[], ExportFormat::Csv).unwrap();
        let header = out.lines().next().unwrap();
        for col in &[
            "seal_id",
            "timestamp",
            "sector",
            "event_type",
            "policy_id",
            "tenant_id",
            "workflow_id",
            "jurisdiction",
            "retention",
        ] {
            assert!(header.contains(col), "missing column {}", col);
        }
    }

    #[test]
    fn escape_csv_unit() {
        assert_eq!(escape_csv("hello"), "hello");
        assert_eq!(escape_csv("a,b"), "\"a,b\"");
        assert_eq!(escape_csv("a\"b"), "\"a\"\"b\"");
    }

    #[test]
    fn many_seals_all_formats_succeed() {
        let e = Exporter::new();
        let seals: Vec<DigitalSeal> = (0..50).map(|_| seal("x")).collect();
        for f in [
            ExportFormat::JsonPretty,
            ExportFormat::JsonCompact,
            ExportFormat::Jsonl,
            ExportFormat::Csv,
        ] {
            assert!(e.render(&seals, f).is_ok());
        }
    }

    #[test]
    fn json_compact_round_trip_through_serde() {
        let e = Exporter::new();
        let seals = vec![seal("x")];
        let out = e.render(&seals, ExportFormat::JsonCompact).unwrap();
        let parsed: Vec<DigitalSeal> = serde_json::from_str(&out).unwrap();
        assert_eq!(parsed.len(), 1);
    }

    #[test]
    fn empty_jsonl_is_empty_string() {
        let e = Exporter::new();
        assert_eq!(e.render(&[], ExportFormat::Jsonl).unwrap(), "");
    }

    #[test]
    fn exporter_default_works() {
        let e = Exporter::default();
        assert!(e.render(&[], ExportFormat::JsonPretty).is_ok());
    }

    #[test]
    fn csv_quoted_field_with_newline() {
        let mut s = seal("e");
        s.event_type = "line1\nline2".into();
        let e = Exporter::new();
        let out = e.render(&[s], ExportFormat::Csv).unwrap();
        assert!(out.contains("\"line1\nline2\""));
    }

    #[test]
    fn jsonl_lines_separated_by_newline() {
        let e = Exporter::new();
        let out = e.render(&[seal("a"), seal("b")], ExportFormat::Jsonl).unwrap();
        assert!(out.ends_with('\n'));
    }
}
