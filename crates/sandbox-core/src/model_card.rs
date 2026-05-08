//! ML model card generator (Mitchell et al., 2018).
//!
//! Implements the IETF/Google standard model-card schema. Operators populate
//! a [`ModelCard`] structure and render it to:
//!
//! - **Markdown** — for documentation, knowledge bases.
//! - **JSON** — for programmatic ingestion (e.g. Hugging Face, MLflow).
//! - **Plain text** — for inclusion in audit packages.
//!
//! The schema covers: model details, intended use, factors, metrics, training
//! data, evaluation data, ethical considerations, and caveats. NIST AI RMF,
//! EU AI Act Art. 11, and SR 11-7 all expect this kind of artifact.

use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};

// =============================================================================
// ModelCard
// =============================================================================

/// Top-level model card.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ModelCard {
    /// Model identification.
    pub model_details: ModelDetails,
    /// Intended use.
    pub intended_use: IntendedUse,
    /// Relevant factors / cohorts.
    pub factors: Factors,
    /// Quantitative analyses (per-cohort metrics).
    pub metrics: Vec<Metric>,
    /// Training data summary.
    pub training_data: DataDescription,
    /// Evaluation data summary.
    pub evaluation_data: DataDescription,
    /// Ethical considerations.
    pub ethical_considerations: Vec<String>,
    /// Caveats and recommendations.
    pub caveats: Vec<String>,
}

// =============================================================================
// Sub-records
// =============================================================================

/// Model identification details.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct ModelDetails {
    /// Name (e.g. `"credit-risk-v3.2"`).
    pub name: String,
    /// Version semver string.
    pub version: String,
    /// Owner / responsible team.
    pub owner: String,
    /// Free-text description.
    pub description: String,
    /// Model type (e.g. `"gradient-boosted-trees"`).
    pub model_type: String,
    /// License (e.g. `"proprietary"`, `"apache-2.0"`).
    pub license: String,
    /// Citation if applicable.
    pub citation: Option<String>,
    /// Contact email.
    pub contact: Option<String>,
}

/// Intended use of the model.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct IntendedUse {
    /// Primary uses.
    pub primary_uses: Vec<String>,
    /// Out-of-scope uses.
    pub out_of_scope: Vec<String>,
    /// Primary intended users.
    pub primary_users: Vec<String>,
}

/// Factors / cohorts the model has been evaluated against.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct Factors {
    /// Relevant factors (e.g. `"age_band"`, `"region"`).
    pub relevant: Vec<String>,
    /// Evaluation factors.
    pub evaluation: Vec<String>,
}

/// One reported metric.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Metric {
    /// Metric name (e.g. `"AUC"`, `"F1"`).
    pub name: String,
    /// Metric value.
    pub value: f64,
    /// Unit (e.g. `"ratio"`, `"%"`).
    pub unit: String,
    /// Cohort the metric was measured on.
    pub cohort: Option<String>,
    /// Confidence interval if any.
    pub confidence_interval: Option<(f64, f64)>,
}

/// Description of a dataset.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct DataDescription {
    /// Source.
    pub source: String,
    /// Time range.
    pub time_range: Option<String>,
    /// Sample count.
    pub sample_count: Option<u64>,
    /// Preprocessing notes.
    pub preprocessing: Vec<String>,
    /// Demographic distribution as free-text.
    pub demographics: Option<String>,
}

// =============================================================================
// ModelCardBuilder
// =============================================================================

/// Builder for [`ModelCard`].
#[derive(Debug)]
pub struct ModelCardBuilder {
    card: ModelCard,
}

impl Default for ModelCardBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl ModelCardBuilder {
    /// New empty builder.
    pub fn new() -> Self {
        Self {
            card: ModelCard {
                model_details: ModelDetails::default(),
                intended_use: IntendedUse::default(),
                factors: Factors::default(),
                metrics: Vec::new(),
                training_data: DataDescription::default(),
                evaluation_data: DataDescription::default(),
                ethical_considerations: Vec::new(),
                caveats: Vec::new(),
            },
        }
    }

    /// Set details.
    pub fn details(mut self, d: ModelDetails) -> Self {
        self.card.model_details = d;
        self
    }

    /// Set intended use.
    pub fn intended_use(mut self, i: IntendedUse) -> Self {
        self.card.intended_use = i;
        self
    }

    /// Set factors.
    pub fn factors(mut self, f: Factors) -> Self {
        self.card.factors = f;
        self
    }

    /// Add a metric.
    pub fn metric(mut self, m: Metric) -> Self {
        self.card.metrics.push(m);
        self
    }

    /// Set training data.
    pub fn training_data(mut self, d: DataDescription) -> Self {
        self.card.training_data = d;
        self
    }

    /// Set evaluation data.
    pub fn evaluation_data(mut self, d: DataDescription) -> Self {
        self.card.evaluation_data = d;
        self
    }

    /// Add an ethical consideration.
    pub fn ethical(mut self, s: impl Into<String>) -> Self {
        self.card.ethical_considerations.push(s.into());
        self
    }

    /// Add a caveat.
    pub fn caveat(mut self, s: impl Into<String>) -> Self {
        self.card.caveats.push(s.into());
        self
    }

    /// Finalize.
    pub fn build(self) -> SandboxResult<ModelCard> {
        if self.card.model_details.name.is_empty() {
            return Err(SandboxError::Other("model card requires name".into()));
        }
        if self.card.model_details.version.is_empty() {
            return Err(SandboxError::Other("model card requires version".into()));
        }
        if self.card.model_details.owner.is_empty() {
            return Err(SandboxError::Other("model card requires owner".into()));
        }
        Ok(self.card)
    }
}

// =============================================================================
// Rendering
// =============================================================================

impl ModelCard {
    /// Render to Markdown.
    pub fn render_markdown(&self) -> String {
        let mut s = String::new();
        let d = &self.model_details;
        s.push_str(&format!("# Model Card — {}\n\n", d.name));
        s.push_str(&format!("- **Version:** {}\n", d.version));
        s.push_str(&format!("- **Owner:** {}\n", d.owner));
        s.push_str(&format!("- **Type:** {}\n", d.model_type));
        s.push_str(&format!("- **License:** {}\n", d.license));
        if let Some(c) = &d.contact {
            s.push_str(&format!("- **Contact:** {}\n", c));
        }
        s.push_str(&format!("\n{}\n\n", d.description));

        s.push_str("## Intended Use\n\n");
        for u in &self.intended_use.primary_uses {
            s.push_str(&format!("- {}\n", u));
        }
        if !self.intended_use.out_of_scope.is_empty() {
            s.push_str("\n### Out of Scope\n\n");
            for u in &self.intended_use.out_of_scope {
                s.push_str(&format!("- {}\n", u));
            }
        }
        if !self.intended_use.primary_users.is_empty() {
            s.push_str("\n### Primary Users\n\n");
            for u in &self.intended_use.primary_users {
                s.push_str(&format!("- {}\n", u));
            }
        }

        s.push_str("\n## Factors\n\n");
        s.push_str("**Relevant factors:** ");
        s.push_str(&self.factors.relevant.join(", "));
        s.push_str("\n\n");
        s.push_str("**Evaluation factors:** ");
        s.push_str(&self.factors.evaluation.join(", "));
        s.push_str("\n");

        s.push_str("\n## Metrics\n\n");
        for m in &self.metrics {
            let cohort = m
                .cohort
                .as_deref()
                .map(|c| format!(" ({})", c))
                .unwrap_or_default();
            s.push_str(&format!(
                "- **{}**{}: {} {}\n",
                m.name, cohort, m.value, m.unit
            ));
        }

        s.push_str("\n## Training Data\n\n");
        s.push_str(&format!("- **Source:** {}\n", self.training_data.source));
        if let Some(n) = self.training_data.sample_count {
            s.push_str(&format!("- **Samples:** {}\n", n));
        }

        s.push_str("\n## Evaluation Data\n\n");
        s.push_str(&format!("- **Source:** {}\n", self.evaluation_data.source));
        if let Some(n) = self.evaluation_data.sample_count {
            s.push_str(&format!("- **Samples:** {}\n", n));
        }

        if !self.ethical_considerations.is_empty() {
            s.push_str("\n## Ethical Considerations\n\n");
            for e in &self.ethical_considerations {
                s.push_str(&format!("- {}\n", e));
            }
        }
        if !self.caveats.is_empty() {
            s.push_str("\n## Caveats\n\n");
            for c in &self.caveats {
                s.push_str(&format!("- {}\n", c));
            }
        }
        s
    }

    /// Render to JSON (pretty-printed).
    pub fn render_json(&self) -> SandboxResult<String> {
        serde_json::to_string_pretty(self).map_err(|e| {
            SandboxError::Other(format!("model card json: {e}"))
        })
    }

    /// Render to plain text.
    pub fn render_plain(&self) -> String {
        // Strip Markdown markers for a simple plain version.
        self.render_markdown()
            .replace("# ", "")
            .replace("## ", "")
            .replace("### ", "")
            .replace("**", "")
            .replace("- ", "* ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn details() -> ModelDetails {
        ModelDetails {
            name: "credit-risk-v3.2".into(),
            version: "3.2.0".into(),
            owner: "ml-platform".into(),
            description: "Credit risk model.".into(),
            model_type: "gradient-boosted-trees".into(),
            license: "proprietary".into(),
            citation: None,
            contact: Some("ml@bank".into()),
        }
    }

    #[test]
    fn build_with_defaults_errors_without_name() {
        let r = ModelCardBuilder::new().build();
        assert!(r.is_err());
    }

    #[test]
    fn build_succeeds_with_required_fields() {
        let c = ModelCardBuilder::new()
            .details(details())
            .build()
            .unwrap();
        assert_eq!(c.model_details.name, "credit-risk-v3.2");
    }

    #[test]
    fn missing_version_errors() {
        let mut d = details();
        d.version = String::new();
        assert!(ModelCardBuilder::new().details(d).build().is_err());
    }

    #[test]
    fn missing_owner_errors() {
        let mut d = details();
        d.owner = String::new();
        assert!(ModelCardBuilder::new().details(d).build().is_err());
    }

    #[test]
    fn metric_added() {
        let c = ModelCardBuilder::new()
            .details(details())
            .metric(Metric {
                name: "AUC".into(),
                value: 0.83,
                unit: "ratio".into(),
                cohort: None,
                confidence_interval: None,
            })
            .build()
            .unwrap();
        assert_eq!(c.metrics.len(), 1);
    }

    #[test]
    fn render_markdown_contains_name() {
        let c = ModelCardBuilder::new()
            .details(details())
            .build()
            .unwrap();
        let md = c.render_markdown();
        assert!(md.contains("credit-risk-v3.2"));
        assert!(md.contains("# Model Card"));
    }

    #[test]
    fn render_markdown_lists_metrics() {
        let c = ModelCardBuilder::new()
            .details(details())
            .metric(Metric {
                name: "AUC".into(),
                value: 0.83,
                unit: "ratio".into(),
                cohort: Some("global".into()),
                confidence_interval: None,
            })
            .build()
            .unwrap();
        let md = c.render_markdown();
        assert!(md.contains("AUC"));
        assert!(md.contains("global"));
    }

    #[test]
    fn render_json_round_trips() {
        let c = ModelCardBuilder::new()
            .details(details())
            .build()
            .unwrap();
        let j = c.render_json().unwrap();
        let p: ModelCard = serde_json::from_str(&j).unwrap();
        assert_eq!(p, c);
    }

    #[test]
    fn plain_render_strips_markdown_markers() {
        let c = ModelCardBuilder::new()
            .details(details())
            .build()
            .unwrap();
        let txt = c.render_plain();
        assert!(!txt.contains("**"));
        assert!(!txt.contains("# "));
    }

    #[test]
    fn ethical_considerations_added() {
        let c = ModelCardBuilder::new()
            .details(details())
            .ethical("Trained on historical data — possible legacy bias.")
            .build()
            .unwrap();
        assert_eq!(c.ethical_considerations.len(), 1);
    }

    #[test]
    fn caveats_added() {
        let c = ModelCardBuilder::new()
            .details(details())
            .caveat("Not validated on dataset X.")
            .caveat("Re-validate after each retraining.")
            .build()
            .unwrap();
        assert_eq!(c.caveats.len(), 2);
    }

    #[test]
    fn intended_use_recorded() {
        let c = ModelCardBuilder::new()
            .details(details())
            .intended_use(IntendedUse {
                primary_uses: vec!["loan-decisioning".into()],
                out_of_scope: vec!["medical".into()],
                primary_users: vec!["bank ops".into()],
            })
            .build()
            .unwrap();
        assert_eq!(c.intended_use.primary_uses.len(), 1);
    }

    #[test]
    fn factors_recorded() {
        let c = ModelCardBuilder::new()
            .details(details())
            .factors(Factors {
                relevant: vec!["age_band".into(), "region".into()],
                evaluation: vec!["age_band".into()],
            })
            .build()
            .unwrap();
        assert_eq!(c.factors.relevant.len(), 2);
    }

    #[test]
    fn training_and_evaluation_data_recorded() {
        let c = ModelCardBuilder::new()
            .details(details())
            .training_data(DataDescription {
                source: "internal_2024".into(),
                time_range: Some("2024-01..2024-12".into()),
                sample_count: Some(120_000),
                preprocessing: vec![],
                demographics: None,
            })
            .evaluation_data(DataDescription {
                source: "holdout".into(),
                time_range: None,
                sample_count: Some(20_000),
                preprocessing: vec![],
                demographics: None,
            })
            .build()
            .unwrap();
        assert_eq!(c.training_data.sample_count, Some(120_000));
        assert_eq!(c.evaluation_data.sample_count, Some(20_000));
    }

    #[test]
    fn metric_serde() {
        let m = Metric {
            name: "AUC".into(),
            value: 0.83,
            unit: "ratio".into(),
            cohort: Some("c".into()),
            confidence_interval: Some((0.81, 0.85)),
        };
        let j = serde_json::to_string(&m).unwrap();
        let p: Metric = serde_json::from_str(&j).unwrap();
        assert_eq!(p, m);
    }

    #[test]
    fn data_description_serde() {
        let d = DataDescription {
            source: "x".into(),
            time_range: Some("y".into()),
            sample_count: Some(10),
            preprocessing: vec!["a".into()],
            demographics: Some("z".into()),
        };
        let j = serde_json::to_string(&d).unwrap();
        let p: DataDescription = serde_json::from_str(&j).unwrap();
        assert_eq!(p, d);
    }

    #[test]
    fn complete_card_serde() {
        let c = ModelCardBuilder::new()
            .details(details())
            .factors(Factors {
                relevant: vec!["x".into()],
                evaluation: vec!["x".into()],
            })
            .metric(Metric {
                name: "AUC".into(),
                value: 0.8,
                unit: "ratio".into(),
                cohort: None,
                confidence_interval: None,
            })
            .ethical("a")
            .caveat("b")
            .build()
            .unwrap();
        let j = serde_json::to_string(&c).unwrap();
        let p: ModelCard = serde_json::from_str(&j).unwrap();
        assert_eq!(p, c);
    }

    #[test]
    fn markdown_handles_empty_optionals() {
        let c = ModelCardBuilder::new()
            .details(ModelDetails {
                name: "x".into(),
                version: "1".into(),
                owner: "o".into(),
                description: "".into(),
                model_type: "".into(),
                license: "".into(),
                citation: None,
                contact: None,
            })
            .build()
            .unwrap();
        let md = c.render_markdown();
        assert!(md.contains("# Model Card"));
    }

    #[test]
    fn empty_metrics_section_still_renders() {
        let c = ModelCardBuilder::new()
            .details(details())
            .build()
            .unwrap();
        let md = c.render_markdown();
        assert!(md.contains("## Metrics"));
    }

    #[test]
    fn multi_metric_render() {
        let c = ModelCardBuilder::new()
            .details(details())
            .metric(Metric {
                name: "AUC".into(),
                value: 0.83,
                unit: "ratio".into(),
                cohort: None,
                confidence_interval: None,
            })
            .metric(Metric {
                name: "F1".into(),
                value: 0.71,
                unit: "ratio".into(),
                cohort: Some("subgroup-A".into()),
                confidence_interval: Some((0.69, 0.73)),
            })
            .build()
            .unwrap();
        let md = c.render_markdown();
        assert!(md.contains("AUC"));
        assert!(md.contains("F1"));
        assert!(md.contains("subgroup-A"));
    }

    #[test]
    fn confidence_interval_optional() {
        let c = ModelCardBuilder::new()
            .details(details())
            .metric(Metric {
                name: "AUC".into(),
                value: 0.83,
                unit: "ratio".into(),
                cohort: None,
                confidence_interval: None,
            })
            .build()
            .unwrap();
        assert!(c.metrics[0].confidence_interval.is_none());
    }
}
