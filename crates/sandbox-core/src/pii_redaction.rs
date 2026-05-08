//! PII redaction policy engine.
//!
//! Operators can declare a set of [`PiiRule`]s and apply them via
//! [`PiiRedactor`] to clean text before sealing or display. Rules use a
//! deterministic regex-style match (the engine here is a simple substring
//! and length-window scanner — production deployments swap in `regex` or
//! `aho-corasick` for richer patterns).
//!
//! Each redaction produces a [`RedactionRecord`] tracking what was hidden
//! so auditors can verify the redactor was applied without exposing the raw
//! values.
//!
//! ## Built-in patterns
//!
//! - Email addresses (presence of `@`).
//! - Long digit runs (potentially card numbers / SSN / IBAN).
//! - "PAN-like" 13–19 digit groups.
//!
//! ## Mask
//!
//! By default redactions are replaced with `[REDACTED:<class>]`. Operators
//! can supply a custom mask string per-rule.

use crate::hashing::{Hasher, Sha256Digest};
use serde::{Deserialize, Serialize};
use std::sync::Mutex;

// =============================================================================
// SensitivityClass
// =============================================================================

/// Categories of redacted content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SensitivityClass {
    /// Email.
    Email,
    /// Card / PAN.
    PaymentCard,
    /// Long digit run that may be SSN / national id.
    NationalId,
    /// Custom pattern.
    Custom,
}

impl SensitivityClass {
    /// Stable label.
    pub fn label(self) -> &'static str {
        match self {
            Self::Email => "email",
            Self::PaymentCard => "payment_card",
            Self::NationalId => "national_id",
            Self::Custom => "custom",
        }
    }
}

// =============================================================================
// PiiRule
// =============================================================================

/// One redaction rule.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PiiRule {
    /// Rule id (free-form, used for audit).
    pub id: String,
    /// Sensitivity class.
    pub class: SensitivityClass,
    /// Mask to substitute (defaults to `[REDACTED:<class>]`).
    pub mask: Option<String>,
    /// Optional custom substring trigger (used for [`SensitivityClass::Custom`]).
    pub substring_trigger: Option<String>,
}

impl PiiRule {
    /// Email rule.
    pub fn email() -> Self {
        Self {
            id: "builtin.email".into(),
            class: SensitivityClass::Email,
            mask: None,
            substring_trigger: None,
        }
    }

    /// Payment-card rule.
    pub fn payment_card() -> Self {
        Self {
            id: "builtin.pan".into(),
            class: SensitivityClass::PaymentCard,
            mask: None,
            substring_trigger: None,
        }
    }

    /// National-id rule.
    pub fn national_id() -> Self {
        Self {
            id: "builtin.national_id".into(),
            class: SensitivityClass::NationalId,
            mask: None,
            substring_trigger: None,
        }
    }

    /// Custom substring rule.
    pub fn custom_substring(id: impl Into<String>, sub: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            class: SensitivityClass::Custom,
            mask: None,
            substring_trigger: Some(sub.into()),
        }
    }

    /// Mask string used.
    pub fn mask_string(&self) -> String {
        self.mask
            .clone()
            .unwrap_or_else(|| format!("[REDACTED:{}]", self.class.label()))
    }
}

// =============================================================================
// RedactionRecord
// =============================================================================

/// One redaction event.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RedactionRecord {
    /// Rule id that fired.
    pub rule_id: String,
    /// Sensitivity class.
    pub class: SensitivityClass,
    /// Hash of the original value (so auditors can verify match without
    /// seeing the raw value).
    pub original_hash: Sha256Digest,
    /// Length of the original.
    pub original_length: u64,
    /// Byte offset in the input where the redaction occurred.
    pub offset: usize,
}

// =============================================================================
// RedactionResult
// =============================================================================

/// Result of redacting one input.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RedactionResult {
    /// Cleaned text.
    pub cleaned: String,
    /// Per-redaction record.
    pub records: Vec<RedactionRecord>,
}

impl RedactionResult {
    /// `true` if at least one redaction happened.
    pub fn was_redacted(&self) -> bool {
        !self.records.is_empty()
    }
    /// Count by class.
    pub fn count_for(&self, class: SensitivityClass) -> usize {
        self.records.iter().filter(|r| r.class == class).count()
    }
}

// =============================================================================
// PiiRedactor
// =============================================================================

/// Stateful redactor.
pub struct PiiRedactor {
    rules: Mutex<Vec<PiiRule>>,
}

impl Default for PiiRedactor {
    fn default() -> Self {
        let r = Self::new();
        r.add_rule(PiiRule::email());
        r.add_rule(PiiRule::payment_card());
        r.add_rule(PiiRule::national_id());
        r
    }
}

impl std::fmt::Debug for PiiRedactor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PiiRedactor")
            .field("rules", &self.rule_count())
            .finish()
    }
}

impl PiiRedactor {
    /// New empty redactor.
    pub fn new() -> Self {
        Self {
            rules: Mutex::new(Vec::new()),
        }
    }

    /// Add a rule.
    pub fn add_rule(&self, r: PiiRule) {
        if let Ok(mut g) = self.rules.lock() {
            g.push(r);
        }
    }

    /// Number of rules.
    pub fn rule_count(&self) -> usize {
        self.rules.lock().map(|g| g.len()).unwrap_or(0)
    }

    /// Apply rules to `input`.
    pub fn redact(&self, input: &str) -> RedactionResult {
        let rules = match self.rules.lock() {
            Ok(g) => g.clone(),
            Err(_) => Vec::new(),
        };
        let mut records = Vec::new();
        let mut tokens = tokenize(input);
        for rule in &rules {
            for tok in &mut tokens {
                if tok.redacted {
                    continue;
                }
                let m = rule_matches(rule, &tok.text);
                if m {
                    let hash = Hasher::sha256(tok.text.as_bytes());
                    records.push(RedactionRecord {
                        rule_id: rule.id.clone(),
                        class: rule.class,
                        original_hash: hash,
                        original_length: tok.text.len() as u64,
                        offset: tok.offset,
                    });
                    tok.text = rule.mask_string();
                    tok.redacted = true;
                }
            }
        }
        let cleaned: String = tokens.iter().map(|t| t.render()).collect();
        RedactionResult { cleaned, records }
    }
}

#[derive(Debug)]
struct Token {
    text: String,
    offset: usize,
    delim_after: String,
    redacted: bool,
}

impl Token {
    fn render(&self) -> String {
        let mut s = self.text.clone();
        s.push_str(&self.delim_after);
        s
    }
}

fn tokenize(s: &str) -> Vec<Token> {
    // Split on whitespace; keep trailing whitespace per-token to round-trip the input.
    let mut tokens = Vec::new();
    let bytes = s.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        // Walk a token (non-whitespace).
        let start = i;
        while i < bytes.len() && !is_ws(bytes[i]) {
            i += 1;
        }
        let text = std::str::from_utf8(&bytes[start..i]).unwrap_or("").to_string();
        // Walk delimiters.
        let dstart = i;
        while i < bytes.len() && is_ws(bytes[i]) {
            i += 1;
        }
        let delim = std::str::from_utf8(&bytes[dstart..i])
            .unwrap_or("")
            .to_string();
        tokens.push(Token {
            text,
            offset: start,
            delim_after: delim,
            redacted: false,
        });
    }
    tokens
}

fn is_ws(b: u8) -> bool {
    b == b' ' || b == b'\t' || b == b'\n' || b == b'\r'
}

fn rule_matches(rule: &PiiRule, token: &str) -> bool {
    match rule.class {
        SensitivityClass::Email => looks_like_email(token),
        SensitivityClass::PaymentCard => looks_like_pan(token),
        SensitivityClass::NationalId => looks_like_national_id(token),
        SensitivityClass::Custom => match &rule.substring_trigger {
            Some(s) => token.contains(s),
            None => false,
        },
    }
}

fn looks_like_email(s: &str) -> bool {
    let at = s.matches('@').count();
    if at != 1 {
        return false;
    }
    let parts: Vec<&str> = s.split('@').collect();
    if parts[0].is_empty() || parts[1].is_empty() {
        return false;
    }
    parts[1].contains('.')
}

fn looks_like_pan(s: &str) -> bool {
    let digits: Vec<char> = s.chars().filter(|c| c.is_ascii_digit()).collect();
    let n = digits.len();
    n >= 13 && n <= 19 && s.chars().all(|c| c.is_ascii_digit() || c == '-' || c == ' ')
}

fn looks_like_national_id(s: &str) -> bool {
    let digits: Vec<char> = s.chars().filter(|c| c.is_ascii_digit()).collect();
    // 9–12 digit run, all digits or with dashes.
    let n = digits.len();
    n >= 9 && n <= 12 && s.chars().all(|c| c.is_ascii_digit() || c == '-')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn email_redacted() {
        let r = PiiRedactor::default();
        let res = r.redact("hello alice@bank.com world");
        assert!(res.was_redacted());
        assert!(res.cleaned.contains("[REDACTED:email]"));
        assert_eq!(res.count_for(SensitivityClass::Email), 1);
    }

    #[test]
    fn payment_card_redacted() {
        let r = PiiRedactor::default();
        let res = r.redact("Pay 4111111111111111 now");
        assert!(res.was_redacted());
        assert_eq!(res.count_for(SensitivityClass::PaymentCard), 1);
    }

    #[test]
    fn payment_card_with_dashes_redacted() {
        let r = PiiRedactor::default();
        let res = r.redact("4111-1111-1111-1111");
        assert_eq!(res.count_for(SensitivityClass::PaymentCard), 1);
    }

    #[test]
    fn national_id_redacted() {
        let r = PiiRedactor::default();
        let res = r.redact("ssn 123456789");
        assert_eq!(res.count_for(SensitivityClass::NationalId), 1);
    }

    #[test]
    fn no_pii_no_redaction() {
        let r = PiiRedactor::default();
        let res = r.redact("hello world");
        assert!(!res.was_redacted());
        assert_eq!(res.cleaned, "hello world");
    }

    #[test]
    fn multiple_emails_redacted() {
        let r = PiiRedactor::default();
        let res = r.redact("a@b.com c@d.org e@f.net");
        assert_eq!(res.count_for(SensitivityClass::Email), 3);
    }

    #[test]
    fn whitespace_preserved() {
        let r = PiiRedactor::default();
        let res = r.redact("a@b.com   foo   c@d.com");
        assert!(res.cleaned.contains("   foo   "));
    }

    #[test]
    fn custom_substring_rule() {
        let r = PiiRedactor::new();
        r.add_rule(PiiRule::custom_substring("secret-rule", "TOPSECRET"));
        let res = r.redact("HELLO TOPSECRET-INFO BYE");
        assert!(res.was_redacted());
        assert_eq!(res.count_for(SensitivityClass::Custom), 1);
    }

    #[test]
    fn record_carries_hash() {
        let r = PiiRedactor::default();
        let res = r.redact("a@b.com");
        let h_a_b = Hasher::sha256(b"a@b.com");
        assert_eq!(res.records[0].original_hash, h_a_b);
    }

    #[test]
    fn record_carries_offset() {
        let r = PiiRedactor::default();
        let res = r.redact("hello a@b.com");
        // "hello " is 6 chars before the email.
        assert_eq!(res.records[0].offset, 6);
    }

    #[test]
    fn record_carries_length() {
        let r = PiiRedactor::default();
        let res = r.redact("a@b.com");
        assert_eq!(res.records[0].original_length, 7);
    }

    #[test]
    fn empty_input_no_op() {
        let r = PiiRedactor::default();
        let res = r.redact("");
        assert_eq!(res.cleaned, "");
        assert!(res.records.is_empty());
    }

    #[test]
    fn rule_count_three_default() {
        let r = PiiRedactor::default();
        assert_eq!(r.rule_count(), 3);
    }

    #[test]
    fn no_rules_no_redaction() {
        let r = PiiRedactor::new();
        let res = r.redact("a@b.com 4111111111111111");
        assert!(!res.was_redacted());
    }

    #[test]
    fn class_label_stable() {
        assert_eq!(SensitivityClass::Email.label(), "email");
        assert_eq!(SensitivityClass::PaymentCard.label(), "payment_card");
        assert_eq!(SensitivityClass::NationalId.label(), "national_id");
        assert_eq!(SensitivityClass::Custom.label(), "custom");
    }

    #[test]
    fn email_with_no_at_not_redacted() {
        let r = PiiRedactor::default();
        let res = r.redact("hello.world.com");
        assert!(!res.was_redacted());
    }

    #[test]
    fn email_with_two_at_not_redacted() {
        let r = PiiRedactor::default();
        let res = r.redact("a@b@c.com");
        assert!(!res.was_redacted());
    }

    #[test]
    fn short_digit_run_not_redacted() {
        let r = PiiRedactor::default();
        let res = r.redact("12345");
        assert!(!res.was_redacted());
    }

    #[test]
    fn redaction_record_serde() {
        let r = RedactionRecord {
            rule_id: "x".into(),
            class: SensitivityClass::Email,
            original_hash: Hasher::sha256(b"x"),
            original_length: 5,
            offset: 0,
        };
        let j = serde_json::to_string(&r).unwrap();
        let p: RedactionRecord = serde_json::from_str(&j).unwrap();
        assert_eq!(p, r);
    }

    #[test]
    fn rule_serde() {
        let r = PiiRule::email();
        let j = serde_json::to_string(&r).unwrap();
        let p: PiiRule = serde_json::from_str(&j).unwrap();
        assert_eq!(p, r);
    }

    #[test]
    fn redaction_result_serde() {
        let res = RedactionResult {
            cleaned: "x".into(),
            records: vec![],
        };
        let j = serde_json::to_string(&res).unwrap();
        let p: RedactionResult = serde_json::from_str(&j).unwrap();
        assert_eq!(p, res);
    }

    #[test]
    fn custom_mask_used_when_provided() {
        let mut r = PiiRule::email();
        r.mask = Some("***".into());
        let red = PiiRedactor::new();
        red.add_rule(r);
        let res = red.redact("a@b.com");
        assert!(res.cleaned.contains("***"));
    }

    #[test]
    fn looks_like_email_unit() {
        assert!(looks_like_email("a@b.com"));
        assert!(!looks_like_email("a@b"));
        assert!(!looks_like_email("@b.com"));
        assert!(!looks_like_email("a@b@c.com"));
    }

    #[test]
    fn looks_like_pan_unit() {
        assert!(looks_like_pan("4111111111111111"));
        assert!(!looks_like_pan("411"));
        assert!(!looks_like_pan("hello"));
    }

    #[test]
    fn many_tokens_processed() {
        let r = PiiRedactor::default();
        let input = (0..50)
            .map(|i| format!("u{i}@x.com"))
            .collect::<Vec<_>>()
            .join(" ");
        let res = r.redact(&input);
        assert_eq!(res.count_for(SensitivityClass::Email), 50);
    }
}
