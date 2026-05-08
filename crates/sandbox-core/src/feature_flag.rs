//! Per-tenant feature flagging.
//!
//! Three flag kinds:
//!
//! - **Boolean** — on/off.
//! - **Variant** — A/B/C string variant.
//! - **PercentageRollout** — fraction of tenants allowed (deterministic by
//!   hashing tenant id).
//!
//! Each flag has a global default and per-tenant overrides. Operators
//! flip flags via the registry; consumers call `is_enabled` /
//! `variant_for` and feed the result into product logic.

use crate::hashing::Hasher;
use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;
use time::OffsetDateTime;

// =============================================================================
// FlagKind
// =============================================================================

/// Flag kind.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum FlagKind {
    /// Boolean.
    Boolean {
        /// Default state.
        default: bool,
    },
    /// String variant (A/B/C).
    Variant {
        /// Default variant.
        default: String,
        /// All allowed variants.
        variants: Vec<String>,
    },
    /// Percentage rollout — `pct` is 0..=100.
    PercentageRollout {
        /// Default percentage.
        default_pct: u32,
    },
}

// =============================================================================
// Override
// =============================================================================

/// Per-tenant override.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FlagOverride {
    /// Tenant.
    pub tenant_id: String,
    /// Override value (boolean / variant / pct).
    pub value: serde_json::Value,
    /// Set by.
    pub set_by: String,
    /// RFC 3339 set at.
    pub set_at: String,
    /// Optional reason.
    pub reason: Option<String>,
}

// =============================================================================
// FeatureFlag
// =============================================================================

/// One flag definition + overrides.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FeatureFlag {
    /// Stable id.
    pub flag_id: String,
    /// Description.
    pub description: String,
    /// Kind.
    pub kind: FlagKind,
    /// Per-tenant overrides.
    pub overrides: Vec<FlagOverride>,
    /// `true` if flag is active overall.
    pub active: bool,
    /// RFC 3339 created.
    pub created_at: String,
}

impl FeatureFlag {
    /// Look up override for a tenant.
    pub fn override_for(&self, tenant: &str) -> Option<&FlagOverride> {
        self.overrides.iter().rev().find(|o| o.tenant_id == tenant)
    }

    /// `true` if `tenant` should see this boolean / percentage flag.
    /// Errors if flag isn't a boolean or percentage.
    pub fn is_enabled(&self, tenant: &str) -> SandboxResult<bool> {
        if !self.active {
            return Ok(false);
        }
        if let Some(o) = self.override_for(tenant) {
            return Ok(o.value.as_bool().unwrap_or(false));
        }
        match &self.kind {
            FlagKind::Boolean { default } => Ok(*default),
            FlagKind::PercentageRollout { default_pct } => Ok(in_pct(tenant, *default_pct)),
            FlagKind::Variant { .. } => Err(SandboxError::Other(
                "is_enabled called on Variant flag — use variant_for".into(),
            )),
        }
    }

    /// Variant for a tenant.
    pub fn variant_for(&self, tenant: &str) -> SandboxResult<String> {
        if !self.active {
            return Err(SandboxError::Other("flag inactive".into()));
        }
        if let Some(o) = self.override_for(tenant) {
            if let Some(s) = o.value.as_str() {
                return Ok(s.to_string());
            }
        }
        match &self.kind {
            FlagKind::Variant { default, .. } => Ok(default.clone()),
            _ => Err(SandboxError::Other(
                "variant_for called on non-Variant flag".into(),
            )),
        }
    }
}

fn in_pct(tenant: &str, pct: u32) -> bool {
    let pct = pct.min(100);
    if pct == 0 {
        return false;
    }
    if pct >= 100 {
        return true;
    }
    let h = Hasher::sha256(tenant.as_bytes()).0;
    // First 4 bytes as u32, mod 100.
    let n =
        u32::from_le_bytes([h[0], h[1], h[2], h[3]]) % 100;
    n < pct
}

// =============================================================================
// FeatureFlagRegistry
// =============================================================================

#[derive(Default)]
struct State {
    flags: HashMap<String, FeatureFlag>,
}

/// Registry.
pub struct FeatureFlagRegistry {
    state: RwLock<State>,
}

impl Default for FeatureFlagRegistry {
    fn default() -> Self {
        Self {
            state: RwLock::new(State::default()),
        }
    }
}

impl std::fmt::Debug for FeatureFlagRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FeatureFlagRegistry")
            .field("flags", &self.len())
            .finish()
    }
}

impl FeatureFlagRegistry {
    /// New empty.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register.
    pub fn register(
        &self,
        flag_id: impl Into<String>,
        description: impl Into<String>,
        kind: FlagKind,
    ) -> SandboxResult<FeatureFlag> {
        let id = flag_id.into();
        let f = FeatureFlag {
            flag_id: id.clone(),
            description: description.into(),
            kind,
            overrides: Vec::new(),
            active: true,
            created_at: OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
        };
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("flag registry poisoned".into()))?;
        if g.flags.contains_key(&id) {
            return Err(SandboxError::Other(format!(
                "flag {} already registered",
                id
            )));
        }
        g.flags.insert(id, f.clone());
        Ok(f)
    }

    /// Toggle the flag's active state.
    pub fn set_active(&self, flag_id: &str, active: bool) -> SandboxResult<()> {
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("flag registry poisoned".into()))?;
        let f = g
            .flags
            .get_mut(flag_id)
            .ok_or_else(|| SandboxError::Other(format!("flag {} not found", flag_id)))?;
        f.active = active;
        Ok(())
    }

    /// Set a tenant override.
    pub fn set_override(
        &self,
        flag_id: &str,
        tenant: impl Into<String>,
        value: serde_json::Value,
        set_by: impl Into<String>,
        reason: Option<String>,
    ) -> SandboxResult<()> {
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("flag registry poisoned".into()))?;
        let f = g
            .flags
            .get_mut(flag_id)
            .ok_or_else(|| SandboxError::Other(format!("flag {} not found", flag_id)))?;
        let o = FlagOverride {
            tenant_id: tenant.into(),
            value,
            set_by: set_by.into(),
            set_at: OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
            reason,
        };
        // Remove any prior override for the same tenant.
        f.overrides.retain(|x| x.tenant_id != o.tenant_id);
        f.overrides.push(o);
        Ok(())
    }

    /// Lookup.
    pub fn get(&self, id: &str) -> Option<FeatureFlag> {
        self.state.read().ok()?.flags.get(id).cloned()
    }
    /// All.
    pub fn all(&self) -> Vec<FeatureFlag> {
        self.state
            .read()
            .map(|g| g.flags.values().cloned().collect())
            .unwrap_or_default()
    }
    /// Convenience: is enabled.
    pub fn is_enabled(&self, flag_id: &str, tenant: &str) -> SandboxResult<bool> {
        let f = self
            .get(flag_id)
            .ok_or_else(|| SandboxError::Other(format!("flag {} not found", flag_id)))?;
        f.is_enabled(tenant)
    }
    /// Convenience: variant.
    pub fn variant(&self, flag_id: &str, tenant: &str) -> SandboxResult<String> {
        let f = self
            .get(flag_id)
            .ok_or_else(|| SandboxError::Other(format!("flag {} not found", flag_id)))?;
        f.variant_for(tenant)
    }
    /// Count.
    pub fn len(&self) -> usize {
        self.state.read().map(|g| g.flags.len()).unwrap_or(0)
    }
    /// Empty?
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn register_creates_flag() {
        let r = FeatureFlagRegistry::new();
        r.register(
            "new-credit-model",
            "Use new credit model",
            FlagKind::Boolean { default: false },
        )
        .unwrap();
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn duplicate_register_errors() {
        let r = FeatureFlagRegistry::new();
        r.register("x", "x", FlagKind::Boolean { default: false }).unwrap();
        assert!(r
            .register("x", "y", FlagKind::Boolean { default: true })
            .is_err());
    }

    #[test]
    fn boolean_default_false() {
        let r = FeatureFlagRegistry::new();
        r.register("x", "x", FlagKind::Boolean { default: false }).unwrap();
        assert!(!r.is_enabled("x", "FAB").unwrap());
    }

    #[test]
    fn boolean_default_true() {
        let r = FeatureFlagRegistry::new();
        r.register("x", "x", FlagKind::Boolean { default: true }).unwrap();
        assert!(r.is_enabled("x", "FAB").unwrap());
    }

    #[test]
    fn override_takes_precedence() {
        let r = FeatureFlagRegistry::new();
        r.register("x", "x", FlagKind::Boolean { default: false }).unwrap();
        r.set_override("x", "FAB", json!(true), "ops", None).unwrap();
        assert!(r.is_enabled("x", "FAB").unwrap());
        // Other tenant still default.
        assert!(!r.is_enabled("x", "ENBD").unwrap());
    }

    #[test]
    fn override_replaces_prior_for_same_tenant() {
        let r = FeatureFlagRegistry::new();
        r.register("x", "x", FlagKind::Boolean { default: false }).unwrap();
        r.set_override("x", "FAB", json!(true), "ops", None).unwrap();
        r.set_override("x", "FAB", json!(false), "ops", None).unwrap();
        assert!(!r.is_enabled("x", "FAB").unwrap());
    }

    #[test]
    fn inactive_flag_disabled() {
        let r = FeatureFlagRegistry::new();
        r.register("x", "x", FlagKind::Boolean { default: true }).unwrap();
        r.set_active("x", false).unwrap();
        assert!(!r.is_enabled("x", "FAB").unwrap());
    }

    #[test]
    fn variant_returns_default() {
        let r = FeatureFlagRegistry::new();
        r.register(
            "v",
            "v",
            FlagKind::Variant {
                default: "control".into(),
                variants: vec!["control".into(), "treatment".into()],
            },
        )
        .unwrap();
        assert_eq!(r.variant("v", "FAB").unwrap(), "control");
    }

    #[test]
    fn variant_override() {
        let r = FeatureFlagRegistry::new();
        r.register(
            "v",
            "v",
            FlagKind::Variant {
                default: "control".into(),
                variants: vec!["control".into(), "treatment".into()],
            },
        )
        .unwrap();
        r.set_override("v", "FAB", json!("treatment"), "ops", None).unwrap();
        assert_eq!(r.variant("v", "FAB").unwrap(), "treatment");
    }

    #[test]
    fn percentage_zero_disabled() {
        let r = FeatureFlagRegistry::new();
        r.register("p", "p", FlagKind::PercentageRollout { default_pct: 0 })
            .unwrap();
        for t in &["FAB", "ENBD", "x"] {
            assert!(!r.is_enabled("p", t).unwrap());
        }
    }

    #[test]
    fn percentage_hundred_enabled() {
        let r = FeatureFlagRegistry::new();
        r.register("p", "p", FlagKind::PercentageRollout { default_pct: 100 })
            .unwrap();
        for t in &["FAB", "ENBD", "x"] {
            assert!(r.is_enabled("p", t).unwrap());
        }
    }

    #[test]
    fn percentage_deterministic() {
        let r = FeatureFlagRegistry::new();
        r.register("p", "p", FlagKind::PercentageRollout { default_pct: 50 })
            .unwrap();
        let a = r.is_enabled("p", "FAB").unwrap();
        let b = r.is_enabled("p", "FAB").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn percentage_distribution_roughly_uniform() {
        let r = FeatureFlagRegistry::new();
        r.register("p", "p", FlagKind::PercentageRollout { default_pct: 50 })
            .unwrap();
        let mut on = 0;
        for i in 0..1000 {
            if r.is_enabled("p", &format!("t{i}")).unwrap() {
                on += 1;
            }
        }
        // Expect ~50% ± 10%.
        assert!(on > 400 && on < 600, "on = {}", on);
    }

    #[test]
    fn variant_on_boolean_errors() {
        let r = FeatureFlagRegistry::new();
        r.register("x", "x", FlagKind::Boolean { default: true }).unwrap();
        assert!(r.variant("x", "FAB").is_err());
    }

    #[test]
    fn is_enabled_on_variant_errors() {
        let r = FeatureFlagRegistry::new();
        r.register(
            "v",
            "v",
            FlagKind::Variant {
                default: "x".into(),
                variants: vec!["x".into()],
            },
        )
        .unwrap();
        assert!(r.is_enabled("v", "FAB").is_err());
    }

    #[test]
    fn set_active_unknown_errors() {
        let r = FeatureFlagRegistry::new();
        assert!(r.set_active("ghost", true).is_err());
    }

    #[test]
    fn set_override_unknown_errors() {
        let r = FeatureFlagRegistry::new();
        assert!(r
            .set_override("ghost", "FAB", json!(true), "ops", None)
            .is_err());
    }

    #[test]
    fn flag_serde() {
        let r = FeatureFlagRegistry::new();
        let f = r
            .register("x", "x", FlagKind::Boolean { default: true })
            .unwrap();
        let j = serde_json::to_string(&f).unwrap();
        let p: FeatureFlag = serde_json::from_str(&j).unwrap();
        assert_eq!(p, f);
    }

    #[test]
    fn registry_count_tracks() {
        let r = FeatureFlagRegistry::new();
        assert!(r.is_empty());
        r.register("x", "x", FlagKind::Boolean { default: false }).unwrap();
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn lookup_unknown_none() {
        let r = FeatureFlagRegistry::new();
        assert!(r.get("ghost").is_none());
    }

    #[test]
    fn override_serde() {
        let o = FlagOverride {
            tenant_id: "FAB".into(),
            value: json!(true),
            set_by: "ops".into(),
            set_at: "t".into(),
            reason: Some("rollout".into()),
        };
        let j = serde_json::to_string(&o).unwrap();
        let p: FlagOverride = serde_json::from_str(&j).unwrap();
        assert_eq!(p, o);
    }

    #[test]
    fn flag_kind_serde() {
        for k in [
            FlagKind::Boolean { default: true },
            FlagKind::PercentageRollout { default_pct: 50 },
            FlagKind::Variant {
                default: "x".into(),
                variants: vec!["x".into()],
            },
        ] {
            let j = serde_json::to_string(&k).unwrap();
            let p: FlagKind = serde_json::from_str(&j).unwrap();
            assert_eq!(p, k);
        }
    }
}
