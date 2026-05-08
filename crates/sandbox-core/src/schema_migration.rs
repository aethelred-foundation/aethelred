//! Seal-schema migration framework.
//!
//! Customers store seals on disk / in object storage / on chain for years.
//! When the seal schema evolves (V1 → V2 → V3), older seals must be readable
//! by the new code path. This module provides a forward-only migration
//! framework that operates on the **JSON wire format** so historical seals
//! can always be re-read, even if they include fields the current Rust types
//! don't model.
//!
//! ## Model
//!
//! - A [`SchemaTag`] is a stable string label like `"v1"`, `"v2"`, ...
//! - Each [`Migration`] declares `from()` and `to()` and provides a pure
//!   `apply(&mut Value)` that rewrites the JSON in place.
//! - [`MigrationRegistry`] holds an ordered chain; [`SchemaMigrator`] applies
//!   each migration whose `from()` matches the current tag, advancing until
//!   either the target tag is reached or no further migration applies.
//!
//! ## Why this exists
//!
//! - **Forward compatibility.** New nodes can read seals minted by old nodes.
//! - **Auditability.** Each step is logged in a [`MigrationReport`] so the
//!   transformation chain is fully traceable.
//! - **Determinism.** Every migration is a pure JSON-to-JSON function. Two
//!   nodes applying the same chain to the same input produce identical output.
//!
//! ## Usage
//!
//! ```ignore
//! let mut reg = MigrationRegistry::new();
//! reg.register(Box::new(MyV1ToV2));
//! reg.register(Box::new(MyV2ToV3));
//! let migrator = SchemaMigrator::new(reg);
//! let (migrated, report) = migrator.migrate_to(value, &SchemaTag::new("v3"))?;
//! ```

use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fmt;

// =============================================================================
// SchemaTag
// =============================================================================

/// Stable string-based schema version tag (e.g. `"v1"`, `"v2"`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SchemaTag(pub String);

impl SchemaTag {
    /// New tag.
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    /// As `&str`.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SchemaTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Field name used to read/write the schema tag in JSON values.
pub const SCHEMA_VERSION_FIELD: &str = "schema_version";

/// Read the `schema_version` string from a JSON object.
pub fn read_tag(v: &Value) -> Option<SchemaTag> {
    v.get(SCHEMA_VERSION_FIELD)
        .and_then(|x| x.as_str())
        .map(|s| SchemaTag::new(s))
}

/// Write the `schema_version` string into a JSON object (creates the field
/// if absent). Errors if `v` is not an object.
pub fn write_tag(v: &mut Value, tag: &SchemaTag) -> SandboxResult<()> {
    let obj = v
        .as_object_mut()
        .ok_or_else(|| SandboxError::Other("schema migration: value is not an object".into()))?;
    obj.insert(
        SCHEMA_VERSION_FIELD.to_string(),
        Value::String(tag.0.clone()),
    );
    Ok(())
}

// =============================================================================
// Migration trait
// =============================================================================

/// One forward migration step.
pub trait Migration: Send + Sync {
    /// Tag this migration upgrades *from*.
    fn from(&self) -> SchemaTag;
    /// Tag this migration upgrades *to*.
    fn to(&self) -> SchemaTag;
    /// Mutate the JSON in place to upgrade.
    fn apply(&self, value: &mut Value) -> SandboxResult<()>;
    /// Optional human-readable description for the migration report.
    fn description(&self) -> &str {
        ""
    }
}

// =============================================================================
// MigrationRegistry
// =============================================================================

/// Ordered chain of migrations. Insertion order = application order.
#[derive(Default)]
pub struct MigrationRegistry {
    chain: Vec<Box<dyn Migration>>,
}

impl fmt::Debug for MigrationRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MigrationRegistry")
            .field("steps", &self.chain.len())
            .finish()
    }
}

impl MigrationRegistry {
    /// New empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a migration step. Order matters.
    pub fn register(&mut self, m: Box<dyn Migration>) {
        self.chain.push(m);
    }

    /// Number of steps registered.
    pub fn len(&self) -> usize {
        self.chain.len()
    }

    /// `true` if no steps registered.
    pub fn is_empty(&self) -> bool {
        self.chain.is_empty()
    }

    /// Iterate steps.
    pub fn steps(&self) -> impl Iterator<Item = &dyn Migration> {
        self.chain.iter().map(|b| b.as_ref())
    }

    /// `true` if a path from `start` to `target` exists in the chain.
    pub fn path_exists(&self, start: &SchemaTag, target: &SchemaTag) -> bool {
        if start == target {
            return true;
        }
        let mut cur = start.clone();
        for s in &self.chain {
            if &s.from() == &cur {
                cur = s.to();
                if &cur == target {
                    return true;
                }
            }
        }
        false
    }
}

// =============================================================================
// MigrationReport — auditable transcript of one migration run
// =============================================================================

/// Report produced by [`SchemaMigrator::migrate_to`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MigrationReport {
    /// Tag the input declared.
    pub from_tag: SchemaTag,
    /// Tag the output ended at.
    pub to_tag: SchemaTag,
    /// Per-step trace, one entry per migration applied.
    pub steps: Vec<MigrationStepReport>,
    /// `true` if the target tag was reached.
    pub reached_target: bool,
}

/// One step in [`MigrationReport`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MigrationStepReport {
    /// Step from-tag.
    pub from: SchemaTag,
    /// Step to-tag.
    pub to: SchemaTag,
    /// Step description.
    pub description: String,
}

// =============================================================================
// SchemaMigrator
// =============================================================================

/// Driver: applies registry migrations to advance a JSON value.
#[derive(Debug)]
pub struct SchemaMigrator {
    registry: MigrationRegistry,
}

impl SchemaMigrator {
    /// New migrator.
    pub fn new(registry: MigrationRegistry) -> Self {
        Self { registry }
    }

    /// Borrow registry.
    pub fn registry(&self) -> &MigrationRegistry {
        &self.registry
    }

    /// Migrate a value as far as possible (no target tag — just apply every
    /// applicable step in order until none matches).
    pub fn migrate_max(&self, value: Value) -> SandboxResult<(Value, MigrationReport)> {
        self.migrate_to_inner(value, None)
    }

    /// Migrate a value forward until `target` is reached, returning a report.
    /// Errors if no path from the starting tag to `target` exists.
    pub fn migrate_to(
        &self,
        value: Value,
        target: &SchemaTag,
    ) -> SandboxResult<(Value, MigrationReport)> {
        self.migrate_to_inner(value, Some(target.clone()))
    }

    fn migrate_to_inner(
        &self,
        mut value: Value,
        target: Option<SchemaTag>,
    ) -> SandboxResult<(Value, MigrationReport)> {
        let from_tag = read_tag(&value).ok_or_else(|| {
            SandboxError::Other(format!(
                "schema migration: missing `{}` field",
                SCHEMA_VERSION_FIELD
            ))
        })?;
        if let Some(t) = &target {
            if !self.registry.path_exists(&from_tag, t) {
                return Err(SandboxError::Other(format!(
                    "schema migration: no path from {} to {}",
                    from_tag, t
                )));
            }
        }
        let mut steps_taken = Vec::new();
        let mut current = from_tag.clone();
        // Walk: at each step, find a migration whose .from() matches current tag.
        loop {
            if let Some(t) = &target {
                if &current == t {
                    break;
                }
            }
            let next_step = self.registry.chain.iter().find(|m| &m.from() == &current);
            let step = match next_step {
                Some(s) => s,
                None => break, // no more applicable steps
            };
            step.apply(&mut value)?;
            // Stamp the new tag so downstream is consistent.
            write_tag(&mut value, &step.to())?;
            steps_taken.push(MigrationStepReport {
                from: step.from(),
                to: step.to(),
                description: step.description().to_string(),
            });
            current = step.to();
        }
        let reached_target = target.as_ref().map(|t| t == &current).unwrap_or(true);
        Ok((
            value,
            MigrationReport {
                from_tag,
                to_tag: current,
                steps: steps_taken,
                reached_target,
            },
        ))
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // -------------------------------------------------------------------------
    // Synthetic migrations for tests.
    // -------------------------------------------------------------------------

    /// V1 → V2: rename field `old_name` to `new_name`.
    struct V1ToV2;
    impl Migration for V1ToV2 {
        fn from(&self) -> SchemaTag {
            SchemaTag::new("v1")
        }
        fn to(&self) -> SchemaTag {
            SchemaTag::new("v2")
        }
        fn apply(&self, value: &mut Value) -> SandboxResult<()> {
            let obj = value
                .as_object_mut()
                .ok_or_else(|| SandboxError::Other("v1->v2 expects object".into()))?;
            if let Some(v) = obj.remove("old_name") {
                obj.insert("new_name".to_string(), v);
            }
            Ok(())
        }
        fn description(&self) -> &str {
            "rename old_name -> new_name"
        }
    }

    /// V2 → V3: insert default `priority = 0` if missing.
    struct V2ToV3;
    impl Migration for V2ToV3 {
        fn from(&self) -> SchemaTag {
            SchemaTag::new("v2")
        }
        fn to(&self) -> SchemaTag {
            SchemaTag::new("v3")
        }
        fn apply(&self, value: &mut Value) -> SandboxResult<()> {
            let obj = value
                .as_object_mut()
                .ok_or_else(|| SandboxError::Other("v2->v3 expects object".into()))?;
            obj.entry("priority".to_string()).or_insert(json!(0));
            Ok(())
        }
        fn description(&self) -> &str {
            "insert default priority"
        }
    }

    /// V3 → V4: wrap two scalar fields into a nested object.
    struct V3ToV4;
    impl Migration for V3ToV4 {
        fn from(&self) -> SchemaTag {
            SchemaTag::new("v3")
        }
        fn to(&self) -> SchemaTag {
            SchemaTag::new("v4")
        }
        fn apply(&self, value: &mut Value) -> SandboxResult<()> {
            let obj = value
                .as_object_mut()
                .ok_or_else(|| SandboxError::Other("v3->v4 expects object".into()))?;
            let new_name = obj.remove("new_name").unwrap_or(json!(""));
            let priority = obj.remove("priority").unwrap_or(json!(0));
            obj.insert(
                "meta".to_string(),
                json!({"name": new_name, "priority": priority}),
            );
            Ok(())
        }
    }

    fn registry_v1_to_v4() -> MigrationRegistry {
        let mut r = MigrationRegistry::new();
        r.register(Box::new(V1ToV2));
        r.register(Box::new(V2ToV3));
        r.register(Box::new(V3ToV4));
        r
    }

    // -------------------------------------------------------------------------
    // SchemaTag basics.
    // -------------------------------------------------------------------------

    #[test]
    fn schema_tag_round_trip() {
        let t = SchemaTag::new("v1");
        let j = serde_json::to_string(&t).unwrap();
        assert_eq!(j, "\"v1\"");
        let p: SchemaTag = serde_json::from_str(&j).unwrap();
        assert_eq!(p, t);
    }

    #[test]
    fn schema_tag_display() {
        assert_eq!(format!("{}", SchemaTag::new("v7")), "v7");
    }

    #[test]
    fn read_tag_returns_some() {
        let v = json!({ "schema_version": "v1", "x": 1 });
        assert_eq!(read_tag(&v), Some(SchemaTag::new("v1")));
    }

    #[test]
    fn read_tag_returns_none_when_missing() {
        let v = json!({ "x": 1 });
        assert!(read_tag(&v).is_none());
    }

    #[test]
    fn write_tag_creates_field() {
        let mut v = json!({});
        write_tag(&mut v, &SchemaTag::new("v3")).unwrap();
        assert_eq!(read_tag(&v), Some(SchemaTag::new("v3")));
    }

    #[test]
    fn write_tag_errors_on_non_object() {
        let mut v = json!([1, 2, 3]);
        assert!(write_tag(&mut v, &SchemaTag::new("v1")).is_err());
    }

    // -------------------------------------------------------------------------
    // Registry.
    // -------------------------------------------------------------------------

    #[test]
    fn registry_starts_empty() {
        let r = MigrationRegistry::new();
        assert!(r.is_empty());
        assert_eq!(r.len(), 0);
    }

    #[test]
    fn registry_register_increments_len() {
        let mut r = MigrationRegistry::new();
        r.register(Box::new(V1ToV2));
        r.register(Box::new(V2ToV3));
        assert_eq!(r.len(), 2);
    }

    #[test]
    fn path_exists_self_loop_trivial() {
        let r = registry_v1_to_v4();
        assert!(r.path_exists(&SchemaTag::new("v1"), &SchemaTag::new("v1")));
    }

    #[test]
    fn path_exists_full_chain() {
        let r = registry_v1_to_v4();
        assert!(r.path_exists(&SchemaTag::new("v1"), &SchemaTag::new("v4")));
    }

    #[test]
    fn path_exists_partial_chain() {
        let r = registry_v1_to_v4();
        assert!(r.path_exists(&SchemaTag::new("v2"), &SchemaTag::new("v4")));
    }

    #[test]
    fn path_does_not_exist_for_unknown() {
        let r = registry_v1_to_v4();
        assert!(!r.path_exists(&SchemaTag::new("v1"), &SchemaTag::new("v99")));
    }

    // -------------------------------------------------------------------------
    // SchemaMigrator.migrate_to.
    // -------------------------------------------------------------------------

    #[test]
    fn migrate_v1_to_v2_renames_field() {
        let m = SchemaMigrator::new({
            let mut r = MigrationRegistry::new();
            r.register(Box::new(V1ToV2));
            r
        });
        let v = json!({ "schema_version": "v1", "old_name": "alice" });
        let (out, rep) = m.migrate_to(v, &SchemaTag::new("v2")).unwrap();
        assert_eq!(out["schema_version"], "v2");
        assert_eq!(out["new_name"], "alice");
        assert!(out.get("old_name").is_none());
        assert!(rep.reached_target);
        assert_eq!(rep.steps.len(), 1);
    }

    #[test]
    fn migrate_v1_to_v3_chains_two_steps() {
        let m = SchemaMigrator::new({
            let mut r = MigrationRegistry::new();
            r.register(Box::new(V1ToV2));
            r.register(Box::new(V2ToV3));
            r
        });
        let v = json!({ "schema_version": "v1", "old_name": "alice" });
        let (out, rep) = m.migrate_to(v, &SchemaTag::new("v3")).unwrap();
        assert_eq!(out["schema_version"], "v3");
        assert_eq!(out["new_name"], "alice");
        assert_eq!(out["priority"], 0);
        assert_eq!(rep.steps.len(), 2);
        assert!(rep.reached_target);
    }

    #[test]
    fn migrate_v1_to_v4_chains_all() {
        let m = SchemaMigrator::new(registry_v1_to_v4());
        let v = json!({ "schema_version": "v1", "old_name": "alice" });
        let (out, rep) = m.migrate_to(v, &SchemaTag::new("v4")).unwrap();
        assert_eq!(out["schema_version"], "v4");
        assert_eq!(out["meta"]["name"], "alice");
        assert_eq!(out["meta"]["priority"], 0);
        assert_eq!(rep.steps.len(), 3);
    }

    #[test]
    fn migrate_no_op_when_already_at_target() {
        let m = SchemaMigrator::new(registry_v1_to_v4());
        let v = json!({ "schema_version": "v3", "new_name": "x", "priority": 5 });
        let (out, rep) = m.migrate_to(v.clone(), &SchemaTag::new("v3")).unwrap();
        assert_eq!(out, v);
        assert_eq!(rep.steps.len(), 0);
        assert!(rep.reached_target);
    }

    #[test]
    fn migrate_errors_when_no_path() {
        let m = SchemaMigrator::new(registry_v1_to_v4());
        let v = json!({ "schema_version": "v1" });
        let err = m
            .migrate_to(v, &SchemaTag::new("v999"))
            .expect_err("no path");
        let msg = format!("{}", err);
        assert!(msg.contains("no path"));
    }

    #[test]
    fn migrate_errors_when_missing_schema_version_field() {
        let m = SchemaMigrator::new(registry_v1_to_v4());
        let v = json!({ "old_name": "alice" });
        let err = m
            .migrate_to(v, &SchemaTag::new("v2"))
            .expect_err("missing field");
        let msg = format!("{}", err);
        assert!(msg.contains("schema_version"));
    }

    #[test]
    fn migrate_max_walks_to_end() {
        let m = SchemaMigrator::new(registry_v1_to_v4());
        let v = json!({ "schema_version": "v1", "old_name": "alice" });
        let (out, rep) = m.migrate_max(v).unwrap();
        assert_eq!(out["schema_version"], "v4");
        assert_eq!(rep.from_tag, SchemaTag::new("v1"));
        assert_eq!(rep.to_tag, SchemaTag::new("v4"));
    }

    #[test]
    fn migrate_max_stops_when_no_step_applies() {
        let mut r = MigrationRegistry::new();
        r.register(Box::new(V1ToV2));
        let m = SchemaMigrator::new(r);
        let v = json!({ "schema_version": "v1", "old_name": "x" });
        let (_, rep) = m.migrate_max(v).unwrap();
        assert_eq!(rep.to_tag, SchemaTag::new("v2"));
    }

    #[test]
    fn migrate_partial_path() {
        let m = SchemaMigrator::new(registry_v1_to_v4());
        let v = json!({ "schema_version": "v2", "new_name": "alice" });
        let (out, rep) = m.migrate_to(v, &SchemaTag::new("v3")).unwrap();
        assert_eq!(out["priority"], 0);
        assert_eq!(rep.steps.len(), 1);
    }

    #[test]
    fn report_step_descriptions_recorded() {
        let m = SchemaMigrator::new(registry_v1_to_v4());
        let v = json!({ "schema_version": "v1", "old_name": "x" });
        let (_, rep) = m.migrate_to(v, &SchemaTag::new("v2")).unwrap();
        assert_eq!(rep.steps[0].description, "rename old_name -> new_name");
    }

    #[test]
    fn report_serde_round_trip() {
        let r = MigrationReport {
            from_tag: SchemaTag::new("v1"),
            to_tag: SchemaTag::new("v2"),
            steps: vec![MigrationStepReport {
                from: SchemaTag::new("v1"),
                to: SchemaTag::new("v2"),
                description: "x".into(),
            }],
            reached_target: true,
        };
        let j = serde_json::to_string(&r).unwrap();
        let p: MigrationReport = serde_json::from_str(&j).unwrap();
        assert_eq!(p, r);
    }

    #[test]
    fn output_schema_version_is_stamped_after_step() {
        // Even if a migration's apply forgets to update the tag, the driver stamps it.
        struct ForgetfulMig;
        impl Migration for ForgetfulMig {
            fn from(&self) -> SchemaTag {
                SchemaTag::new("v1")
            }
            fn to(&self) -> SchemaTag {
                SchemaTag::new("v2")
            }
            fn apply(&self, value: &mut Value) -> SandboxResult<()> {
                let obj = value.as_object_mut().unwrap();
                obj.insert("added".to_string(), json!(true));
                Ok(())
            }
        }
        let mut r = MigrationRegistry::new();
        r.register(Box::new(ForgetfulMig));
        let m = SchemaMigrator::new(r);
        let v = json!({ "schema_version": "v1" });
        let (out, _) = m.migrate_to(v, &SchemaTag::new("v2")).unwrap();
        assert_eq!(out["schema_version"], "v2");
        assert_eq!(out["added"], true);
    }

    #[test]
    fn multiple_runs_idempotent_at_target() {
        let m = SchemaMigrator::new(registry_v1_to_v4());
        let v = json!({ "schema_version": "v1", "old_name": "x" });
        let (out1, _) = m.migrate_to(v, &SchemaTag::new("v4")).unwrap();
        let (out2, _) = m.migrate_to(out1.clone(), &SchemaTag::new("v4")).unwrap();
        assert_eq!(out1, out2);
    }

    #[test]
    fn registry_steps_iter_visits_all() {
        let r = registry_v1_to_v4();
        assert_eq!(r.steps().count(), 3);
    }

    #[test]
    fn migration_apply_propagates_error() {
        struct ErroringMig;
        impl Migration for ErroringMig {
            fn from(&self) -> SchemaTag {
                SchemaTag::new("v1")
            }
            fn to(&self) -> SchemaTag {
                SchemaTag::new("v2")
            }
            fn apply(&self, _v: &mut Value) -> SandboxResult<()> {
                Err(SandboxError::Other("boom".into()))
            }
        }
        let mut r = MigrationRegistry::new();
        r.register(Box::new(ErroringMig));
        let m = SchemaMigrator::new(r);
        let v = json!({ "schema_version": "v1" });
        let err = m
            .migrate_to(v, &SchemaTag::new("v2"))
            .expect_err("must propagate");
        assert!(format!("{err}").contains("boom"));
    }

    #[test]
    fn empty_registry_with_target_self_succeeds() {
        let m = SchemaMigrator::new(MigrationRegistry::new());
        let v = json!({ "schema_version": "v1" });
        let (out, _) = m.migrate_to(v.clone(), &SchemaTag::new("v1")).unwrap();
        assert_eq!(out, v);
    }
}
