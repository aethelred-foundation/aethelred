//! Kubernetes manifest register — declared cluster state.
//!
//! Maps to **CIS Kubernetes Benchmark** (declared workload posture),
//! **SOC 2 CC8.1** (configuration change control), and PCI-DSS 6.x
//! (secure deployment). Every applied Kubernetes manifest (Deployment,
//! StatefulSet, DaemonSet, CronJob, Service, Ingress, ConfigMap,
//! Secret-by-reference, Role / RoleBinding) is logged here with:
//!
//! - **content hash** for tamper-evident traceability,
//! - **container image references** with digests,
//! - **RBAC bindings** referenced by the manifest,
//! - **cluster + namespace** scope,
//! - **lifecycle**: `Drafted → Applied → Active → (Replaced | Deleted)`.
//!
//! Distinct from [`crate::terraform_plan_register`] (cloud-IaC) and
//! [`crate::deployment_pipeline`] (CI/CD stages); this is the
//! **cluster-state inventory** that answers "what's actually running in
//! prod-cluster-east right now?"

use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;

// =============================================================================
// ManifestKind
// =============================================================================

/// Kind of Kubernetes resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifestKind {
    Deployment,
    StatefulSet,
    DaemonSet,
    Job,
    CronJob,
    Service,
    Ingress,
    ConfigMap,
    Secret,
    Role,
    RoleBinding,
    ClusterRole,
    ClusterRoleBinding,
    NetworkPolicy,
    PodSecurityPolicy,
    Namespace,
    Other,
}

impl ManifestKind {
    /// True if this kind directly creates running pods.
    pub fn runs_workload(self) -> bool {
        matches!(
            self,
            Self::Deployment | Self::StatefulSet | Self::DaemonSet | Self::Job | Self::CronJob
        )
    }

    /// True if this kind is RBAC-relevant.
    pub fn is_rbac(self) -> bool {
        matches!(
            self,
            Self::Role | Self::RoleBinding | Self::ClusterRole | Self::ClusterRoleBinding
        )
    }
}

// =============================================================================
// ManifestStage
// =============================================================================

/// Lifecycle stage of a manifest record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifestStage {
    /// Drafted but not yet applied.
    Drafted,
    /// `kubectl apply` succeeded; awaiting reconciliation.
    Applied,
    /// Currently authoritative cluster state.
    Active,
    /// Replaced by a newer manifest version.
    Replaced,
    /// Deleted from the cluster.
    Deleted,
}

impl ManifestStage {
    /// True if no further state changes expected.
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Replaced | Self::Deleted)
    }

    /// True if currently authoritative.
    pub fn is_active(self) -> bool {
        matches!(self, Self::Active)
    }
}

// =============================================================================
// ContainerImage
// =============================================================================

/// One referenced container image.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContainerImage {
    /// Image name ("registry.example/api").
    pub name: String,
    /// Tag ("v3.2.1").
    pub tag: String,
    /// SHA-256 digest (recommended for production manifests).
    pub digest: Option<String>,
}

impl ContainerImage {
    /// True if this reference is digest-pinned (production best practice).
    pub fn is_digest_pinned(&self) -> bool {
        self.digest.is_some()
    }
}

// =============================================================================
// RbacBinding
// =============================================================================

/// One RBAC binding referenced by the manifest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RbacBinding {
    /// Binding kind ("ServiceAccount", "User", "Group").
    pub subject_kind: String,
    /// Subject name.
    pub subject_name: String,
    /// Role / ClusterRole name granted.
    pub role: String,
}

// =============================================================================
// ManifestEvent
// =============================================================================

/// One event on the manifest timeline.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManifestEvent {
    /// RFC 3339.
    pub at: String,
    /// Actor.
    pub actor: String,
    /// Stage applied.
    pub stage: ManifestStage,
    /// Free-text note.
    pub note: String,
}

// =============================================================================
// KubernetesManifest
// =============================================================================

/// One manifest record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KubernetesManifest {
    /// Unique id (e.g., "K8S-PROD-API-v3.2.1").
    pub manifest_id: String,
    /// Tenant scope.
    pub tenant_id: String,
    /// Cluster ("prod-us-east", "staging").
    pub cluster: String,
    /// Namespace (use "default" or empty for cluster-scoped resources).
    pub namespace: String,
    /// Kind.
    pub kind: ManifestKind,
    /// Resource name.
    pub resource_name: String,
    /// Manifest content SHA-256.
    pub content_sha256: String,
    /// Storage URI for the YAML.
    pub manifest_uri: Option<String>,
    /// Container images referenced.
    pub images: Vec<ContainerImage>,
    /// RBAC bindings referenced.
    pub rbac: Vec<RbacBinding>,
    /// Stage.
    pub stage: ManifestStage,
    /// Linked Terraform plan id (if any).
    pub linked_plan_id: Option<String>,
    /// Linked deployment id (if any).
    pub linked_deployment_id: Option<String>,
    /// RFC 3339 — drafted.
    pub drafted_at: String,
    /// RFC 3339 — applied.
    pub applied_at: Option<String>,
    /// RFC 3339 — became Active.
    pub activated_at: Option<String>,
    /// RFC 3339 — closed (Replaced or Deleted).
    pub closed_at: Option<String>,
    /// Successor manifest id (set when Replaced).
    pub successor: Option<String>,
    /// Event log.
    pub events: Vec<ManifestEvent>,
    /// Free-form tags.
    pub tags: Vec<String>,
}

impl KubernetesManifest {
    /// New `Drafted` manifest.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        manifest_id: impl Into<String>,
        tenant_id: impl Into<String>,
        cluster: impl Into<String>,
        namespace: impl Into<String>,
        kind: ManifestKind,
        resource_name: impl Into<String>,
        content_sha256: impl Into<String>,
        drafted_at: impl Into<String>,
    ) -> Self {
        Self {
            manifest_id: manifest_id.into(),
            tenant_id: tenant_id.into(),
            cluster: cluster.into(),
            namespace: namespace.into(),
            kind,
            resource_name: resource_name.into(),
            content_sha256: content_sha256.into(),
            manifest_uri: None,
            images: Vec::new(),
            rbac: Vec::new(),
            stage: ManifestStage::Drafted,
            linked_plan_id: None,
            linked_deployment_id: None,
            drafted_at: drafted_at.into(),
            applied_at: None,
            activated_at: None,
            closed_at: None,
            successor: None,
            events: Vec::new(),
            tags: Vec::new(),
        }
    }

    /// True if every container image is digest-pinned.
    pub fn all_digests_pinned(&self) -> bool {
        !self.images.is_empty() && self.images.iter().all(|i| i.is_digest_pinned())
    }

    /// Images that are not digest-pinned.
    pub fn unpinned_images(&self) -> Vec<&ContainerImage> {
        self.images.iter().filter(|i| !i.is_digest_pinned()).collect()
    }
}

// =============================================================================
// Lifecycle transition table
// =============================================================================

fn legal_transition(from: ManifestStage, to: ManifestStage) -> bool {
    use ManifestStage::*;
    matches!(
        (from, to),
        (Drafted, Applied)
            | (Drafted, Deleted)        // discarded draft
            | (Applied, Active)
            | (Applied, Deleted)        // failed reconciliation
            | (Active, Replaced)
            | (Active, Deleted)
    )
}

// =============================================================================
// KubernetesManifestRegister
// =============================================================================

/// Thread-safe register of Kubernetes manifests.
#[derive(Debug, Default)]
pub struct KubernetesManifestRegister {
    inner: RwLock<HashMap<String, KubernetesManifest>>,
}

impl KubernetesManifestRegister {
    /// New empty register.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new draft.
    pub fn register(&self, manifest: KubernetesManifest) -> SandboxResult<()> {
        if !matches!(manifest.stage, ManifestStage::Drafted) {
            return Err(SandboxError::Other(format!(
                "manifest must start Drafted, got {:?}",
                manifest.stage
            )));
        }
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("k8s manifest register poisoned".into()))?;
        if g.contains_key(&manifest.manifest_id) {
            return Err(SandboxError::Other(format!(
                "manifest already registered: {}",
                manifest.manifest_id
            )));
        }
        g.insert(manifest.manifest_id.clone(), manifest);
        Ok(())
    }

    /// Add a container image reference. Allowed only in Drafted.
    pub fn add_image(&self, manifest_id: &str, image: ContainerImage) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("k8s manifest register poisoned".into()))?;
        let m = g
            .get_mut(manifest_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown manifest {manifest_id}")))?;
        if !matches!(m.stage, ManifestStage::Drafted) {
            return Err(SandboxError::Other(format!(
                "cannot add image to {manifest_id}: stage is {:?}",
                m.stage
            )));
        }
        m.images.push(image);
        Ok(())
    }

    /// Add an RBAC binding. Allowed only in Drafted.
    pub fn add_rbac(&self, manifest_id: &str, binding: RbacBinding) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("k8s manifest register poisoned".into()))?;
        let m = g
            .get_mut(manifest_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown manifest {manifest_id}")))?;
        if !matches!(m.stage, ManifestStage::Drafted) {
            return Err(SandboxError::Other(format!(
                "cannot add rbac to {manifest_id}: stage is {:?}",
                m.stage
            )));
        }
        m.rbac.push(binding);
        Ok(())
    }

    /// Apply the manifest (Drafted → Applied).
    pub fn apply(
        &self,
        manifest_id: &str,
        actor: impl Into<String>,
        at: impl Into<String>,
    ) -> SandboxResult<KubernetesManifest> {
        self.simple_transition(manifest_id, ManifestStage::Applied, actor, at, "applied")
    }

    /// Activate (Applied → Active) — controller has reconciled.
    pub fn activate(
        &self,
        manifest_id: &str,
        actor: impl Into<String>,
        at: impl Into<String>,
    ) -> SandboxResult<KubernetesManifest> {
        self.simple_transition(manifest_id, ManifestStage::Active, actor, at, "reconciled")
    }

    /// Replace this manifest with a successor.
    pub fn replace_with(
        &self,
        older_id: &str,
        successor_id: &str,
        actor: impl Into<String>,
        at: impl Into<String>,
    ) -> SandboxResult<KubernetesManifest> {
        let actor = actor.into();
        let when = at.into();
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("k8s manifest register poisoned".into()))?;
        if !g.contains_key(successor_id) {
            return Err(SandboxError::Other(format!(
                "unknown successor {successor_id}"
            )));
        }
        let older = g
            .get_mut(older_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown manifest {older_id}")))?;
        if !legal_transition(older.stage, ManifestStage::Replaced) {
            return Err(SandboxError::Other(format!(
                "illegal transition {:?} -> Replaced",
                older.stage
            )));
        }
        older.stage = ManifestStage::Replaced;
        older.closed_at = Some(when.clone());
        older.successor = Some(successor_id.to_string());
        older.events.push(ManifestEvent {
            at: when,
            actor,
            stage: ManifestStage::Replaced,
            note: format!("replaced by {successor_id}"),
        });
        Ok(older.clone())
    }

    /// Delete the manifest.
    pub fn delete(
        &self,
        manifest_id: &str,
        actor: impl Into<String>,
        at: impl Into<String>,
        reason: impl Into<String>,
    ) -> SandboxResult<KubernetesManifest> {
        self.simple_transition(manifest_id, ManifestStage::Deleted, actor, at, reason)
    }

    fn simple_transition(
        &self,
        manifest_id: &str,
        new_stage: ManifestStage,
        actor: impl Into<String>,
        at: impl Into<String>,
        note: impl Into<String>,
    ) -> SandboxResult<KubernetesManifest> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("k8s manifest register poisoned".into()))?;
        let m = g
            .get_mut(manifest_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown manifest {manifest_id}")))?;
        if !legal_transition(m.stage, new_stage) {
            return Err(SandboxError::Other(format!(
                "illegal transition {:?} -> {:?}",
                m.stage, new_stage
            )));
        }
        let when = at.into();
        m.stage = new_stage;
        match new_stage {
            ManifestStage::Applied => {
                m.applied_at = Some(when.clone());
            }
            ManifestStage::Active => {
                m.activated_at = Some(when.clone());
            }
            ManifestStage::Replaced | ManifestStage::Deleted => {
                m.closed_at = Some(when.clone());
            }
            _ => {}
        }
        m.events.push(ManifestEvent {
            at: when,
            actor: actor.into(),
            stage: new_stage,
            note: note.into(),
        });
        Ok(m.clone())
    }

    /// Set storage URI for the YAML.
    pub fn set_manifest_uri(
        &self,
        manifest_id: &str,
        uri: impl Into<String>,
    ) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("k8s manifest register poisoned".into()))?;
        let m = g
            .get_mut(manifest_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown manifest {manifest_id}")))?;
        m.manifest_uri = Some(uri.into());
        Ok(())
    }

    /// Link to a Terraform plan id.
    pub fn set_linked_plan(
        &self,
        manifest_id: &str,
        plan_id: impl Into<String>,
    ) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("k8s manifest register poisoned".into()))?;
        let m = g
            .get_mut(manifest_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown manifest {manifest_id}")))?;
        m.linked_plan_id = Some(plan_id.into());
        Ok(())
    }

    /// Link to a deployment id.
    pub fn set_linked_deployment(
        &self,
        manifest_id: &str,
        deployment_id: impl Into<String>,
    ) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("k8s manifest register poisoned".into()))?;
        let m = g
            .get_mut(manifest_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown manifest {manifest_id}")))?;
        m.linked_deployment_id = Some(deployment_id.into());
        Ok(())
    }

    /// Add a tag (deduplicated).
    pub fn add_tag(&self, manifest_id: &str, tag: impl Into<String>) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("k8s manifest register poisoned".into()))?;
        let m = g
            .get_mut(manifest_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown manifest {manifest_id}")))?;
        let tag = tag.into();
        if !m.tags.contains(&tag) {
            m.tags.push(tag);
        }
        Ok(())
    }

    /// Look up.
    pub fn get(&self, manifest_id: &str) -> Option<KubernetesManifest> {
        let g = self.inner.read().ok()?;
        g.get(manifest_id).cloned()
    }

    /// All manifests.
    pub fn all(&self) -> Vec<KubernetesManifest> {
        match self.inner.read() {
            Ok(g) => g.values().cloned().collect(),
            Err(_) => Vec::new(),
        }
    }

    /// Manifests for a tenant.
    pub fn for_tenant(&self, tenant_id: &str) -> Vec<KubernetesManifest> {
        self.all()
            .into_iter()
            .filter(|m| m.tenant_id == tenant_id)
            .collect()
    }

    /// Manifests in a cluster.
    pub fn for_cluster(&self, cluster: &str) -> Vec<KubernetesManifest> {
        self.all()
            .into_iter()
            .filter(|m| m.cluster == cluster)
            .collect()
    }

    /// Manifests in a (cluster, namespace).
    pub fn for_namespace(
        &self,
        cluster: &str,
        namespace: &str,
    ) -> Vec<KubernetesManifest> {
        self.all()
            .into_iter()
            .filter(|m| m.cluster == cluster && m.namespace == namespace)
            .collect()
    }

    /// Manifests by kind.
    pub fn by_kind(&self, kind: ManifestKind) -> Vec<KubernetesManifest> {
        self.all().into_iter().filter(|m| m.kind == kind).collect()
    }

    /// Active manifests.
    pub fn active(&self) -> Vec<KubernetesManifest> {
        self.all()
            .into_iter()
            .filter(|m| m.stage.is_active())
            .collect()
    }

    /// Active workload manifests with at least one un-pinned image
    /// (security best-practice violation).
    pub fn unpinned_workloads(&self) -> Vec<KubernetesManifest> {
        self.all()
            .into_iter()
            .filter(|m| {
                m.stage.is_active()
                    && m.kind.runs_workload()
                    && !m.images.is_empty()
                    && !m.all_digests_pinned()
            })
            .collect()
    }

    /// Number of registered manifests.
    pub fn count(&self) -> usize {
        self.inner.read().map(|g| g.len()).unwrap_or(0)
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest(id: &str, kind: ManifestKind) -> KubernetesManifest {
        KubernetesManifest::new(
            id,
            "tenant-a",
            "prod-us-east",
            "billing",
            kind,
            format!("res-{id}"),
            "abc123",
            "2025-04-01T00:00:00Z",
        )
    }

    fn img(name: &str, tag: &str, digest: Option<&str>) -> ContainerImage {
        ContainerImage {
            name: name.into(),
            tag: tag.into(),
            digest: digest.map(String::from),
        }
    }

    fn rbac(subject: &str, role: &str) -> RbacBinding {
        RbacBinding {
            subject_kind: "ServiceAccount".into(),
            subject_name: subject.into(),
            role: role.into(),
        }
    }

    #[test]
    fn register_and_get() {
        let r = KubernetesManifestRegister::new();
        r.register(manifest("m1", ManifestKind::Deployment)).unwrap();
        assert!(r.get("m1").is_some());
    }

    #[test]
    fn duplicate_register_errors() {
        let r = KubernetesManifestRegister::new();
        r.register(manifest("m1", ManifestKind::Deployment)).unwrap();
        let err = r
            .register(manifest("m1", ManifestKind::Deployment))
            .unwrap_err();
        assert!(format!("{err}").contains("already registered"));
    }

    #[test]
    fn must_start_drafted() {
        let mut m = manifest("m1", ManifestKind::Deployment);
        m.stage = ManifestStage::Active;
        let r = KubernetesManifestRegister::new();
        let err = r.register(m).unwrap_err();
        assert!(format!("{err}").contains("must start Drafted"));
    }

    #[test]
    fn legal_transitions() {
        use ManifestStage::*;
        assert!(legal_transition(Drafted, Applied));
        assert!(legal_transition(Drafted, Deleted));
        assert!(legal_transition(Applied, Active));
        assert!(legal_transition(Applied, Deleted));
        assert!(legal_transition(Active, Replaced));
        assert!(legal_transition(Active, Deleted));
        // illegal
        assert!(!legal_transition(Drafted, Active));
        assert!(!legal_transition(Replaced, Active));
        assert!(!legal_transition(Deleted, Active));
    }

    #[test]
    fn happy_path_lifecycle() {
        let r = KubernetesManifestRegister::new();
        r.register(manifest("m1", ManifestKind::Deployment)).unwrap();
        r.add_image(
            "m1",
            img("registry/api", "v3.2.1", Some("sha256:deadbeef")),
        )
        .unwrap();
        r.add_rbac("m1", rbac("api-sa", "api-role")).unwrap();
        r.apply("m1", "ops", "2025-04-02T00:00:00Z").unwrap();
        let m = r.activate("m1", "controller", "2025-04-02T00:01:00Z").unwrap();
        assert_eq!(m.stage, ManifestStage::Active);
        assert!(m.stage.is_active());
        assert!(m.all_digests_pinned());
        assert_eq!(m.events.len(), 2); // applied, activated
    }

    #[test]
    fn add_image_after_drafted_errors() {
        let r = KubernetesManifestRegister::new();
        r.register(manifest("m1", ManifestKind::Deployment)).unwrap();
        r.apply("m1", "ops", "2025-04-02T00:00:00Z").unwrap();
        let err = r.add_image("m1", img("x", "v1", None)).unwrap_err();
        assert!(format!("{err}").contains("cannot add image"));
    }

    #[test]
    fn add_rbac_after_drafted_errors() {
        let r = KubernetesManifestRegister::new();
        r.register(manifest("m1", ManifestKind::Role)).unwrap();
        r.apply("m1", "ops", "2025-04-02T00:00:00Z").unwrap();
        let err = r.add_rbac("m1", rbac("x", "y")).unwrap_err();
        assert!(format!("{err}").contains("cannot add rbac"));
    }

    #[test]
    fn replace_with_links_chain() {
        let r = KubernetesManifestRegister::new();
        r.register(manifest("m1", ManifestKind::Deployment)).unwrap();
        r.apply("m1", "ops", "2025-04-02T00:00:00Z").unwrap();
        r.activate("m1", "controller", "2025-04-02T00:01:00Z").unwrap();
        r.register(manifest("m2", ManifestKind::Deployment)).unwrap();
        r.replace_with("m1", "m2", "ops", "2025-04-10T00:00:00Z").unwrap();
        let old = r.get("m1").unwrap();
        assert_eq!(old.stage, ManifestStage::Replaced);
        assert_eq!(old.successor.as_deref(), Some("m2"));
        assert!(old.stage.is_terminal());
    }

    #[test]
    fn replace_unknown_successor_errors() {
        let r = KubernetesManifestRegister::new();
        r.register(manifest("m1", ManifestKind::Deployment)).unwrap();
        r.apply("m1", "ops", "2025-04-02T00:00:00Z").unwrap();
        r.activate("m1", "controller", "2025-04-02T00:01:00Z").unwrap();
        let err = r
            .replace_with("m1", "ghost", "ops", "2025-04-10T00:00:00Z")
            .unwrap_err();
        assert!(format!("{err}").contains("unknown successor"));
    }

    #[test]
    fn replace_must_be_active() {
        let r = KubernetesManifestRegister::new();
        r.register(manifest("m1", ManifestKind::Deployment)).unwrap();
        r.register(manifest("m2", ManifestKind::Deployment)).unwrap();
        let err = r
            .replace_with("m1", "m2", "ops", "2025-04-10T00:00:00Z")
            .unwrap_err();
        assert!(format!("{err}").contains("illegal transition"));
    }

    #[test]
    fn delete_from_drafted() {
        let r = KubernetesManifestRegister::new();
        r.register(manifest("m1", ManifestKind::Deployment)).unwrap();
        let m = r
            .delete("m1", "ops", "2025-04-02T00:00:00Z", "discarded draft")
            .unwrap();
        assert_eq!(m.stage, ManifestStage::Deleted);
    }

    #[test]
    fn delete_from_applied_or_active() {
        let r = KubernetesManifestRegister::new();
        r.register(manifest("m1", ManifestKind::Deployment)).unwrap();
        r.apply("m1", "ops", "2025-04-02T00:00:00Z").unwrap();
        let m = r
            .delete("m1", "ops", "2025-04-02T01:00:00Z", "rollback")
            .unwrap();
        assert_eq!(m.stage, ManifestStage::Deleted);

        let r = KubernetesManifestRegister::new();
        r.register(manifest("m2", ManifestKind::Deployment)).unwrap();
        r.apply("m2", "ops", "2025-04-02T00:00:00Z").unwrap();
        r.activate("m2", "controller", "2025-04-02T00:01:00Z").unwrap();
        let m = r
            .delete("m2", "ops", "2025-04-10T00:00:00Z", "decommissioned")
            .unwrap();
        assert_eq!(m.stage, ManifestStage::Deleted);
    }

    #[test]
    fn unpinned_workloads_query() {
        let r = KubernetesManifestRegister::new();
        // Pinned, active workload
        r.register(manifest("good", ManifestKind::Deployment)).unwrap();
        r.add_image("good", img("api", "v1", Some("sha256:abc"))).unwrap();
        r.apply("good", "ops", "2025-04-02T00:00:00Z").unwrap();
        r.activate("good", "ctrl", "2025-04-02T00:01:00Z").unwrap();
        // Unpinned, active workload
        r.register(manifest("bad", ManifestKind::Deployment)).unwrap();
        r.add_image("bad", img("api", "latest", None)).unwrap();
        r.apply("bad", "ops", "2025-04-02T00:00:00Z").unwrap();
        r.activate("bad", "ctrl", "2025-04-02T00:01:00Z").unwrap();
        // Unpinned but only Drafted
        r.register(manifest("draft", ManifestKind::Deployment)).unwrap();
        r.add_image("draft", img("api", "latest", None)).unwrap();
        // Active but ConfigMap (not workload)
        r.register(manifest("cfg", ManifestKind::ConfigMap)).unwrap();
        r.apply("cfg", "ops", "2025-04-02T00:00:00Z").unwrap();
        r.activate("cfg", "ctrl", "2025-04-02T00:01:00Z").unwrap();

        let unpinned = r.unpinned_workloads();
        let ids: Vec<_> = unpinned.iter().map(|m| m.manifest_id.clone()).collect();
        assert_eq!(ids, vec!["bad"]);
    }

    #[test]
    fn unpinned_images_helper() {
        let r = KubernetesManifestRegister::new();
        r.register(manifest("m1", ManifestKind::Deployment)).unwrap();
        r.add_image("m1", img("a", "v1", Some("sha256:111"))).unwrap();
        r.add_image("m1", img("b", "v2", None)).unwrap();
        let m = r.get("m1").unwrap();
        assert!(!m.all_digests_pinned());
        assert_eq!(m.unpinned_images().len(), 1);
        assert_eq!(m.unpinned_images()[0].name, "b");
    }

    #[test]
    fn set_uri_link_tag() {
        let r = KubernetesManifestRegister::new();
        r.register(manifest("m1", ManifestKind::Deployment)).unwrap();
        r.set_manifest_uri("m1", "git://repo/m1.yaml").unwrap();
        r.set_linked_plan("m1", "TF-PLAN-007").unwrap();
        r.set_linked_deployment("m1", "DEPLOY-007").unwrap();
        r.add_tag("m1", "production").unwrap();
        r.add_tag("m1", "production").unwrap(); // dedupe
        let m = r.get("m1").unwrap();
        assert_eq!(m.manifest_uri.as_deref(), Some("git://repo/m1.yaml"));
        assert_eq!(m.linked_plan_id.as_deref(), Some("TF-PLAN-007"));
        assert_eq!(m.linked_deployment_id.as_deref(), Some("DEPLOY-007"));
        assert_eq!(m.tags, vec!["production"]);
    }

    #[test]
    fn unknown_manifest_errors() {
        let r = KubernetesManifestRegister::new();
        let err = r.set_manifest_uri("nope", "x").unwrap_err();
        assert!(format!("{err}").contains("unknown manifest"));
    }

    #[test]
    fn for_cluster_namespace_filters() {
        let r = KubernetesManifestRegister::new();
        r.register(manifest("m1", ManifestKind::Deployment)).unwrap();
        let mut other = manifest("m2", ManifestKind::Service);
        other.cluster = "staging".into();
        other.namespace = "default".into();
        r.register(other).unwrap();
        assert_eq!(r.for_cluster("prod-us-east").len(), 1);
        assert_eq!(r.for_cluster("staging").len(), 1);
        assert_eq!(r.for_namespace("prod-us-east", "billing").len(), 1);
        assert_eq!(r.for_namespace("staging", "default").len(), 1);
        assert_eq!(r.for_namespace("prod-us-east", "default").len(), 0);
    }

    #[test]
    fn by_kind_filter() {
        let r = KubernetesManifestRegister::new();
        r.register(manifest("d", ManifestKind::Deployment)).unwrap();
        r.register(manifest("s", ManifestKind::Service)).unwrap();
        r.register(manifest("ss", ManifestKind::StatefulSet)).unwrap();
        assert_eq!(r.by_kind(ManifestKind::Deployment).len(), 1);
        assert_eq!(r.by_kind(ManifestKind::Service).len(), 1);
        assert_eq!(r.by_kind(ManifestKind::StatefulSet).len(), 1);
        assert_eq!(r.by_kind(ManifestKind::CronJob).len(), 0);
    }

    #[test]
    fn for_tenant_filter() {
        let r = KubernetesManifestRegister::new();
        r.register(manifest("m1", ManifestKind::Deployment)).unwrap();
        let mut other = manifest("m2", ManifestKind::Deployment);
        other.tenant_id = "tenant-b".into();
        r.register(other).unwrap();
        assert_eq!(r.for_tenant("tenant-a").len(), 1);
        assert_eq!(r.for_tenant("tenant-b").len(), 1);
    }

    #[test]
    fn active_filter() {
        let r = KubernetesManifestRegister::new();
        r.register(manifest("m1", ManifestKind::Deployment)).unwrap();
        r.apply("m1", "ops", "2025-04-02T00:00:00Z").unwrap();
        r.activate("m1", "ctrl", "2025-04-02T00:01:00Z").unwrap();
        r.register(manifest("m2", ManifestKind::Deployment)).unwrap();
        assert_eq!(r.active().len(), 1);
    }

    #[test]
    fn kind_helpers() {
        for k in [
            ManifestKind::Deployment,
            ManifestKind::StatefulSet,
            ManifestKind::DaemonSet,
            ManifestKind::Job,
            ManifestKind::CronJob,
        ] {
            assert!(k.runs_workload());
        }
        for k in [ManifestKind::Service, ManifestKind::ConfigMap, ManifestKind::Ingress] {
            assert!(!k.runs_workload());
        }
        for k in [
            ManifestKind::Role,
            ManifestKind::RoleBinding,
            ManifestKind::ClusterRole,
            ManifestKind::ClusterRoleBinding,
        ] {
            assert!(k.is_rbac());
        }
        assert!(!ManifestKind::Deployment.is_rbac());
    }

    #[test]
    fn count_tracks() {
        let r = KubernetesManifestRegister::new();
        assert_eq!(r.count(), 0);
        r.register(manifest("m1", ManifestKind::Deployment)).unwrap();
        assert_eq!(r.count(), 1);
    }

    #[test]
    fn manifest_serde() {
        let m = manifest("m1", ManifestKind::Deployment);
        let j = serde_json::to_string(&m).unwrap();
        let back: KubernetesManifest = serde_json::from_str(&j).unwrap();
        assert_eq!(m, back);
    }

    #[test]
    fn enums_serde() {
        for k in [
            ManifestKind::Deployment,
            ManifestKind::StatefulSet,
            ManifestKind::DaemonSet,
            ManifestKind::Job,
            ManifestKind::CronJob,
            ManifestKind::Service,
            ManifestKind::Ingress,
            ManifestKind::ConfigMap,
            ManifestKind::Secret,
            ManifestKind::Role,
            ManifestKind::RoleBinding,
            ManifestKind::ClusterRole,
            ManifestKind::ClusterRoleBinding,
            ManifestKind::NetworkPolicy,
            ManifestKind::PodSecurityPolicy,
            ManifestKind::Namespace,
            ManifestKind::Other,
        ] {
            assert_eq!(
                k,
                serde_json::from_str::<ManifestKind>(&serde_json::to_string(&k).unwrap()).unwrap()
            );
        }
        for s in [
            ManifestStage::Drafted,
            ManifestStage::Applied,
            ManifestStage::Active,
            ManifestStage::Replaced,
            ManifestStage::Deleted,
        ] {
            assert_eq!(
                s,
                serde_json::from_str::<ManifestStage>(&serde_json::to_string(&s).unwrap()).unwrap()
            );
        }
    }
}
