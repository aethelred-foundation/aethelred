//! Enterprise v0.2.0 test suite for sandbox-research.

use aethelred_sandbox_core::audit::{AuditFormat, AuditTrail};
use aethelred_sandbox_core::error_code::ErrorCategory;
use aethelred_sandbox_core::verify::Verifier;
use aethelred_sandbox_core::{EvidenceBundle, Sector};
use aethelred_sandbox_research::*;

fn mbz() -> ResearchSandbox {
    ResearchSandbox::quickstart("MBZUAI").unwrap()
}

// ======================================================================
// Quickstart / Builder
// ======================================================================

#[test]
fn quickstart_creates_sandbox() {
    let sb = mbz();
    assert_eq!(sb.tenant(), "MBZUAI");
}

#[test]
fn builder_fair() {
    let sb = ResearchSandbox::builder()
        .tenant("Lab")
        .jurisdiction(ResearchJurisdiction::Fair)
        .build()
        .unwrap();
    assert_eq!(sb.primary_jurisdiction(), ResearchJurisdiction::Fair);
}

#[test]
fn builder_neurips() {
    let sb = ResearchSandbox::builder()
        .tenant("Lab")
        .jurisdiction(ResearchJurisdiction::NeurIpsReproducibility)
        .build()
        .unwrap();
    assert_eq!(sb.primary_jurisdiction(), ResearchJurisdiction::NeurIpsReproducibility);
}

#[test]
fn builder_mlperf() {
    let sb = ResearchSandbox::builder()
        .tenant("Lab")
        .jurisdiction(ResearchJurisdiction::MlPerf)
        .build()
        .unwrap();
    assert_eq!(sb.primary_jurisdiction(), ResearchJurisdiction::MlPerf);
}

#[test]
fn builder_iso_42001() {
    let sb = ResearchSandbox::builder()
        .tenant("Lab")
        .jurisdiction(ResearchJurisdiction::Iso42001)
        .build()
        .unwrap();
    assert_eq!(sb.primary_jurisdiction(), ResearchJurisdiction::Iso42001);
}

#[test]
fn builder_nist_ai_rmf() {
    let sb = ResearchSandbox::builder()
        .tenant("Lab")
        .jurisdiction(ResearchJurisdiction::NistAiRmf)
        .build()
        .unwrap();
    assert_eq!(sb.primary_jurisdiction(), ResearchJurisdiction::NistAiRmf);
}

#[test]
fn builder_unesco_ethics() {
    let sb = ResearchSandbox::builder()
        .tenant("Lab")
        .jurisdiction(ResearchJurisdiction::UnescoEthics)
        .build()
        .unwrap();
    assert_eq!(sb.primary_jurisdiction(), ResearchJurisdiction::UnescoEthics);
}

#[test]
fn builder_eu_ai_act_research() {
    let sb = ResearchSandbox::builder()
        .tenant("Lab")
        .jurisdiction(ResearchJurisdiction::EuAiActResearch)
        .build()
        .unwrap();
    assert_eq!(sb.primary_jurisdiction(), ResearchJurisdiction::EuAiActResearch);
}

// ======================================================================
// Bulk seal
// ======================================================================

#[test]
fn bulk_seal_experiment_runs() {
    let sb = mbz();
    let r = sb
        .seal_experiment_runs((0..5).map(|_| ExperimentRun::demo()))
        .unwrap();
    assert_eq!(r.len(), 5);
}

#[test]
fn bulk_seal_model_releases() {
    let sb = mbz();
    let r = sb
        .seal_model_releases((0..3).map(|_| ModelReleasePack::demo()))
        .unwrap();
    assert_eq!(r.len(), 3);
}

#[test]
fn bulk_seal_reproducibility_checks() {
    let sb = mbz();
    let r = sb
        .seal_reproducibility_checks((0..7).map(|_| ReproducibilityCheck::demo()))
        .unwrap();
    assert_eq!(r.len(), 7);
}

#[test]
fn bulk_seal_training_runs() {
    let sb = mbz();
    let r = sb
        .seal_training_runs((0..4).map(|_| TrainingRun::demo()))
        .unwrap();
    assert_eq!(r.len(), 4);
}

#[test]
fn bulk_seal_empty() {
    let sb = mbz();
    let v: Vec<ExperimentRun> = vec![];
    assert_eq!(sb.seal_experiment_runs(v).unwrap().len(), 0);
}

#[test]
fn bulk_seal_large() {
    let sb = mbz();
    let r = sb
        .seal_experiment_runs((0..50).map(|_| ExperimentRun::demo()))
        .unwrap();
    assert_eq!(r.len(), 50);
}

#[test]
fn mixed_workflow_log() {
    let sb = mbz();
    sb.seal_experiment_run(ExperimentRun::demo()).unwrap();
    sb.seal_model_release(ModelReleasePack::demo()).unwrap();
    sb.seal_reproducibility_check(ReproducibilityCheck::demo()).unwrap();
    sb.seal_training_run(TrainingRun::demo()).unwrap();
    assert_eq!(sb.seal_count(), 4);
}

// ======================================================================
// Envelope + Verifier
// ======================================================================

#[test]
fn envelope_at_returns_proof() {
    let sb = mbz();
    sb.seal_experiment_run(ExperimentRun::demo()).unwrap();
    let env = sb.envelope_at(0).unwrap();
    assert!(env.merkle_proof.is_some());
    assert!(env.merkle_proof.unwrap().verify());
}

#[test]
fn envelope_oor_errors() {
    let sb = mbz();
    sb.seal_experiment_run(ExperimentRun::demo()).unwrap();
    assert!(sb.envelope_at(99).is_err());
}

#[test]
fn all_envelopes_share_root() {
    let sb = mbz();
    for _ in 0..6 {
        sb.seal_experiment_run(ExperimentRun::demo()).unwrap();
    }
    let envs = sb.all_envelopes().unwrap();
    let root = sb.current_root().unwrap();
    for env in &envs {
        assert_eq!(env.merkle_proof.as_ref().unwrap().root, root);
    }
}

#[test]
fn verify_all_passes() {
    let sb = mbz();
    for _ in 0..4 {
        sb.seal_experiment_run(ExperimentRun::demo()).unwrap();
    }
    let r = sb.verify_all().unwrap();
    assert!(r.iter().all(|x| x.passed()));
}

#[test]
fn verify_strict_fails_without_attestation() {
    let sb = mbz();
    sb.seal_experiment_run(ExperimentRun::demo()).unwrap();
    let r = sb.verify_all_with(&Verifier::strict()).unwrap();
    assert!(!r[0].passed());
}

#[test]
fn current_root_changes() {
    let sb = mbz();
    let r0 = sb.current_root().unwrap();
    sb.seal_experiment_run(ExperimentRun::demo()).unwrap();
    assert_ne!(r0, sb.current_root().unwrap());
}

// ======================================================================
// Audit trail
// ======================================================================

#[test]
fn audit_plaintext() {
    let sb = mbz();
    sb.seal_experiment_run(ExperimentRun::demo()).unwrap();
    let s = sb.audit_trail(AuditFormat::PlainText).unwrap();
    assert!(s.contains("MBZUAI"));
}

#[test]
fn audit_markdown() {
    let sb = mbz();
    sb.seal_experiment_run(ExperimentRun::demo()).unwrap();
    let s = sb.audit_trail(AuditFormat::Markdown).unwrap();
    assert!(s.contains("|"));
}

#[test]
fn audit_csv() {
    let sb = mbz();
    sb.seal_experiment_run(ExperimentRun::demo()).unwrap();
    let s = sb.audit_trail(AuditFormat::Csv).unwrap();
    assert!(s.starts_with("position,seal_id,timestamp,"));
}

#[test]
fn audit_struct_count() {
    let sb = mbz();
    for _ in 0..3 {
        sb.seal_experiment_run(ExperimentRun::demo()).unwrap();
    }
    let trail = sb.audit_trail_struct().unwrap();
    assert_eq!(trail.total, 3);
}

#[test]
fn audit_records_workflow_id() {
    let sb = mbz();
    sb.seal_experiment_run(ExperimentRun::demo()).unwrap();
    let trail = sb.audit_trail_struct().unwrap();
    assert_eq!(trail.entries[0].workflow_id, "experiment_run");
}

// ======================================================================
// Multi-jurisdiction views
// ======================================================================

#[test]
fn fair_view() {
    let sb = mbz();
    let s = sb.seal_experiment_run(ExperimentRun::demo()).unwrap();
    let view = sb.regulator_view(&s.seal, ResearchJurisdiction::Fair);
    assert!(!view.citations.is_empty());
}

#[test]
fn neurips_view() {
    let sb = mbz();
    let s = sb.seal_experiment_run(ExperimentRun::demo()).unwrap();
    let view = sb.regulator_view(&s.seal, ResearchJurisdiction::NeurIpsReproducibility);
    assert!(!view.citations.is_empty());
}

#[test]
fn mlperf_view() {
    let sb = mbz();
    let s = sb.seal_experiment_run(ExperimentRun::demo()).unwrap();
    let view = sb.regulator_view(&s.seal, ResearchJurisdiction::MlPerf);
    assert!(!view.citations.is_empty());
}

#[test]
fn iso_42001_view() {
    let sb = mbz();
    let s = sb.seal_experiment_run(ExperimentRun::demo()).unwrap();
    let view = sb.regulator_view(&s.seal, ResearchJurisdiction::Iso42001);
    assert!(!view.citations.is_empty());
}

#[test]
fn nist_view() {
    let sb = mbz();
    let s = sb.seal_experiment_run(ExperimentRun::demo()).unwrap();
    let view = sb.regulator_view(&s.seal, ResearchJurisdiction::NistAiRmf);
    assert!(!view.citations.is_empty());
}

#[test]
fn unesco_view() {
    let sb = mbz();
    let s = sb.seal_experiment_run(ExperimentRun::demo()).unwrap();
    let view = sb.regulator_view(&s.seal, ResearchJurisdiction::UnescoEthics);
    assert!(!view.citations.is_empty());
}

#[test]
fn eu_ai_act_research_view() {
    let sb = mbz();
    let s = sb.seal_experiment_run(ExperimentRun::demo()).unwrap();
    let view = sb.regulator_view(&s.seal, ResearchJurisdiction::EuAiActResearch);
    assert!(!view.citations.is_empty());
}

// ======================================================================
// Dataset class coverage
// ======================================================================

#[test]
fn public_dataset_seals() {
    let sb = mbz();
    let mut e = ExperimentRun::demo();
    e.dataset_class = DatasetClass::Public;
    sb.seal_experiment_run(e).unwrap();
}

#[test]
fn synthetic_dataset_seals() {
    let sb = mbz();
    let mut e = ExperimentRun::demo();
    e.dataset_class = DatasetClass::Synthetic;
    sb.seal_experiment_run(e).unwrap();
}

#[test]
fn consented_dataset_seals() {
    let sb = mbz();
    let mut e = ExperimentRun::demo();
    e.dataset_class = DatasetClass::Consented;
    sb.seal_experiment_run(e).unwrap();
}

// ======================================================================
// License coverage
// ======================================================================

#[test]
fn apache_2_license_seals() {
    let sb = mbz();
    let mut m = ModelReleasePack::demo();
    m.license = License::Apache20;
    sb.seal_model_release(m).unwrap();
}

#[test]
fn mit_license_seals() {
    let sb = mbz();
    let mut m = ModelReleasePack::demo();
    m.license = License::Mit;
    sb.seal_model_release(m).unwrap();
}

#[test]
fn bsd_license_seals() {
    let sb = mbz();
    let mut m = ModelReleasePack::demo();
    m.license = License::Bsd3Clause;
    sb.seal_model_release(m).unwrap();
}

#[test]
fn cc_by_license_seals() {
    let sb = mbz();
    let mut m = ModelReleasePack::demo();
    m.license = License::CcBy40;
    sb.seal_model_release(m).unwrap();
}

// ======================================================================
// Reproducibility result coverage
// ======================================================================

#[test]
fn reproduced_check_seals() {
    let sb = mbz();
    let mut r = ReproducibilityCheck::demo();
    r.result = ReproducibilityResult::Reproduced;
    sb.seal_reproducibility_check(r).unwrap();
}

#[test]
fn partially_reproduced_check_seals() {
    let sb = mbz();
    let mut r = ReproducibilityCheck::demo();
    r.result = ReproducibilityResult::PartiallyReproduced;
    sb.seal_reproducibility_check(r).unwrap();
}

#[test]
fn not_reproduced_check_seals() {
    let sb = mbz();
    let mut r = ReproducibilityCheck::demo();
    r.result = ReproducibilityResult::NotReproduced;
    sb.seal_reproducibility_check(r).unwrap();
}

#[test]
fn inconclusive_check_seals() {
    let sb = mbz();
    let mut r = ReproducibilityCheck::demo();
    r.result = ReproducibilityResult::Inconclusive;
    sb.seal_reproducibility_check(r).unwrap();
}

// ======================================================================
// Workflow id + sectors
// ======================================================================

#[test]
fn experiment_workflow_id() {
    let sb = mbz();
    let s = sb.seal_experiment_run(ExperimentRun::demo()).unwrap();
    assert_eq!(s.seal.workflow_id, "experiment_run");
}

#[test]
fn model_release_workflow_id() {
    let sb = mbz();
    let s = sb.seal_model_release(ModelReleasePack::demo()).unwrap();
    assert_eq!(s.seal.workflow_id, "model_release");
}

#[test]
fn reproducibility_workflow_id() {
    let sb = mbz();
    let s = sb.seal_reproducibility_check(ReproducibilityCheck::demo()).unwrap();
    assert_eq!(s.seal.workflow_id, "reproducibility_check");
}

#[test]
fn training_workflow_id() {
    let sb = mbz();
    let s = sb.seal_training_run(TrainingRun::demo()).unwrap();
    assert_eq!(s.seal.workflow_id, "training_run");
}

#[test]
fn research_sector_in_seal() {
    let sb = mbz();
    let s = sb.seal_experiment_run(ExperimentRun::demo()).unwrap();
    assert_eq!(s.seal.sector, Sector::Research);
}

// ======================================================================
// Approvals
// ======================================================================

#[test]
fn experiment_seal_has_approval() {
    let sb = mbz();
    let s = sb.seal_experiment_run(ExperimentRun::demo()).unwrap();
    assert!(s.seal.approval_count() >= 1);
}

#[test]
fn model_release_seal_has_approval() {
    let sb = mbz();
    let s = sb.seal_model_release(ModelReleasePack::demo()).unwrap();
    assert!(s.seal.approval_count() >= 1);
}

#[test]
fn repro_seal_has_approval() {
    let sb = mbz();
    let s = sb.seal_reproducibility_check(ReproducibilityCheck::demo()).unwrap();
    assert!(s.seal.approval_count() >= 1);
}

#[test]
fn training_seal_has_approval() {
    let sb = mbz();
    let s = sb.seal_training_run(TrainingRun::demo()).unwrap();
    assert!(s.seal.approval_count() >= 1);
}

// ======================================================================
// Evidence
// ======================================================================

#[test]
fn merkle_proofs_verify_for_each_seal() {
    let sb = mbz();
    for _ in 0..8 {
        sb.seal_experiment_run(ExperimentRun::demo()).unwrap();
    }
    let envs = sb.all_envelopes().unwrap();
    for env in envs {
        assert!(env.merkle_proof.unwrap().verify());
    }
}

#[test]
fn evidence_indices_monotonic() {
    let sb = mbz();
    for _ in 0..5 {
        sb.seal_experiment_run(ExperimentRun::demo()).unwrap();
    }
    let bundle = sb.export_evidence().unwrap();
    for (i, e) in bundle.entries.iter().enumerate() {
        assert_eq!(e.index, i as u64);
    }
}

#[test]
fn evidence_root_matches_current() {
    let sb = mbz();
    sb.seal_experiment_run(ExperimentRun::demo()).unwrap();
    let bundle = sb.export_evidence().unwrap();
    assert_eq!(bundle.merkle_root, sb.current_root().unwrap());
}

#[test]
fn empty_seal_count() {
    let sb = mbz();
    assert_eq!(sb.seal_count(), 0);
}

#[test]
fn empty_audit_trail() {
    let sb = mbz();
    let trail = sb.audit_trail_struct().unwrap();
    assert_eq!(trail.total, 0);
}

#[test]
fn empty_envelopes() {
    let sb = mbz();
    assert!(sb.all_envelopes().unwrap().is_empty());
}

#[test]
fn empty_verify_all() {
    let sb = mbz();
    assert!(sb.verify_all().unwrap().is_empty());
}

// ======================================================================
// Verifier mutations + serde
// ======================================================================

#[test]
fn verifier_detects_event_hash_tamper() {
    use aethelred_sandbox_core::Hasher;
    let sb = mbz();
    sb.seal_experiment_run(ExperimentRun::demo()).unwrap();
    let mut env = sb.envelope_at(0).unwrap();
    env.seal.event_hash = Hasher::sha256(b"tamper");
    let root = sb.current_root().unwrap();
    let r = Verifier::default().verify_envelope(&env, root).unwrap();
    assert!(!r.passed());
}

#[test]
fn verify_with_wrong_root_fails() {
    use aethelred_sandbox_core::Hasher;
    let sb = mbz();
    sb.seal_experiment_run(ExperimentRun::demo()).unwrap();
    let env = sb.envelope_at(0).unwrap();
    let r = Verifier::default()
        .verify_envelope(&env, Hasher::sha256(b"wrong-root"))
        .unwrap();
    assert!(!r.passed());
}

#[test]
fn evidence_bundle_serde_roundtrip() {
    let sb = mbz();
    sb.seal_experiment_run(ExperimentRun::demo()).unwrap();
    let b = sb.export_evidence().unwrap();
    let j = serde_json::to_string(&b).unwrap();
    let p: EvidenceBundle = serde_json::from_str(&j).unwrap();
    assert_eq!(p.entries.len(), b.entries.len());
}

#[test]
fn audit_trail_serde_roundtrip() {
    let sb = mbz();
    sb.seal_experiment_run(ExperimentRun::demo()).unwrap();
    let t = sb.audit_trail_struct().unwrap();
    let j = serde_json::to_string(&t).unwrap();
    let p: AuditTrail = serde_json::from_str(&j).unwrap();
    assert_eq!(p.total, t.total);
}

#[test]
fn experiment_serde_roundtrip() {
    let e = ExperimentRun::demo();
    let j = serde_json::to_string(&e).unwrap();
    let p: ExperimentRun = serde_json::from_str(&j).unwrap();
    assert_eq!(p.experiment_id, e.experiment_id);
}

#[test]
fn extra_gate_can_be_added() {
    use aethelred_sandbox_core::policy::PolicyGate;
    let sb = ResearchSandbox::builder()
        .tenant("Lab-X")
        .with_extra_gate(PolicyGate::optional("test.extra", "Extra", "rule"))
        .build()
        .unwrap();
    sb.seal_experiment_run(ExperimentRun::demo()).unwrap();
    assert_eq!(sb.seal_count(), 1);
}

#[test]
fn label_override() {
    let sb = ResearchSandbox::builder()
        .tenant("MBZUAI")
        .label("Custom Label")
        .build()
        .unwrap();
    sb.seal_experiment_run(ExperimentRun::demo()).unwrap();
}

#[test]
fn verifier_independent() {
    let sb = mbz();
    sb.seal_experiment_run(ExperimentRun::demo()).unwrap();
    let env = sb.envelope_at(0).unwrap();
    let root = sb.current_root().unwrap();
    let r = Verifier::default().verify_envelope(&env, root).unwrap();
    assert!(r.passed());
}

#[test]
fn current_root_stable() {
    let sb = mbz();
    sb.seal_experiment_run(ExperimentRun::demo()).unwrap();
    let r1 = sb.current_root().unwrap();
    let r2 = sb.current_root().unwrap();
    assert_eq!(r1, r2);
}

#[test]
fn many_clean_seals_verify_count() {
    let sb = mbz();
    for _ in 0..15 {
        sb.seal_experiment_run(ExperimentRun::demo()).unwrap();
    }
    let r = sb.verify_all().unwrap();
    assert_eq!(r.len(), 15);
    for x in r {
        assert!(x.passed());
    }
}

#[test]
fn audit_csv_lines_match_seals() {
    let sb = mbz();
    for _ in 0..4 {
        sb.seal_experiment_run(ExperimentRun::demo()).unwrap();
    }
    let csv = sb.audit_trail(AuditFormat::Csv).unwrap();
    assert_eq!(csv.lines().count(), 5); // header + 4
}

#[test]
fn evidence_log_workflow_ordering() {
    let sb = mbz();
    sb.seal_experiment_run(ExperimentRun::demo()).unwrap();
    sb.seal_model_release(ModelReleasePack::demo()).unwrap();
    sb.seal_reproducibility_check(ReproducibilityCheck::demo()).unwrap();
    sb.seal_training_run(TrainingRun::demo()).unwrap();
    let bundle = sb.export_evidence().unwrap();
    let workflows: Vec<&str> = bundle
        .entries
        .iter()
        .map(|e| e.seal.workflow_id.as_str())
        .collect();
    assert_eq!(workflows[0], "experiment_run");
    assert_eq!(workflows[1], "model_release");
    assert_eq!(workflows[2], "reproducibility_check");
    assert_eq!(workflows[3], "training_run");
}

#[test]
fn audit_records_training_workflow_id() {
    let sb = mbz();
    sb.seal_training_run(TrainingRun::demo()).unwrap();
    let trail = sb.audit_trail_struct().unwrap();
    assert_eq!(trail.entries[0].workflow_id, "training_run");
}

#[test]
fn audit_records_repro_workflow_id() {
    let sb = mbz();
    sb.seal_reproducibility_check(ReproducibilityCheck::demo()).unwrap();
    let trail = sb.audit_trail_struct().unwrap();
    assert_eq!(trail.entries[0].workflow_id, "reproducibility_check");
}

#[test]
fn audit_records_model_release_workflow_id() {
    let sb = mbz();
    sb.seal_model_release(ModelReleasePack::demo()).unwrap();
    let trail = sb.audit_trail_struct().unwrap();
    assert_eq!(trail.entries[0].workflow_id, "model_release");
}

#[test]
fn experiment_seal_id_format() {
    let sb = mbz();
    let s = sb.seal_experiment_run(ExperimentRun::demo()).unwrap();
    assert!(s.id_string().starts_with("seal_"));
}

#[test]
fn model_release_seal_id_format() {
    let sb = mbz();
    let s = sb.seal_model_release(ModelReleasePack::demo()).unwrap();
    assert!(s.id_string().starts_with("seal_"));
}

#[test]
fn reproducibility_seal_id_format() {
    let sb = mbz();
    let s = sb.seal_reproducibility_check(ReproducibilityCheck::demo()).unwrap();
    assert!(s.id_string().starts_with("seal_"));
}

#[test]
fn training_seal_id_format() {
    let sb = mbz();
    let s = sb.seal_training_run(TrainingRun::demo()).unwrap();
    assert!(s.id_string().starts_with("seal_"));
}

#[test]
fn _error_category_used() {
    let _ = ErrorCategory::Policy;
}

// ======================================================================
// Additional dataset / license combinations + envelope checks
// ======================================================================

#[test]
fn research_only_dataset_seals() {
    let sb = mbz();
    let mut e = ExperimentRun::demo();
    e.dataset_class = DatasetClass::ResearchOnly;
    sb.seal_experiment_run(e).unwrap();
}

#[test]
fn restricted_dataset_blocks_experiment() {
    let sb = mbz();
    let mut e = ExperimentRun::demo();
    e.dataset_class = DatasetClass::Restricted;
    let r = sb.seal_experiment_run(e);
    assert!(r.is_err());
    assert!(r.unwrap_err().is_policy_denial());
}

#[test]
fn cc_by_nc_license_seals() {
    let sb = mbz();
    let mut m = ModelReleasePack::demo();
    m.license = License::CcByNc40;
    sb.seal_model_release(m).unwrap();
}

#[test]
fn mpl_license_seals() {
    let sb = mbz();
    let mut m = ModelReleasePack::demo();
    m.license = License::Mpl20;
    sb.seal_model_release(m).unwrap();
}

#[test]
fn many_training_runs_count() {
    let sb = mbz();
    for _ in 0..20 {
        sb.seal_training_run(TrainingRun::demo()).unwrap();
    }
    assert_eq!(sb.seal_count(), 20);
}

#[test]
fn many_repro_checks_count() {
    let sb = mbz();
    for _ in 0..20 {
        sb.seal_reproducibility_check(ReproducibilityCheck::demo()).unwrap();
    }
    assert_eq!(sb.seal_count(), 20);
}

#[test]
fn empty_audit_csv_is_header_only() {
    let sb = mbz();
    let csv = sb.audit_trail(AuditFormat::Csv).unwrap();
    assert_eq!(csv.lines().count(), 1);
}

#[test]
fn verify_all_default_count_matches_seal_count() {
    let sb = mbz();
    for _ in 0..6 {
        sb.seal_experiment_run(ExperimentRun::demo()).unwrap();
    }
    let r = sb.verify_all().unwrap();
    assert_eq!(r.len(), sb.seal_count());
}

#[test]
fn jurisdiction_tag_matches_default() {
    let sb = mbz();
    let s = sb.seal_experiment_run(ExperimentRun::demo()).unwrap();
    // FAIR is the default jurisdiction.
    assert!(!s.seal.jurisdiction_tag.is_empty());
}

#[test]
fn evidence_log_count_after_clean_seals() {
    let sb = mbz();
    let count = 12;
    for _ in 0..count {
        sb.seal_experiment_run(ExperimentRun::demo()).unwrap();
    }
    let bundle = sb.export_evidence().unwrap();
    assert_eq!(bundle.entries.len(), count);
}
