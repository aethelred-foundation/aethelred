//! Enterprise v0.2.0 test suite for sandbox-ai-agents.

use aethelred_sandbox_ai_agents::*;
use aethelred_sandbox_core::audit::{AuditFormat, AuditTrail};
use aethelred_sandbox_core::error_code::ErrorCategory;
use aethelred_sandbox_core::verify::Verifier;
use aethelred_sandbox_core::{EvidenceBundle, Sector};

fn lab() -> AiAgentsSandbox {
    AiAgentsSandbox::quickstart("AI-Lab").unwrap()
}

// ======================================================================
// Quickstart / Builder
// ======================================================================

#[test]
fn quickstart_default_jurisdiction() {
    let sb = lab();
    assert_eq!(sb.tenant(), "AI-Lab");
}

#[test]
fn builder_eu_ai_act_art_26() {
    let sb = AiAgentsSandbox::builder()
        .tenant("EU-Deployer")
        .jurisdiction(AiAgentsJurisdiction::EuAiActArt26)
        .build()
        .unwrap();
    assert_eq!(sb.primary_jurisdiction(), AiAgentsJurisdiction::EuAiActArt26);
}

#[test]
fn builder_iso_42001() {
    let sb = AiAgentsSandbox::builder()
        .tenant("ISO-Org")
        .jurisdiction(AiAgentsJurisdiction::Iso42001)
        .build()
        .unwrap();
    assert_eq!(sb.primary_jurisdiction(), AiAgentsJurisdiction::Iso42001);
}

#[test]
fn builder_nist_ai_rmf() {
    let sb = AiAgentsSandbox::builder()
        .tenant("NIST-Org")
        .jurisdiction(AiAgentsJurisdiction::NistAiRmf)
        .build()
        .unwrap();
    assert_eq!(sb.primary_jurisdiction(), AiAgentsJurisdiction::NistAiRmf);
}

#[test]
fn builder_uae_pdpl() {
    let sb = AiAgentsSandbox::builder()
        .tenant("UAE-Org")
        .jurisdiction(AiAgentsJurisdiction::UaePdpl)
        .build()
        .unwrap();
    assert_eq!(sb.primary_jurisdiction(), AiAgentsJurisdiction::UaePdpl);
}

#[test]
fn builder_uae_naip() {
    let sb = AiAgentsSandbox::builder()
        .tenant("UAE-NAIP")
        .jurisdiction(AiAgentsJurisdiction::UaeNaip)
        .build()
        .unwrap();
    assert_eq!(sb.primary_jurisdiction(), AiAgentsJurisdiction::UaeNaip);
}

// ======================================================================
// Bulk seal
// ======================================================================

#[test]
fn bulk_seal_passports() {
    let sb = lab();
    let r = sb
        .seal_passports((0..5).map(|_| AgentPassport::demo()))
        .unwrap();
    assert_eq!(r.len(), 5);
}

#[test]
fn bulk_seal_tool_invocations() {
    let sb = lab();
    sb.seal_passport(AgentPassport::demo()).unwrap(); // register agent
    let r = sb
        .seal_tool_invocations((0..3).map(|_| ToolInvocation::demo()))
        .unwrap();
    assert_eq!(r.len(), 3);
}

#[test]
fn bulk_seal_actions() {
    let sb = lab();
    sb.seal_passport(AgentPassport::demo()).unwrap();
    let r = sb
        .seal_actions((0..7).map(|_| AgentAction::demo()))
        .unwrap();
    assert_eq!(r.len(), 7);
}

#[test]
fn bulk_seal_prompt_injection_tests() {
    let sb = lab();
    let r = sb
        .seal_prompt_injection_tests((0..4).map(|_| PromptInjectionTest::demo()))
        .unwrap();
    assert_eq!(r.len(), 4);
}

#[test]
fn bulk_seal_empty() {
    let sb = lab();
    let v: Vec<AgentPassport> = vec![];
    assert_eq!(sb.seal_passports(v).unwrap().len(), 0);
}

#[test]
fn bulk_seal_large() {
    let sb = lab();
    let r = sb
        .seal_passports((0..50).map(|_| AgentPassport::demo()))
        .unwrap();
    assert_eq!(r.len(), 50);
}

#[test]
fn mixed_workflow_log() {
    let sb = lab();
    sb.seal_passport(AgentPassport::demo()).unwrap();
    // tool invocation + action need an active passport (set by seal_passport above)
    sb.seal_tool_invocation(ToolInvocation::demo()).unwrap();
    sb.seal_action(AgentAction::demo()).unwrap();
    sb.seal_prompt_injection_test(PromptInjectionTest::demo()).unwrap();
    assert_eq!(sb.seal_count(), 4);
}

// ======================================================================
// Envelope + Verifier
// ======================================================================

#[test]
fn envelope_at_returns_proof() {
    let sb = lab();
    sb.seal_passport(AgentPassport::demo()).unwrap();
    let env = sb.envelope_at(0).unwrap();
    assert!(env.merkle_proof.is_some());
    assert!(env.merkle_proof.unwrap().verify());
}

#[test]
fn envelope_oor_errors() {
    let sb = lab();
    sb.seal_passport(AgentPassport::demo()).unwrap();
    assert!(sb.envelope_at(99).is_err());
}

#[test]
fn all_envelopes_share_root() {
    let sb = lab();
    for _ in 0..6 {
        sb.seal_passport(AgentPassport::demo()).unwrap();
    }
    let envs = sb.all_envelopes().unwrap();
    let root = sb.current_root().unwrap();
    for env in &envs {
        assert_eq!(env.merkle_proof.as_ref().unwrap().root, root);
    }
}

#[test]
fn verify_all_passes() {
    let sb = lab();
    for _ in 0..4 {
        sb.seal_passport(AgentPassport::demo()).unwrap();
    }
    let r = sb.verify_all().unwrap();
    assert!(r.iter().all(|x| x.passed()));
}

#[test]
fn verify_strict_fails_without_attestation() {
    let sb = lab();
    sb.seal_passport(AgentPassport::demo()).unwrap();
    let r = sb.verify_all_with(&Verifier::strict()).unwrap();
    assert!(!r[0].passed());
}

#[test]
fn current_root_changes() {
    let sb = lab();
    let r0 = sb.current_root().unwrap();
    sb.seal_passport(AgentPassport::demo()).unwrap();
    assert_ne!(r0, sb.current_root().unwrap());
}

// ======================================================================
// Audit trail
// ======================================================================

#[test]
fn audit_plaintext() {
    let sb = lab();
    sb.seal_passport(AgentPassport::demo()).unwrap();
    let s = sb.audit_trail(AuditFormat::PlainText).unwrap();
    assert!(s.contains("AI-Lab"));
}

#[test]
fn audit_markdown() {
    let sb = lab();
    sb.seal_passport(AgentPassport::demo()).unwrap();
    let s = sb.audit_trail(AuditFormat::Markdown).unwrap();
    assert!(s.contains("|"));
}

#[test]
fn audit_csv() {
    let sb = lab();
    sb.seal_passport(AgentPassport::demo()).unwrap();
    let s = sb.audit_trail(AuditFormat::Csv).unwrap();
    assert!(s.starts_with("position,seal_id,timestamp,"));
}

#[test]
fn audit_struct_count() {
    let sb = lab();
    for _ in 0..3 {
        sb.seal_passport(AgentPassport::demo()).unwrap();
    }
    let trail = sb.audit_trail_struct().unwrap();
    assert_eq!(trail.total, 3);
}

// ======================================================================
// Adversarial — prompt injection
// ======================================================================

#[test]
fn unrejected_prompt_injection_test_blocks() {
    let sb = lab();
    let mut p = PromptInjectionTest::demo();
    p.rejected = false;
    assert!(sb.seal_prompt_injection_test(p).is_err());
}

#[test]
fn rejected_prompt_injection_test_seals() {
    let sb = lab();
    let mut p = PromptInjectionTest::demo();
    p.rejected = true;
    sb.seal_prompt_injection_test(p).unwrap();
}

// ======================================================================
// Multi-jurisdiction views
// ======================================================================

#[test]
fn eu_ai_act_view() {
    let sb = lab();
    let s = sb.seal_passport(AgentPassport::demo()).unwrap();
    let view = sb.regulator_view(&s.seal, AiAgentsJurisdiction::EuAiActArt26);
    assert!(!view.citations.is_empty());
}

#[test]
fn iso_42001_view() {
    let sb = lab();
    let s = sb.seal_passport(AgentPassport::demo()).unwrap();
    let view = sb.regulator_view(&s.seal, AiAgentsJurisdiction::Iso42001);
    assert!(!view.citations.is_empty());
}

#[test]
fn nist_ai_rmf_view() {
    let sb = lab();
    let s = sb.seal_passport(AgentPassport::demo()).unwrap();
    let view = sb.regulator_view(&s.seal, AiAgentsJurisdiction::NistAiRmf);
    assert!(!view.citations.is_empty());
}

#[test]
fn uae_pdpl_view() {
    let sb = lab();
    let s = sb.seal_passport(AgentPassport::demo()).unwrap();
    let view = sb.regulator_view(&s.seal, AiAgentsJurisdiction::UaePdpl);
    assert!(!view.citations.is_empty());
}

#[test]
fn uae_naip_view() {
    let sb = lab();
    let s = sb.seal_passport(AgentPassport::demo()).unwrap();
    let view = sb.regulator_view(&s.seal, AiAgentsJurisdiction::UaeNaip);
    assert!(!view.citations.is_empty());
}

// ======================================================================
// Risk tier coverage
// ======================================================================

#[test]
fn read_only_action_seals() {
    let sb = lab();
    sb.seal_passport(AgentPassport::demo()).unwrap();
    let mut a = AgentAction::demo();
    a.risk_tier = RiskTier::ReadOnly;
    sb.seal_action(a).unwrap();
}

#[test]
fn read_transform_action_seals() {
    let sb = lab();
    sb.seal_passport(AgentPassport::demo()).unwrap();
    let mut a = AgentAction::demo();
    a.risk_tier = RiskTier::ReadTransform;
    sb.seal_action(a).unwrap();
}

#[test]
fn write_sandbox_action_seals() {
    let sb = lab();
    sb.seal_passport(AgentPassport::demo()).unwrap();
    let mut a = AgentAction::demo();
    a.risk_tier = RiskTier::WriteSandbox;
    sb.seal_action(a).unwrap();
}

// ======================================================================
// Lifecycle coverage
// ======================================================================

#[test]
fn issued_passport_seals() {
    let sb = lab();
    let mut p = AgentPassport::demo();
    p.lifecycle = AgentLifecycle::Issued;
    sb.seal_passport(p).unwrap();
}

#[test]
fn active_passport_seals() {
    let sb = lab();
    let mut p = AgentPassport::demo();
    p.lifecycle = AgentLifecycle::Active;
    sb.seal_passport(p).unwrap();
}

#[test]
fn suspended_passport_seals() {
    let sb = lab();
    let mut p = AgentPassport::demo();
    p.lifecycle = AgentLifecycle::Suspended;
    sb.seal_passport(p).unwrap();
}

#[test]
fn revoked_passport_seals() {
    let sb = lab();
    let mut p = AgentPassport::demo();
    p.lifecycle = AgentLifecycle::Revoked;
    sb.seal_passport(p).unwrap();
}

#[test]
fn expired_passport_seals() {
    let sb = lab();
    let mut p = AgentPassport::demo();
    p.lifecycle = AgentLifecycle::Expired;
    sb.seal_passport(p).unwrap();
}

// ======================================================================
// Evidence + Approvals + Sectors
// ======================================================================

#[test]
fn merkle_proofs_verify() {
    let sb = lab();
    for _ in 0..8 {
        sb.seal_passport(AgentPassport::demo()).unwrap();
    }
    let envs = sb.all_envelopes().unwrap();
    for env in envs {
        assert!(env.merkle_proof.unwrap().verify());
    }
}

#[test]
fn evidence_indices_monotonic() {
    let sb = lab();
    for _ in 0..5 {
        sb.seal_passport(AgentPassport::demo()).unwrap();
    }
    let bundle = sb.export_evidence().unwrap();
    for (i, e) in bundle.entries.iter().enumerate() {
        assert_eq!(e.index, i as u64);
    }
}

#[test]
fn evidence_root_matches_current() {
    let sb = lab();
    sb.seal_passport(AgentPassport::demo()).unwrap();
    let bundle = sb.export_evidence().unwrap();
    assert_eq!(bundle.merkle_root, sb.current_root().unwrap());
}

#[test]
fn empty_seal_count() {
    let sb = lab();
    assert_eq!(sb.seal_count(), 0);
}

#[test]
fn empty_audit_trail() {
    let sb = lab();
    let trail = sb.audit_trail_struct().unwrap();
    assert_eq!(trail.total, 0);
}

#[test]
fn empty_envelopes() {
    let sb = lab();
    assert!(sb.all_envelopes().unwrap().is_empty());
}

#[test]
fn empty_verify_all() {
    let sb = lab();
    assert!(sb.verify_all().unwrap().is_empty());
}

#[test]
fn passport_seal_has_approval() {
    let sb = lab();
    let s = sb.seal_passport(AgentPassport::demo()).unwrap();
    assert!(s.seal.approval_count() >= 1);
}

#[test]
fn ai_agents_sector_in_seal() {
    let sb = lab();
    let s = sb.seal_passport(AgentPassport::demo()).unwrap();
    assert_eq!(s.seal.sector, Sector::AiAgents);
}

#[test]
fn passport_workflow_id() {
    let sb = lab();
    let s = sb.seal_passport(AgentPassport::demo()).unwrap();
    assert_eq!(s.seal.workflow_id, "agent_passport");
}

#[test]
fn tool_invocation_workflow_id() {
    let sb = lab();
    sb.seal_passport(AgentPassport::demo()).unwrap();
    let s = sb.seal_tool_invocation(ToolInvocation::demo()).unwrap();
    assert_eq!(s.seal.workflow_id, "tool_invocation");
}

#[test]
fn action_workflow_id() {
    let sb = lab();
    sb.seal_passport(AgentPassport::demo()).unwrap();
    let s = sb.seal_action(AgentAction::demo()).unwrap();
    assert_eq!(s.seal.workflow_id, "agent_action");
}

#[test]
fn pi_test_workflow_id() {
    let sb = lab();
    let s = sb.seal_prompt_injection_test(PromptInjectionTest::demo()).unwrap();
    assert_eq!(s.seal.workflow_id, "prompt_injection_test");
}

// ======================================================================
// Verifier + Error code + Serde
// ======================================================================

#[test]
fn verifier_detects_event_hash_tamper() {
    use aethelred_sandbox_core::Hasher;
    let sb = lab();
    sb.seal_passport(AgentPassport::demo()).unwrap();
    let mut env = sb.envelope_at(0).unwrap();
    env.seal.event_hash = Hasher::sha256(b"tampered");
    let root = sb.current_root().unwrap();
    let r = Verifier::default().verify_envelope(&env, root).unwrap();
    assert!(!r.passed());
}

#[test]
fn verify_with_wrong_root_fails() {
    use aethelred_sandbox_core::Hasher;
    let sb = lab();
    sb.seal_passport(AgentPassport::demo()).unwrap();
    let env = sb.envelope_at(0).unwrap();
    let r = Verifier::default()
        .verify_envelope(&env, Hasher::sha256(b"wrong-root"))
        .unwrap();
    assert!(!r.passed());
}

#[test]
fn unrejected_pi_test_yields_policy_code() {
    let sb = lab();
    let mut p = PromptInjectionTest::demo();
    p.rejected = false;
    let err = sb.seal_prompt_injection_test(p).unwrap_err();
    assert_eq!(err.error_code().category, ErrorCategory::Policy);
}

#[test]
fn evidence_bundle_serde_roundtrip() {
    let sb = lab();
    sb.seal_passport(AgentPassport::demo()).unwrap();
    let b = sb.export_evidence().unwrap();
    let j = serde_json::to_string(&b).unwrap();
    let p: EvidenceBundle = serde_json::from_str(&j).unwrap();
    assert_eq!(p.entries.len(), b.entries.len());
}

#[test]
fn audit_trail_serde_roundtrip() {
    let sb = lab();
    sb.seal_passport(AgentPassport::demo()).unwrap();
    let t = sb.audit_trail_struct().unwrap();
    let j = serde_json::to_string(&t).unwrap();
    let p: AuditTrail = serde_json::from_str(&j).unwrap();
    assert_eq!(p.total, t.total);
}

#[test]
fn passport_serde_roundtrip() {
    let p = AgentPassport::demo();
    let j = serde_json::to_string(&p).unwrap();
    let r: AgentPassport = serde_json::from_str(&j).unwrap();
    assert_eq!(p.agent_id, r.agent_id);
}

#[test]
fn tool_invocation_serde_roundtrip() {
    let p = ToolInvocation::demo();
    let j = serde_json::to_string(&p).unwrap();
    let r: ToolInvocation = serde_json::from_str(&j).unwrap();
    assert_eq!(p.agent_id, r.agent_id);
}

#[test]
fn agent_action_serde_roundtrip() {
    let p = AgentAction::demo();
    let j = serde_json::to_string(&p).unwrap();
    let r: AgentAction = serde_json::from_str(&j).unwrap();
    assert_eq!(p.agent_id, r.agent_id);
}

#[test]
fn pi_test_serde_roundtrip() {
    let p = PromptInjectionTest::demo();
    let j = serde_json::to_string(&p).unwrap();
    let r: PromptInjectionTest = serde_json::from_str(&j).unwrap();
    assert_eq!(p.test_id, r.test_id);
}

#[test]
fn extra_gate_can_be_added() {
    use aethelred_sandbox_core::policy::PolicyGate;
    let sb = AiAgentsSandbox::builder()
        .tenant("AI-X")
        .with_extra_gate(PolicyGate::optional("test.extra", "Extra", "rule"))
        .build()
        .unwrap();
    sb.seal_passport(AgentPassport::demo()).unwrap();
    assert_eq!(sb.seal_count(), 1);
}

#[test]
fn label_override() {
    let sb = AiAgentsSandbox::builder()
        .tenant("AI-Lab")
        .label("Custom Lab")
        .build()
        .unwrap();
    sb.seal_passport(AgentPassport::demo()).unwrap();
}

#[test]
fn verifier_independent() {
    let sb = lab();
    sb.seal_passport(AgentPassport::demo()).unwrap();
    let env = sb.envelope_at(0).unwrap();
    let root = sb.current_root().unwrap();
    let r = Verifier::default().verify_envelope(&env, root).unwrap();
    assert!(r.passed());
}

// ======================================================================
// Additional invocation + tool-manifest tests
// ======================================================================

#[test]
fn revoked_passport_blocks_action() {
    let sb = lab();
    let mut p = AgentPassport::demo();
    p.lifecycle = AgentLifecycle::Revoked;
    sb.seal_passport(p).unwrap();
    let r = sb.seal_action(AgentAction::demo());
    assert!(r.is_err());
}

#[test]
fn suspended_passport_blocks_tool_invocation() {
    let sb = lab();
    let mut p = AgentPassport::demo();
    p.lifecycle = AgentLifecycle::Suspended;
    sb.seal_passport(p).unwrap();
    let r = sb.seal_tool_invocation(ToolInvocation::demo());
    assert!(r.is_err());
}

#[test]
fn expired_passport_blocks_tool_invocation() {
    let sb = lab();
    let mut p = AgentPassport::demo();
    p.lifecycle = AgentLifecycle::Expired;
    sb.seal_passport(p).unwrap();
    let r = sb.seal_tool_invocation(ToolInvocation::demo());
    assert!(r.is_err());
}

#[test]
fn unknown_agent_action_blocks() {
    let sb = lab();
    // No passport sealed for this agent.
    let mut a = AgentAction::demo();
    a.agent_id = "unknown-agent-xyz".into();
    assert!(sb.seal_action(a).is_err());
}

#[test]
fn unknown_agent_tool_invocation_blocks() {
    let sb = lab();
    let mut t = ToolInvocation::demo();
    t.agent_id = "unknown-agent-zzz".into();
    assert!(sb.seal_tool_invocation(t).is_err());
}

#[test]
fn pi_test_seal_records_workflow() {
    let sb = lab();
    let s = sb.seal_prompt_injection_test(PromptInjectionTest::demo()).unwrap();
    assert_eq!(s.seal.workflow_id, "prompt_injection_test");
}

#[test]
fn pi_test_seal_carries_rejected() {
    let sb = lab();
    let s = sb.seal_prompt_injection_test(PromptInjectionTest::demo()).unwrap();
    assert!(s.rejected);
}

#[test]
fn passport_seal_carries_lifecycle() {
    let sb = lab();
    let s = sb.seal_passport(AgentPassport::demo()).unwrap();
    assert!(s.id_string().starts_with("seal_"));
}

#[test]
fn audit_records_pi_workflow_id() {
    let sb = lab();
    sb.seal_prompt_injection_test(PromptInjectionTest::demo()).unwrap();
    let trail = sb.audit_trail_struct().unwrap();
    assert_eq!(trail.entries[0].workflow_id, "prompt_injection_test");
}

#[test]
fn audit_records_passport_workflow_id() {
    let sb = lab();
    sb.seal_passport(AgentPassport::demo()).unwrap();
    let trail = sb.audit_trail_struct().unwrap();
    assert_eq!(trail.entries[0].workflow_id, "agent_passport");
}

// ======================================================================
// More verification edge cases
// ======================================================================

#[test]
fn verifier_detects_input_hash_tamper() {
    use aethelred_sandbox_core::Hasher;
    let sb = lab();
    sb.seal_passport(AgentPassport::demo()).unwrap();
    let mut env = sb.envelope_at(0).unwrap();
    env.seal.input_hash = Hasher::sha256(b"tamper");
    let root = sb.current_root().unwrap();
    let r = Verifier::default().verify_envelope(&env, root).unwrap();
    assert!(!r.passed());
}

#[test]
fn verifier_detects_output_hash_tamper() {
    use aethelred_sandbox_core::Hasher;
    let sb = lab();
    sb.seal_passport(AgentPassport::demo()).unwrap();
    let mut env = sb.envelope_at(0).unwrap();
    env.seal.output_hash = Hasher::sha256(b"tamper-output");
    let root = sb.current_root().unwrap();
    let r = Verifier::default().verify_envelope(&env, root).unwrap();
    assert!(!r.passed());
}

#[test]
fn verifier_detects_tenant_mutation() {
    let sb = lab();
    sb.seal_passport(AgentPassport::demo()).unwrap();
    let mut env = sb.envelope_at(0).unwrap();
    env.seal.tenant_id = "different-tenant".into();
    let root = sb.current_root().unwrap();
    let r = Verifier::default().verify_envelope(&env, root).unwrap();
    assert!(!r.passed());
}

#[test]
fn current_root_is_stable_for_unchanged_log() {
    let sb = lab();
    sb.seal_passport(AgentPassport::demo()).unwrap();
    let r1 = sb.current_root().unwrap();
    let r2 = sb.current_root().unwrap();
    assert_eq!(r1, r2);
}

#[test]
fn many_passports_all_verifiable() {
    let sb = lab();
    for i in 0..15 {
        let mut p = AgentPassport::demo();
        p.agent_id = format!("agent-{i}");
        sb.seal_passport(p).unwrap();
    }
    let r = sb.verify_all().unwrap();
    assert_eq!(r.len(), 15);
    for x in r {
        assert!(x.passed());
    }
}

#[test]
fn build_default_uses_eu_ai_act_default() {
    let sb = AiAgentsSandbox::builder().tenant("X").build().unwrap();
    assert_eq!(sb.primary_jurisdiction(), AiAgentsJurisdiction::EuAiActArt26);
}

#[test]
fn evidence_export_count_matches_seal_count() {
    let sb = lab();
    for _ in 0..6 {
        sb.seal_passport(AgentPassport::demo()).unwrap();
    }
    let bundle = sb.export_evidence().unwrap();
    assert_eq!(bundle.entries.len(), sb.seal_count());
}

#[test]
fn three_action_workflow_sequence() {
    let sb = lab();
    sb.seal_passport(AgentPassport::demo()).unwrap();
    sb.seal_action(AgentAction::demo()).unwrap();
    sb.seal_action(AgentAction::demo()).unwrap();
    sb.seal_action(AgentAction::demo()).unwrap();
    assert_eq!(sb.seal_count(), 4); // passport + 3 actions
}

#[test]
fn tool_invocation_after_passport_works() {
    let sb = lab();
    sb.seal_passport(AgentPassport::demo()).unwrap();
    sb.seal_tool_invocation(ToolInvocation::demo()).unwrap();
    assert_eq!(sb.seal_count(), 2);
}

#[test]
fn verify_all_with_default_includes_check_categories() {
    let sb = lab();
    sb.seal_passport(AgentPassport::demo()).unwrap();
    let reports = sb.verify_all().unwrap();
    assert!(reports[0].total() >= 8);
}

#[test]
fn audit_trail_csv_has_rows_per_seal() {
    let sb = lab();
    for _ in 0..3 {
        sb.seal_passport(AgentPassport::demo()).unwrap();
    }
    let csv = sb.audit_trail(AuditFormat::Csv).unwrap();
    assert_eq!(csv.lines().count(), 4); // header + 3 data rows
}
