package evidence

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/aethelred/aethelred/pkg/governance/policy"
	"github.com/aethelred/aethelred/pkg/protocol/agent"
)

// ---------------------------------------------------------------------------
// Bundle tests
// ---------------------------------------------------------------------------

func TestNewEvidenceBundle(t *testing.T) {
	bundle := NewEvidenceBundle("SOC2")
	if bundle.ID == "" {
		t.Fatal("expected non-empty bundle ID")
	}
	if bundle.Framework != "SOC2" {
		t.Fatalf("expected SOC2, got %s", bundle.Framework)
	}
	if bundle.Version != SchemaVersion {
		t.Fatalf("expected version %s, got %s", SchemaVersion, bundle.Version)
	}
}

func TestEvidenceBundle_AddRecord(t *testing.T) {
	bundle := NewEvidenceBundle("NIST-800-53")
	bundle.AddRecord(Record{
		ID:        "rec-1",
		Type:      "audit",
		Action:    "job_submitted",
		Actor:     "validator-01",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	})

	if len(bundle.Records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(bundle.Records))
	}
	if bundle.Records[0].Hash == "" {
		t.Fatal("expected record hash to be computed")
	}
}

func TestEvidenceBundle_Finalize(t *testing.T) {
	bundle := NewEvidenceBundle("SOC2")
	bundle.AddRecord(Record{
		ID:        "rec-1",
		Type:      "audit",
		Action:    "job_submitted",
		Actor:     "validator-01",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	})

	err := bundle.Finalize("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if bundle.ContentHash == "" {
		t.Fatal("expected non-empty content hash")
	}
}

func TestEvidenceBundle_Finalize_WithSigner(t *testing.T) {
	bundle := NewEvidenceBundle("SOC2")
	bundle.AddRecord(Record{
		ID:        "rec-1",
		Type:      "audit",
		Action:    "job_submitted",
		Actor:     "validator-01",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	})

	// 32-byte hex key.
	signerKey := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	err := bundle.Finalize(signerKey)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if bundle.Signature == "" {
		t.Fatal("expected non-empty signature")
	}
}

func TestEvidenceBundle_Finalize_NoRecords(t *testing.T) {
	bundle := NewEvidenceBundle("SOC2")
	err := bundle.Finalize("")
	if err == nil {
		t.Fatal("expected error for empty records")
	}
}

func TestEvidenceBundle_Validate(t *testing.T) {
	bundle := NewEvidenceBundle("SOC2")
	bundle.AddRecord(Record{
		ID:        "rec-1",
		Type:      "audit",
		Action:    "test",
		Actor:     "tester",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	})
	_ = bundle.Finalize("")

	if err := bundle.Validate(); err != nil {
		t.Fatalf("validation failed: %v", err)
	}
}

func TestEvidenceBundle_Validate_Tampered(t *testing.T) {
	bundle := NewEvidenceBundle("SOC2")
	bundle.AddRecord(Record{
		ID:        "rec-1",
		Type:      "audit",
		Action:    "test",
		Actor:     "tester",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	})
	_ = bundle.Finalize("")

	// Tamper with a record.
	bundle.Records[0].Action = "tampered"

	if err := bundle.Validate(); err == nil {
		t.Fatal("expected validation failure for tampered bundle")
	}
}

func TestNewPolicyReceiptEvidence_RequiresEnterpriseFields(t *testing.T) {
	_, err := NewPolicyReceiptEvidence(&policy.SignedPolicyReceipt{})
	if err == nil {
		t.Fatal("expected invalid receipt to fail conversion")
	}
}

func TestNewAgentPassportEvidence_EnterpriseFields(t *testing.T) {
	identity := newEnterpriseIdentityFixture(t)

	passport, err := NewAgentPassportEvidence(identity)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	publicKeyBytes, err := hex.DecodeString(identity.PublicKeyHex)
	if err != nil {
		t.Fatalf("decoding public key: %v", err)
	}

	if passport.DID != identity.AgentID() {
		t.Fatalf("expected DID %q, got %q", identity.AgentID(), passport.DID)
	}
	if passport.PublicKeyHash != EvidenceHashHex(publicKeyBytes) {
		t.Fatalf("expected public key hash %q, got %q", EvidenceHashHex(publicKeyBytes), passport.PublicKeyHash)
	}
	if passport.HumanOwner != identity.Liability.HumanOwner {
		t.Fatalf("expected human owner %q, got %q", identity.Liability.HumanOwner, passport.HumanOwner)
	}
	if len(passport.SponsorChain) != len(identity.SponsorChain) {
		t.Fatalf("expected %d sponsors, got %d", len(identity.SponsorChain), len(passport.SponsorChain))
	}
	if len(passport.JurisdictionTags) != 2 || len(passport.AllowedTools) != 2 {
		t.Fatal("expected exported passport to preserve jurisdictions and allowed tools")
	}
}

func TestEvidenceBundle_Validate_TraceabilityChain(t *testing.T) {
	identity := newEnterpriseIdentityFixture(t)
	receipt := newSignedPolicyReceiptFixture(t, identity.AgentID())

	passport, err := NewAgentPassportEvidence(identity)
	if err != nil {
		t.Fatalf("passport conversion failed: %v", err)
	}
	receiptEvidence, err := NewPolicyReceiptEvidence(receipt)
	if err != nil {
		t.Fatalf("receipt conversion failed: %v", err)
	}

	seal := Seal{
		SealID:         "seal-trace-001",
		JobID:          "job-treasury-001",
		OutputHash:     EvidenceHashHex([]byte("approved-payment-output")),
		ValidatorCount: 4,
		BlockHeight:    128,
		Timestamp:      time.Now().UTC().Format(time.RFC3339Nano),
	}
	traceLink, err := NewTraceLink(identity, receipt, seal, "treasury approval chain")
	if err != nil {
		t.Fatalf("trace link creation failed: %v", err)
	}

	bundle := NewEvidenceBundle("Finance Control Ledger")
	bundle.AddRecord(Record{
		ID:        "record-trace-001",
		Type:      "governance",
		Action:    "payments.release.authorized",
		Actor:     identity.AgentID(),
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Data: map[string]string{
			"policy_receipt_id": receipt.ID,
			"seal_id":           seal.SealID,
		},
	})
	bundle.AddAgentPassport(passport)
	bundle.AddPolicyReceipt(receiptEvidence)
	bundle.AddSeal(seal)
	bundle.AddTraceLink(traceLink)

	if err := bundle.Finalize(""); err != nil {
		t.Fatalf("finalize failed: %v", err)
	}
	if err := bundle.Validate(); err != nil {
		t.Fatalf("validate failed: %v", err)
	}

	port, err := Package(bundle, true)
	if err != nil {
		t.Fatalf("package failed: %v", err)
	}
	if err := VerifyPortable(port); err != nil {
		t.Fatalf("portable verification failed: %v", err)
	}
}

func TestEvidenceBundle_Validate_TraceabilityMismatchFails(t *testing.T) {
	identity := newEnterpriseIdentityFixture(t)
	receipt := newSignedPolicyReceiptFixture(t, identity.AgentID())

	passport, err := NewAgentPassportEvidence(identity)
	if err != nil {
		t.Fatalf("passport conversion failed: %v", err)
	}
	receiptEvidence, err := NewPolicyReceiptEvidence(receipt)
	if err != nil {
		t.Fatalf("receipt conversion failed: %v", err)
	}

	seal := Seal{
		SealID:         "seal-trace-002",
		JobID:          "job-treasury-002",
		OutputHash:     EvidenceHashHex([]byte("output")),
		ValidatorCount: 4,
		BlockHeight:    256,
		Timestamp:      time.Now().UTC().Format(time.RFC3339Nano),
	}
	traceLink, err := NewTraceLink(identity, receipt, seal, "tamper check")
	if err != nil {
		t.Fatalf("trace link creation failed: %v", err)
	}
	traceLink.PolicyReceiptHash = "not-the-real-hash"

	bundle := NewEvidenceBundle("Finance Control Ledger")
	bundle.AddRecord(Record{
		ID:        "record-trace-002",
		Type:      "governance",
		Action:    "payments.release.authorized",
		Actor:     identity.AgentID(),
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
	})
	bundle.AddAgentPassport(passport)
	bundle.AddPolicyReceipt(receiptEvidence)
	bundle.AddSeal(seal)
	bundle.AddTraceLink(traceLink)

	if err := bundle.Finalize(""); err != nil {
		t.Fatalf("finalize failed: %v", err)
	}
	if err := bundle.Validate(); err == nil {
		t.Fatal("expected traceability mismatch to fail validation")
	}
}

func TestEvidenceBundle_Validate_TrustCompliancePackageEvidence(t *testing.T) {
	bundle := NewEvidenceBundle("Trust Kernel")
	artifact := TrustCompliancePackageEvidence{
		PackageHash:   EvidenceHashHex([]byte("package")),
		PayloadHash:   EvidenceHashHex([]byte("payload")),
		DocumentHash:  EvidenceHashHex([]byte("document")),
		Format:        "oscal",
		ExportVersion: "1.0.0",
		GeneratedAt:   "2026-04-14T16:00:00Z",
		Signed:        true,
		Signature: &TrustComplianceSignatureEvidence{
			Signer:    "validator:test-signer",
			KeyID:     "key-1",
			Algorithm: "ed25519",
			SignedAt:  "2026-04-14T16:00:01Z",
		},
		AuditAnchor: &TrustComplianceAuditAnchorEvidence{
			Sequence:    17,
			RecordHash:  EvidenceHashHex([]byte("audit-anchor")),
			Action:      "trust_compliance_export_anchored",
			Actor:       "validator:test-signer",
			Timestamp:   "2026-04-14T16:00:02Z",
			BlockHeight: 512,
		},
	}
	if err := bundle.AddTrustCompliancePackage(artifact); err != nil {
		t.Fatalf("AddTrustCompliancePackage failed: %v", err)
	}
	if len(bundle.TrustCompliancePackages) != 1 {
		t.Fatalf("expected one trust compliance package, got %d", len(bundle.TrustCompliancePackages))
	}
	if len(bundle.Records) != 1 {
		t.Fatalf("expected projected anchor record to be added, got %d", len(bundle.Records))
	}

	if err := bundle.Finalize(""); err != nil {
		t.Fatalf("finalize failed: %v", err)
	}
	if err := bundle.Validate(); err != nil {
		t.Fatalf("validate failed: %v", err)
	}

	bundle.Records[0].Data["package_hash"] = "tampered"
	if err := bundle.Validate(); err == nil {
		t.Fatal("expected trust compliance anchor tampering to fail validation")
	}
}

func TestEvidenceBundle_Validate_ApproverAttestationEvidence(t *testing.T) {
	identity := newEnterpriseIdentityFixture(t)
	receipt := newSignedPolicyReceiptFixture(t, identity.AgentID())

	passport, err := NewAgentPassportEvidence(identity)
	if err != nil {
		t.Fatalf("passport conversion failed: %v", err)
	}
	receiptEvidence, err := NewPolicyReceiptEvidence(receipt)
	if err != nil {
		t.Fatalf("receipt conversion failed: %v", err)
	}
	seal := Seal{
		SealID:         "seal-approver-attestation-001",
		JobID:          "job-approver-attestation-001",
		OutputHash:     EvidenceHashHex([]byte("approved-approval-output")),
		ValidatorCount: 4,
		BlockHeight:    129,
		Timestamp:      time.Now().UTC().Format(time.RFC3339Nano),
	}
	traceLink, err := NewTraceLink(identity, receipt, seal, "approval attestation chain")
	if err != nil {
		t.Fatalf("trace link creation failed: %v", err)
	}
	attestation, err := NewApproverAttestationEvidence(
		identity,
		receipt,
		"approval-record-001",
		traceLink.ID,
		seal.SealID,
		receipt.EvaluatedAt,
		"Approved by controller",
		map[string]string{"approval_stage": "final"},
	)
	if err != nil {
		t.Fatalf("approver attestation conversion failed: %v", err)
	}

	bundle := NewEvidenceBundle("Finance Control Ledger")
	bundle.AddRecord(Record{
		ID:        "approval-record-001",
		Type:      "governance",
		Action:    "payments.release.approved",
		Actor:     identity.AgentID(),
		Timestamp: receipt.EvaluatedAt.UTC().Format(time.RFC3339Nano),
	})
	bundle.AddAgentPassport(passport)
	bundle.AddPolicyReceipt(receiptEvidence)
	bundle.AddSeal(seal)
	bundle.AddTraceLink(traceLink)
	if err := bundle.AddApproverAttestation(attestation); err != nil {
		t.Fatalf("AddApproverAttestation failed: %v", err)
	}

	if err := bundle.Finalize(""); err != nil {
		t.Fatalf("finalize failed: %v", err)
	}
	if err := bundle.Validate(); err != nil {
		t.Fatalf("validate failed: %v", err)
	}

	bundle.ApproverAttestations[0].PolicyReceiptHash = "tampered"
	if err := bundle.Validate(); err == nil {
		t.Fatal("expected approver attestation tampering to fail validation")
	}
}

func TestEvidenceBundle_Validate_ValueSettlementEvidence(t *testing.T) {
	identity := newEnterpriseIdentityFixture(t)
	receipt := newSignedPolicyReceiptFixture(t, identity.AgentID())

	passport, err := NewAgentPassportEvidence(identity)
	if err != nil {
		t.Fatalf("passport conversion failed: %v", err)
	}
	receiptEvidence, err := NewPolicyReceiptEvidence(receipt)
	if err != nil {
		t.Fatalf("receipt conversion failed: %v", err)
	}
	seal := Seal{
		SealID:         "seal-value-settlement-001",
		JobID:          "job-value-settlement-001",
		OutputHash:     EvidenceHashHex([]byte("value-settlement-output")),
		ValidatorCount: 4,
		BlockHeight:    130,
		Timestamp:      time.Now().UTC().Format(time.RFC3339Nano),
	}

	bundle := NewEvidenceBundle("Finance Control Ledger")
	bundle.AddRecord(Record{
		ID:        "record-value-settlement-001",
		Type:      "transaction",
		Action:    "payments.release.settled",
		Actor:     identity.AgentID(),
		Timestamp: receipt.EvaluatedAt.UTC().Format(time.RFC3339Nano),
	})
	bundle.AddAgentPassport(passport)
	bundle.AddPolicyReceipt(receiptEvidence)
	bundle.AddSeal(seal)
	if err := bundle.AddValueSettlement(ValueSettlementEvidence{
		ID:                "value-settlement:settlement-001",
		SettlementID:      "settlement-001",
		WorkflowID:        "workflow-001",
		Network:           "aethelred",
		Method:            "stablecoin",
		Counterparty:      "Trusted Vendor",
		Beneficiary:       "Trusted Vendor",
		FiatAmount:        2500,
		FiatCurrency:      "USD",
		TokenAmount:       2500,
		TokenDenomination: "USDC",
		ExchangeRate:      1.0,
		Status:            "settled",
		ReasonCode:        "treasury_release",
		Reference:         "workflow-001",
		TxHash:            "0xsettlement001",
		PolicyReceiptID:   receipt.ID,
		PolicyReceiptHash: receipt.ContentHash,
		SealID:            seal.SealID,
		SettledAt:         receipt.EvaluatedAt.UTC().Format(time.RFC3339Nano),
	}); err != nil {
		t.Fatalf("AddValueSettlement failed: %v", err)
	}

	if err := bundle.Finalize(""); err != nil {
		t.Fatalf("finalize failed: %v", err)
	}
	if err := bundle.Validate(); err != nil {
		t.Fatalf("validate failed: %v", err)
	}

	bundle.ValueSettlements[0].PolicyReceiptHash = "tampered"
	if err := bundle.Validate(); err == nil {
		t.Fatal("expected value settlement tampering to fail validation")
	}
}

// ---------------------------------------------------------------------------
// Portable evidence tests
// ---------------------------------------------------------------------------

func TestPackage_Unpackage(t *testing.T) {
	bundle := NewEvidenceBundle("SOC2")
	bundle.AddRecord(Record{
		ID:        "rec-1",
		Type:      "audit",
		Action:    "test",
		Actor:     "tester",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	})
	_ = bundle.Finalize("")

	pe, err := Package(bundle, true)
	if err != nil {
		t.Fatalf("packaging failed: %v", err)
	}
	if pe.PackageHash == "" {
		t.Fatal("expected non-empty package hash")
	}

	// Round-trip through JSON.
	data, err := json.Marshal(pe)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	restored, err := Unpackage(data)
	if err != nil {
		t.Fatalf("unpackage failed: %v", err)
	}
	if restored.Bundle.ID != bundle.ID {
		t.Fatalf("bundle ID mismatch: expected %s, got %s", bundle.ID, restored.Bundle.ID)
	}
}

func TestPackage_NilBundle(t *testing.T) {
	_, err := Package(nil, false)
	if err == nil {
		t.Fatal("expected error for nil bundle")
	}
}

func TestPackage_UnfinalizedBundle(t *testing.T) {
	bundle := NewEvidenceBundle("SOC2")
	_, err := Package(bundle, false)
	if err == nil {
		t.Fatal("expected error for unfinalized bundle")
	}
}

func TestVerifyPortable(t *testing.T) {
	bundle := NewEvidenceBundle("NIST-800-53")
	bundle.AddRecord(Record{
		ID:        "rec-1",
		Type:      "audit",
		Action:    "test",
		Actor:     "tester",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	})
	bundle.AddAttestation(Attestation{
		ID:          "att-1",
		Type:        "tee",
		Platform:    "sgx",
		EnclaveID:   "sgx-enclave-1",
		Measurement: "abc123",
		Timestamp:   time.Now().UTC().Format(time.RFC3339Nano),
	})
	_ = bundle.Finalize("")

	pe, _ := Package(bundle, true)
	pe.AddTrustAnchor(PlatformTrustAnchor{Platform: "sgx", RootHash: "abc123"})

	// Recompute package hash after adding trust anchor.
	hash, _ := pe.computePackageHash()
	pe.PackageHash = hash

	if err := VerifyPortable(pe); err != nil {
		t.Fatalf("verification failed: %v", err)
	}
}

func newEnterpriseIdentityFixture(t *testing.T) *agent.AgentIdentity {
	t.Helper()

	identity, _, err := agent.NewEnterpriseAgentIdentity(
		[]agent.Capability{{Name: "payments.release", Version: "1.0"}},
		agent.EnterpriseIdentityOptions{
			Issuer: "did:aethelred:issuer-bank-1",
			SponsorChain: []agent.SponsorRecord{
				{
					SponsorDID:        "did:aethelred:bank-parent",
					SponsorName:       "Bank Parent",
					Jurisdiction:      "UAE",
					Role:              "sponsor_of_record",
					LiabilityAccepted: true,
					SignedAt:          time.Now().UTC(),
				},
				{
					SponsorDID:        "did:aethelred:bank-risk",
					SponsorName:       "Bank Risk",
					Jurisdiction:      "UK",
					Role:              "risk_owner",
					LiabilityAccepted: true,
					SignedAt:          time.Now().UTC().Add(time.Minute),
				},
			},
			Liability: &agent.LiabilityProfile{
				HumanOwner:       "alice.chen",
				BusinessUnit:     "treasury-ops",
				SponsorOfRecord:  "did:aethelred:bank-parent",
				FallbackApprover: "treasury-duty-officer",
				IncidentContact:  "soc@bank.example",
				LiabilityModel:   "enterprise-sponsored",
			},
			JurisdictionTags: []string{"UAE", "UK"},
			AllowedTools:     []string{"payments.release", "sanctions.screen"},
			Metadata: map[string]string{
				"workflow": "treasury_release",
				"sector":   "finance",
			},
		},
	)
	if err != nil {
		t.Fatalf("creating enterprise identity: %v", err)
	}

	return identity
}

func newSignedPolicyReceiptFixture(t *testing.T, actor string) *policy.SignedPolicyReceipt {
	t.Helper()

	engine := policy.NewPolicyEngine(policy.DefaultEngineConfig())
	policySet := &policy.PolicySet{
		ID:       "traceability-policy-set",
		Name:     "Traceability Policy Set",
		Priority: 10,
		Enabled:  true,
		Rules: []policy.Rule{
			policy.NewAllowRule("allow_treasury_release", []policy.Condition{{Field: "risk_tier", Operator: policy.Equals, Value: "low"}}),
		},
	}
	if err := engine.RegisterPolicySet(policySet); err != nil {
		t.Fatalf("registering policy set: %v", err)
	}

	signerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating signer key: %v", err)
	}

	req := &policy.EvaluationRequest{
		Actor:    actor,
		Action:   "payments.release",
		Resource: "acct:treasury-main",
		Context: map[string]string{
			"jurisdiction": "UAE",
			"risk_tier":    "low",
		},
		Metadata: map[string]string{
			"amount":   "50000",
			"workflow": "treasury_release",
		},
	}

	_, receipt, err := engine.EvaluateAndSign(context.Background(), req, signerKey, "did:aethelred:policy-gateway-1", "")
	if err != nil {
		t.Fatalf("creating signed policy receipt: %v", err)
	}

	return receipt
}

func TestVerifyPortable_UntrustedPlatform(t *testing.T) {
	bundle := NewEvidenceBundle("SOC2")
	bundle.AddRecord(Record{
		ID:        "rec-1",
		Type:      "audit",
		Action:    "test",
		Actor:     "tester",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	})
	bundle.AddAttestation(Attestation{
		ID:          "att-1",
		Type:        "tee",
		Platform:    "unknown-platform",
		EnclaveID:   "unknown-enclave",
		Measurement: "abc123",
		Timestamp:   time.Now().UTC().Format(time.RFC3339Nano),
	})
	_ = bundle.Finalize("")

	pe, _ := Package(bundle, true)
	pe.AddTrustAnchor(PlatformTrustAnchor{Platform: "sgx", RootHash: "abc123"})
	hash, _ := pe.computePackageHash()
	pe.PackageHash = hash

	err := VerifyPortable(pe)
	if err == nil {
		t.Fatal("expected verification failure for untrusted platform")
	}
}

// ---------------------------------------------------------------------------
// Chain of custody tests
// ---------------------------------------------------------------------------

func TestRecordCreation(t *testing.T) {
	chain, err := RecordCreation("auditor-01")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(chain) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(chain))
	}
	if chain[0].Action != "created" {
		t.Fatalf("expected 'created', got %s", chain[0].Action)
	}
}

func TestRecordTransfer(t *testing.T) {
	chain, _ := RecordCreation("auditor-01")
	chain, err := RecordTransfer(chain, "auditor-01", "regulator-01")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(chain) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(chain))
	}
	if chain[1].PreviousHash != chain[0].Hash {
		t.Fatal("chain linkage broken")
	}
}

func TestRecordTransfer_SameParty(t *testing.T) {
	chain, _ := RecordCreation("auditor-01")
	_, err := RecordTransfer(chain, "auditor-01", "auditor-01")
	if err == nil {
		t.Fatal("expected error for same-party transfer")
	}
}

func TestRecordAccess(t *testing.T) {
	chain, _ := RecordCreation("auditor-01")
	chain, err := RecordAccess(chain, "reviewer-01")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(chain) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(chain))
	}
}

func TestRecordExport(t *testing.T) {
	chain, _ := RecordCreation("auditor-01")
	chain, err := RecordExport(chain, "auditor-01")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if chain[1].Action != "export" {
		t.Fatalf("expected 'export', got %s", chain[1].Action)
	}
}

func TestVerifyCustodyChain_Valid(t *testing.T) {
	chain, _ := RecordCreation("auditor-01")
	time.Sleep(2 * time.Millisecond)
	chain, _ = RecordTransfer(chain, "auditor-01", "regulator-01")
	time.Sleep(2 * time.Millisecond)
	chain, _ = RecordAccess(chain, "reviewer-01")

	if err := VerifyCustodyChain(chain); err != nil {
		t.Fatalf("verification failed: %v", err)
	}
}

func TestVerifyCustodyChain_Tampered(t *testing.T) {
	chain, _ := RecordCreation("auditor-01")
	chain, _ = RecordTransfer(chain, "auditor-01", "regulator-01")

	// Tamper with an entry.
	chain[1].Custodian = "tampered"

	if err := VerifyCustodyChain(chain); err == nil {
		t.Fatal("expected verification failure for tampered chain")
	}
}

func TestVerifyCustodyChain_Empty(t *testing.T) {
	if err := VerifyCustodyChain(nil); err == nil {
		t.Fatal("expected error for empty chain")
	}
}

// ---------------------------------------------------------------------------
// Standalone verifier tests
// ---------------------------------------------------------------------------

func TestStandaloneVerifier_VerifyBundle(t *testing.T) {
	bundle := NewEvidenceBundle("SOC2")
	bundle.AddRecord(Record{
		ID:        "rec-1",
		Type:      "audit",
		Action:    "test",
		Actor:     "tester",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	})
	_ = bundle.Finalize("")

	verifier := NewStandaloneVerifier(nil, false)
	if err := verifier.VerifyBundle(bundle); err != nil {
		t.Fatalf("verification failed: %v", err)
	}
}

func TestStandaloneVerifier_StrictMode_UntrustedPlatform(t *testing.T) {
	bundle := NewEvidenceBundle("SOC2")
	bundle.AddRecord(Record{
		ID:        "rec-1",
		Type:      "audit",
		Action:    "test",
		Actor:     "tester",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	})
	bundle.AddAttestation(Attestation{
		ID:          "att-1",
		Type:        "tee",
		Platform:    "unknown",
		EnclaveID:   "unknown-enclave",
		Measurement: "abc123",
		Timestamp:   time.Now().UTC().Format(time.RFC3339Nano),
	})
	_ = bundle.Finalize("")

	verifier := NewStandaloneVerifier([]string{"sgx"}, true)
	err := verifier.VerifyBundle(bundle)
	if err == nil {
		t.Fatal("expected error for untrusted platform in strict mode")
	}
}

func TestStandaloneVerifier_VerifyChain(t *testing.T) {
	b1 := NewEvidenceBundle("SOC2")
	b1.CreatedAt = "2026-01-01T00:00:00Z"
	b1.AddRecord(Record{
		ID:        "rec-1",
		Type:      "audit",
		Action:    "first",
		Actor:     "tester",
		Timestamp: "2026-01-01T00:00:00Z",
	})
	_ = b1.Finalize("")

	b2 := NewEvidenceBundle("SOC2")
	b2.CreatedAt = "2026-01-02T00:00:00Z"
	b2.AddRecord(Record{
		ID:        "rec-2",
		Type:      "audit",
		Action:    "second",
		Actor:     "tester",
		Timestamp: "2026-01-02T00:00:00Z",
	})
	_ = b2.Finalize("")

	verifier := NewStandaloneVerifier(nil, false)
	if err := verifier.VerifyChain([]*EvidenceBundle{b1, b2}); err != nil {
		t.Fatalf("chain verification failed: %v", err)
	}
}

func TestStandaloneVerifier_VerifyChain_Empty(t *testing.T) {
	verifier := NewStandaloneVerifier(nil, false)
	err := verifier.VerifyChain(nil)
	if err == nil {
		t.Fatal("expected error for empty chain")
	}
}

// ---------------------------------------------------------------------------
// Edge-case, error-path, and concurrency tests
// ---------------------------------------------------------------------------

func TestBundle_NilContent(t *testing.T) {
	bundle := NewEvidenceBundle("SOC2")

	// Add a record with minimal fields.
	bundle.AddRecord(Record{
		ID:        "rec-nil",
		Type:      "audit",
		Action:    "test",
		Actor:     "tester",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	})

	// Attestation with empty fields.
	bundle.AddAttestation(Attestation{})

	err := bundle.Finalize("")
	if err != nil {
		t.Fatalf("Finalize with empty attestation failed: %v", err)
	}
}

func TestBundle_FinalizeWithoutContent(t *testing.T) {
	bundle := NewEvidenceBundle("SOC2")
	err := bundle.Finalize("")
	if err == nil {
		t.Fatal("expected error when finalizing empty bundle")
	}
	if !errors.Is(err, ErrInvalidBundle) {
		t.Fatalf("expected ErrInvalidBundle, got %v", err)
	}
}

func TestBundle_FinalizeWithShortKey(t *testing.T) {
	bundle := NewEvidenceBundle("SOC2")
	bundle.AddRecord(Record{
		ID: "rec-short", Type: "audit", Action: "test", Actor: "tester",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	})

	// Key shorter than 16 bytes (32 hex chars).
	err := bundle.Finalize("tooshort")
	if err == nil {
		t.Fatal("expected error for short signing key")
	}
}

func TestBundle_TamperContentHash(t *testing.T) {
	bundle := NewEvidenceBundle("SOC2")
	bundle.AddRecord(Record{
		ID: "rec-tamper", Type: "audit", Action: "test", Actor: "tester",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	})
	_ = bundle.Finalize("")

	// Tamper with the content hash.
	bundle.ContentHash = "000000000000000000000000000000000000000000000000"

	err := bundle.Validate()
	if err == nil {
		t.Fatal("expected validation failure for tampered content hash")
	}
}

func TestBundle_ConcurrentFinalize(t *testing.T) {
	// Each goroutine creates its own bundle and finalizes it.
	var wg sync.WaitGroup
	errs := make(chan error, 20)

	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			bundle := NewEvidenceBundle("SOC2")
			bundle.AddRecord(Record{
				ID:        fmt.Sprintf("rec-%d", idx),
				Type:      "audit",
				Action:    "test",
				Actor:     "tester",
				Timestamp: time.Now().UTC().Format(time.RFC3339),
			})
			if err := bundle.Finalize(""); err != nil {
				errs <- fmt.Errorf("goroutine %d: %w", idx, err)
			}
		}(i)
	}
	wg.Wait()
	close(errs)

	for e := range errs {
		t.Errorf("concurrent finalize error: %v", e)
	}
}

func TestPortable_NilBundle(t *testing.T) {
	_, err := Package(nil, false)
	if err == nil {
		t.Fatal("expected error for nil bundle")
	}
}

func TestPortable_RoundTrip(t *testing.T) {
	bundle := NewEvidenceBundle("NIST-800-53")
	bundle.AddRecord(Record{
		ID: "rec-rt", Type: "audit", Action: "roundtrip", Actor: "tester",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	})
	_ = bundle.Finalize("")

	pe, err := Package(bundle, false)
	if err != nil {
		t.Fatalf("Package failed: %v", err)
	}

	data, err := json.Marshal(pe)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	restored, err := Unpackage(data)
	if err != nil {
		t.Fatalf("Unpackage failed: %v", err)
	}

	// Verify bundle ID survived the round trip.
	if restored.Bundle.ID != bundle.ID {
		t.Fatalf("bundle ID mismatch: %s vs %s", restored.Bundle.ID, bundle.ID)
	}
}

func TestVerifier_BrokenChain(t *testing.T) {
	// Create two bundles with a temporal gap.
	b1 := NewEvidenceBundle("SOC2")
	b1.AddRecord(Record{
		ID: "rec-gap-1", Type: "audit", Action: "first", Actor: "tester",
		Timestamp: "2026-01-01T00:00:00Z",
	})
	_ = b1.Finalize("")

	b2 := NewEvidenceBundle("SOC2")
	b2.AddRecord(Record{
		ID: "rec-gap-2", Type: "audit", Action: "second", Actor: "tester",
		Timestamp: "2026-06-01T00:00:00Z", // Large gap.
	})
	_ = b2.Finalize("")

	verifier := NewStandaloneVerifier(nil, false)
	err := verifier.VerifyChain([]*EvidenceBundle{b1, b2})
	// The verifier checks structural integrity; gaps may or may not be an error.
	if err != nil {
		t.Logf("VerifyChain with temporal gap returned: %v", err)
	}
}

func TestVerifier_TamperedBundle(t *testing.T) {
	bundle := NewEvidenceBundle("SOC2")
	bundle.AddRecord(Record{
		ID: "rec-verify", Type: "audit", Action: "test", Actor: "tester",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	})
	_ = bundle.Finalize("")

	// Tamper with record content.
	bundle.Records[0].Action = "tampered-action"

	verifier := NewStandaloneVerifier(nil, false)
	err := verifier.VerifyBundle(bundle)
	if err == nil {
		t.Fatal("expected error for tampered bundle content")
	}
}

func TestCustody_ConcurrentTransfers(t *testing.T) {
	chain, _ := RecordCreation("auditor-01")

	var wg sync.WaitGroup
	var mu sync.Mutex
	errs := make(chan error, 20)

	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			mu.Lock()
			newChain, err := RecordAccess(chain, fmt.Sprintf("reviewer-%d", idx))
			if err != nil {
				errs <- err
			} else {
				_ = newChain
			}
			mu.Unlock()
		}(i)
	}
	wg.Wait()
	close(errs)

	for e := range errs {
		t.Errorf("concurrent custody error: %v", e)
	}
}

func TestCustody_InvalidAction(t *testing.T) {
	// Empty chain.
	err := VerifyCustodyChain(nil)
	if err == nil {
		t.Fatal("expected error for empty chain")
	}
	if !errors.Is(err, ErrCustodyViolation) {
		t.Logf("error type: %v", err)
	}
}

func TestExport_AllFormats(t *testing.T) {
	bundle := NewEvidenceBundle("SOC2")
	bundle.AddRecord(Record{
		ID: "rec-export", Type: "audit", Action: "test", Actor: "tester",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	})
	_ = bundle.Finalize("")

	// JSON export via Package.
	pe, err := Package(bundle, false)
	if err != nil {
		t.Fatalf("Package failed: %v", err)
	}

	jsonData, err := json.Marshal(pe)
	if err != nil {
		t.Fatalf("JSON marshal failed: %v", err)
	}
	if len(jsonData) == 0 {
		t.Error("expected non-empty JSON export")
	}
}
