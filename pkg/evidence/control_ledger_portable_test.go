package evidence

import (
	"crypto/ed25519"
	"testing"
)

func TestPortableControlLedgerPackage_Verify(t *testing.T) {
	ledger := newPortableControlLedgerFixture(t)

	pkg, err := PackagePortableControlLedger(ledger, true)
	if err != nil {
		t.Fatalf("PackagePortableControlLedger failed: %v", err)
	}
	if pkg.PackageHash == "" {
		t.Fatal("expected package hash to be populated")
	}
	if pkg.SchemaDefinition != SchemaVersion {
		t.Fatalf("expected schema definition %q, got %q", SchemaVersion, pkg.SchemaDefinition)
	}
	if pkg.Ledger == nil || pkg.Ledger.Bundle == nil {
		t.Fatal("expected packaged ledger snapshot")
	}
	if pkg.Ledger.Summary.TotalApproverAttestations != 1 || pkg.Ledger.Summary.TotalValueSettlements != 1 || pkg.Ledger.Summary.TotalTrustCompliancePackages != 1 {
		t.Fatalf("expected trust compliance count to survive packaging, got %+v", pkg.Ledger.Summary)
	}

	if err := VerifyPortableControlLedgerPackage(pkg); err != nil {
		t.Fatalf("VerifyPortableControlLedgerPackage failed: %v", err)
	}
}

func TestPortableControlLedgerPackage_TamperFails(t *testing.T) {
	ledger := newPortableControlLedgerFixture(t)

	pkg, err := PackagePortableControlLedger(ledger, false)
	if err != nil {
		t.Fatalf("PackagePortableControlLedger failed: %v", err)
	}
	pkg.Ledger.Bundle.TrustCompliancePackages[0].PackageHash = "tampered"

	if err := VerifyPortableControlLedgerPackage(pkg); err == nil {
		t.Fatal("expected tampered portable control ledger package to fail verification")
	}
}

func TestPortableControlLedgerPackage_SignAndAnchorVerify(t *testing.T) {
	ledger := newPortableControlLedgerFixture(t)

	pkg, err := PackagePortableControlLedger(ledger, true)
	if err != nil {
		t.Fatalf("PackagePortableControlLedger failed: %v", err)
	}

	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	if err := pkg.SignEd25519(ed25519.NewKeyFromSeed(seed), "validator:test-portable-ledger"); err != nil {
		t.Fatalf("SignEd25519 failed: %v", err)
	}
	anchor := &PortableControlLedgerPackageAuditAnchor{
		Sequence:    29,
		Action:      "control_ledger_package_anchored",
		Category:    "governance",
		Severity:    "info",
		BlockHeight: 144,
		Timestamp:   "2026-04-14T16:00:00Z",
		Actor:       "validator:test-portable-ledger",
		Details:     pkg.AnchorDetails(),
	}
	anchor.RecordHash = anchor.ComputeHash()
	pkg.AuditAnchor = anchor

	if err := VerifyPortableControlLedgerPackage(pkg); err != nil {
		t.Fatalf("VerifyPortableControlLedgerPackage failed: %v", err)
	}
}

func newPortableControlLedgerFixture(t *testing.T) *ControlLedger {
	t.Helper()

	identity := newEnterpriseIdentityFixture(t)
	receipt := newSignedPolicyReceiptFixture(t, identity.AgentID())

	passport, err := NewAgentPassportEvidence(identity)
	if err != nil {
		t.Fatalf("passport conversion failed: %v", err)
	}
	receiptEvidence, err := NewPolicyReceiptEvidence(receipt)
	if err != nil {
		t.Fatalf("policy receipt conversion failed: %v", err)
	}

	seal := Seal{
		SealID:         "seal-portable-ledger-001",
		JobID:          "job-portable-ledger-001",
		OutputHash:     EvidenceHashHex([]byte("portable-ledger-output")),
		ValidatorCount: 4,
		BlockHeight:    64,
		Timestamp:      receipt.EvaluatedAt.UTC().Format(rfc3339Nano),
	}
	traceLink, err := NewTraceLink(identity, receipt, seal, "portable control ledger")
	if err != nil {
		t.Fatalf("trace link creation failed: %v", err)
	}

	ledger := NewControlLedger("Trust Kernel")
	ledger.WithMetadata("workflow", "treasury_release")
	ledger.AddRecord(Record{
		ID:        "record-portable-ledger-001",
		Type:      "governance",
		Action:    "payments.release.authorized",
		Actor:     identity.AgentID(),
		Timestamp: receipt.EvaluatedAt.UTC().Format(rfc3339Nano),
	})
	ledger.AddAgentPassport(passport)
	approverAttestation, err := NewApproverAttestationEvidence(
		identity,
		receipt,
		"record-portable-ledger-001",
		traceLink.ID,
		seal.SealID,
		receipt.EvaluatedAt,
		"Treasury approver attestation",
		map[string]string{"approval_stage": "final"},
	)
	if err != nil {
		t.Fatalf("approver attestation conversion failed: %v", err)
	}
	if err := ledger.AddApproverAttestation(approverAttestation); err != nil {
		t.Fatalf("adding approver attestation failed: %v", err)
	}
	if err := ledger.AddValueSettlement(ValueSettlementEvidence{
		ID:                "value-settlement:portable-ledger",
		SettlementID:      "portable-ledger",
		WorkflowID:        "portable-ledger",
		Network:           "aethelred",
		Method:            "stablecoin",
		Counterparty:      "Acme Supplier",
		Beneficiary:       "Acme Supplier",
		FiatAmount:        2500,
		FiatCurrency:      "USD",
		TokenAmount:       2500,
		TokenDenomination: "USDC",
		ExchangeRate:      1.0,
		Status:            "settled",
		ReasonCode:        "treasury_release",
		Reference:         "portable-ledger",
		TxHash:            "0xportable001",
		PolicyReceiptID:   receipt.ID,
		PolicyReceiptHash: receipt.ContentHash,
		SealID:            seal.SealID,
		SettledAt:         receipt.EvaluatedAt.UTC().Format(rfc3339Nano),
	}); err != nil {
		t.Fatalf("adding value settlement failed: %v", err)
	}
	ledger.AddPolicyReceipt(receiptEvidence)
	ledger.AddSeal(seal)
	ledger.AddTraceLink(traceLink)
	if err := ledger.AddTrustCompliancePackage(TrustCompliancePackageEvidence{
		ID:            "trust-compliance-package:portable-ledger",
		PackageHash:   EvidenceHashHex([]byte("portable-ledger-package")),
		PayloadHash:   EvidenceHashHex([]byte("portable-ledger-payload")),
		DocumentHash:  EvidenceHashHex([]byte("portable-ledger-document")),
		Format:        "json",
		ExportVersion: "1.0.0",
		GeneratedAt:   receipt.EvaluatedAt.UTC().Format(rfc3339Nano),
		AuditAnchor: &TrustComplianceAuditAnchorEvidence{
			Sequence:    19,
			RecordHash:  EvidenceHashHex([]byte("portable-ledger-anchor")),
			Action:      "trust_compliance_export_anchored",
			Actor:       "validator:test-signer",
			Timestamp:   receipt.EvaluatedAt.UTC().Format(rfc3339Nano),
			BlockHeight: 144,
		},
	}); err != nil {
		t.Fatalf("adding trust compliance package failed: %v", err)
	}

	if err := ledger.AddControl(LedgerControl{
		ControlID:   "TRUST-PORTABLE-001",
		ControlName: "Portable Auditor Package",
		Status:      ControlSatisfied,
		EvidenceRefs: ControlEvidenceRefs{
			RecordIDs:                 []string{"record-portable-ledger-001"},
			ApproverAttestationIDs:    []string{approverAttestation.ID},
			ValueSettlementIDs:        []string{"value-settlement:portable-ledger"},
			PolicyReceiptIDs:          []string{receipt.ID},
			SealIDs:                   []string{seal.SealID},
			TraceLinkIDs:              []string{traceLink.ID},
			TrustCompliancePackageIDs: []string{"trust-compliance-package:portable-ledger"},
		},
	}); err != nil {
		t.Fatalf("adding control failed: %v", err)
	}

	if err := ledger.Finalize(""); err != nil {
		t.Fatalf("finalize failed: %v", err)
	}
	if err := ledger.Validate(); err != nil {
		t.Fatalf("validate failed: %v", err)
	}

	return ledger
}
