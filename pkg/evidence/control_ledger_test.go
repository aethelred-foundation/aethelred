package evidence

import "testing"

func TestControlLedger_FinalizeValidateAndPackage(t *testing.T) {
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
		SealID:         "seal-control-ledger-001",
		JobID:          "job-control-ledger-001",
		OutputHash:     EvidenceHashHex([]byte("control-ledger-output")),
		ValidatorCount: 4,
		BlockHeight:    64,
		Timestamp:      receipt.EvaluatedAt.UTC().Format(rfc3339Nano),
	}
	traceLink, err := NewTraceLink(identity, receipt, seal, "auditor trace")
	if err != nil {
		t.Fatalf("trace link creation failed: %v", err)
	}

	ledger := NewControlLedger("Trust Kernel")
	ledger.WithMetadata("workflow", "treasury_release")
	ledger.AddRecord(Record{
		ID:        "record-control-ledger-001",
		Type:      "governance",
		Action:    "payments.release.authorized",
		Actor:     identity.AgentID(),
		Timestamp: receipt.EvaluatedAt.UTC().Format(rfc3339Nano),
		Data: map[string]string{
			"policy_receipt_id": receipt.ID,
			"seal_id":           seal.SealID,
		},
	})
	ledger.AddAgentPassport(passport)
	approvalAttestation, err := NewApproverAttestationEvidence(
		identity,
		receipt,
		"record-control-ledger-001",
		traceLink.ID,
		seal.SealID,
		receipt.EvaluatedAt,
		"Treasury approver attestation",
		map[string]string{"approval_stage": "final"},
	)
	if err != nil {
		t.Fatalf("approver attestation conversion failed: %v", err)
	}
	if err := ledger.AddApproverAttestation(approvalAttestation); err != nil {
		t.Fatalf("adding approver attestation failed: %v", err)
	}
	if err := ledger.AddValueSettlement(ValueSettlementEvidence{
		ID:                "value-settlement:ledger-settlement",
		SettlementID:      "ledger-settlement",
		WorkflowID:        "record-control-ledger-001",
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
		Reference:         "record-control-ledger-001",
		TxHash:            "0xledger001",
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
	trustCompliance := TrustCompliancePackageEvidence{
		ID:            "trust-compliance-package:ledger-package",
		PackageHash:   EvidenceHashHex([]byte("ledger-package")),
		PayloadHash:   EvidenceHashHex([]byte("ledger-payload")),
		DocumentHash:  EvidenceHashHex([]byte("ledger-document")),
		Format:        "json",
		ExportVersion: "1.0.0",
		GeneratedAt:   receipt.EvaluatedAt.UTC().Format(rfc3339Nano),
		AuditAnchor: &TrustComplianceAuditAnchorEvidence{
			Sequence:    42,
			RecordHash:  EvidenceHashHex([]byte("ledger-anchor")),
			Action:      "trust_compliance_export_anchored",
			Actor:       "validator:test-signer",
			Timestamp:   receipt.EvaluatedAt.UTC().Format(rfc3339Nano),
			BlockHeight: 128,
		},
	}
	if err := ledger.AddTrustCompliancePackage(trustCompliance); err != nil {
		t.Fatalf("adding trust compliance package failed: %v", err)
	}

	if err := ledger.AddControl(LedgerControl{
		ControlID:   "TRUST-001",
		ControlName: "Authorized Autonomous Action",
		Description: "Proves who acted, what policy allowed it, and which sealed execution followed.",
		Status:      ControlSatisfied,
		EvidenceRefs: ControlEvidenceRefs{
			RecordIDs:                 []string{"record-control-ledger-001"},
			ApproverAttestationIDs:    []string{approvalAttestation.ID},
			ValueSettlementIDs:        []string{"value-settlement:ledger-settlement"},
			PolicyReceiptIDs:          []string{receipt.ID},
			SealIDs:                   []string{seal.SealID},
			TraceLinkIDs:              []string{traceLink.ID},
			TrustCompliancePackageIDs: []string{trustCompliance.ID},
		},
	}); err != nil {
		t.Fatalf("adding control mapping failed: %v", err)
	}

	if err := ledger.Finalize(""); err != nil {
		t.Fatalf("finalize failed: %v", err)
	}
	if err := ledger.Validate(); err != nil {
		t.Fatalf("validate failed: %v", err)
	}

	if ledger.Summary.TotalControls != 1 {
		t.Fatalf("expected 1 control, got %d", ledger.Summary.TotalControls)
	}
	if ledger.Summary.TotalPassports != 1 || ledger.Summary.TotalApproverAttestations != 1 || ledger.Summary.TotalValueSettlements != 1 || ledger.Summary.TotalPolicyReceipts != 1 || ledger.Summary.TotalTraceLinks != 1 || ledger.Summary.TotalTrustCompliancePackages != 1 {
		t.Fatal("expected summary counts to reflect trust artifacts")
	}
	if !ledger.Summary.TraceIntact || !ledger.Summary.PortableReady || !ledger.Summary.Finalized {
		t.Fatal("expected finalized control ledger to be trace-intact and portable-ready")
	}
	if len(ledger.Summary.Jurisdictions) != 2 {
		t.Fatalf("expected two unique jurisdictions, got %d", len(ledger.Summary.Jurisdictions))
	}

	portable, err := PackageControlLedger(ledger, true)
	if err != nil {
		t.Fatalf("package control ledger failed: %v", err)
	}
	if err := VerifyPortable(portable); err != nil {
		t.Fatalf("portable verification failed: %v", err)
	}

	verifier := NewStandaloneVerifier(nil, true)
	if err := verifier.VerifyControlLedger(ledger); err != nil {
		t.Fatalf("control ledger verification failed: %v", err)
	}
}

func TestControlLedger_Validate_InvalidControlReferenceFails(t *testing.T) {
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
		SealID:         "seal-control-ledger-002",
		JobID:          "job-control-ledger-002",
		OutputHash:     EvidenceHashHex([]byte("control-ledger-output-2")),
		ValidatorCount: 4,
		BlockHeight:    65,
		Timestamp:      receipt.EvaluatedAt.UTC().Format(rfc3339Nano),
	}
	traceLink, err := NewTraceLink(identity, receipt, seal, "auditor trace")
	if err != nil {
		t.Fatalf("trace link creation failed: %v", err)
	}

	ledger := NewControlLedger("Trust Kernel")
	ledger.AddRecord(Record{
		ID:        "record-control-ledger-002",
		Type:      "governance",
		Action:    "payments.release.authorized",
		Actor:     identity.AgentID(),
		Timestamp: receipt.EvaluatedAt.UTC().Format(rfc3339Nano),
	})
	ledger.AddAgentPassport(passport)
	if err := ledger.AddApproverAttestation(ApproverAttestationEvidence{
		ID:                "approver-attestation:broken",
		Approver:          identity.AgentID(),
		ApproverDID:       identity.AgentID(),
		PassportDID:       identity.AgentID(),
		PolicyReceiptID:   receipt.ID,
		PolicyReceiptHash: receipt.ContentHash,
		Action:            receipt.Action,
		Decision:          "allow",
		TraceLinkID:       traceLink.ID,
		SealID:            seal.SealID,
		AuthorizedAt:      receipt.EvaluatedAt.UTC().Format(rfc3339Nano),
	}); err != nil {
		t.Fatalf("adding approver attestation failed: %v", err)
	}
	if err := ledger.AddValueSettlement(ValueSettlementEvidence{
		ID:                "value-settlement:broken",
		SettlementID:      "broken",
		FiatAmount:        100,
		FiatCurrency:      "USD",
		TokenAmount:       100,
		TokenDenomination: "USDC",
		Status:            "settled",
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
		PackageHash:   EvidenceHashHex([]byte("broken-package")),
		PayloadHash:   EvidenceHashHex([]byte("broken-payload")),
		DocumentHash:  EvidenceHashHex([]byte("broken-document")),
		Format:        "json",
		ExportVersion: "1.0.0",
		GeneratedAt:   receipt.EvaluatedAt.UTC().Format(rfc3339Nano),
	}); err != nil {
		t.Fatalf("adding trust compliance package failed: %v", err)
	}

	if err := ledger.AddControl(LedgerControl{
		ControlID:   "TRUST-002",
		ControlName: "Broken Mapping",
		Status:      ControlSatisfied,
		EvidenceRefs: ControlEvidenceRefs{
			ApproverAttestationIDs:    []string{"approver-attestation:does-not-exist"},
			ValueSettlementIDs:        []string{"value-settlement:does-not-exist"},
			TrustCompliancePackageIDs: []string{"trust-compliance-package:does-not-exist"},
		},
	}); err != nil {
		t.Fatalf("adding control mapping failed: %v", err)
	}

	if err := ledger.Finalize(""); err != nil {
		t.Fatalf("finalize failed: %v", err)
	}
	if err := ledger.Validate(); err == nil {
		t.Fatal("expected invalid control reference to fail validation")
	}
}

const rfc3339Nano = "2006-01-02T15:04:05.999999999Z07:00"
