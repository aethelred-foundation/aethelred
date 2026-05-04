package export

import (
	"encoding/csv"
	"encoding/json"
	"strings"
	"testing"

	"github.com/aethelred/aethelred/pkg/evidence"
)

type testControlLedger struct {
	ID              string            `json:"id"`
	Framework       string            `json:"framework"`
	CreatedAt       string            `json:"created_at"`
	Version         string            `json:"version"`
	Metadata        map[string]string `json:"metadata"`
	Summary         map[string]any    `json:"summary"`
	Controls        []map[string]any  `json:"controls"`
	Passports       []map[string]any  `json:"agent_passports"`
	Approvals       []map[string]any  `json:"approver_attestations"`
	Settlements     []map[string]any  `json:"value_settlements"`
	Receipts        []map[string]any  `json:"policy_receipts"`
	Seals           []map[string]any  `json:"seals"`
	Links           []map[string]any  `json:"trace_links"`
	TrustCompliance []map[string]any  `json:"trust_compliance_packages"`
}

func newTestControlLedger() *testControlLedger {
	return &testControlLedger{
		ID:        "ledger-001",
		Framework: "finance-control-ledger",
		CreatedAt: "2026-04-14T10:00:00Z",
		Version:   "0.1.0",
		Metadata: map[string]string{
			"jurisdiction": "UAE",
			"owner":        "controls-team",
		},
		Summary: map[string]any{
			"total_controls":                  1,
			"total_passports":                 1,
			"total_approver_attestations":     1,
			"total_value_settlements":         1,
			"total_policy_receipts":           1,
			"total_seals":                     1,
			"total_trace_links":               1,
			"total_trust_compliance_packages": 1,
			"chain_intact":                    true,
		},
		Controls: []map[string]any{
			{
				"control_id":     "CTRL-001",
				"control_name":   "Treasury Release Approval",
				"status":         "satisfied",
				"description":    "Release requires policy and execution proof.",
				"evidence_count": 4,
				"evidence_refs":  []string{"rec-001", "approver-attestation:approval-001", "seal-001", "link-001"},
				"findings":       []string{"Approval path is fully evidenced."},
				"metadata": map[string]string{
					"domain": "treasury",
				},
			},
		},
		Passports: []map[string]any{
			{
				"did":               "did:aethelred:agent-001",
				"issuer":            "did:aethelred:issuer-001",
				"public_key_hash":   "abcd",
				"human_owner":       "alice.chen",
				"business_unit":     "treasury",
				"sponsor_of_record": "did:aethelred:bank-parent",
				"liability_model":   "enterprise-sponsored",
				"jurisdiction_tags": []string{"UAE", "UK"},
				"allowed_tools":     []string{"payments.release"},
				"issued_at":         "2026-04-14T10:00:00Z",
			},
		},
		Approvals: []map[string]any{
			{
				"id":                  "approver-attestation:approval-001",
				"approval_record_id":  "approval-001",
				"approver":            "alice.chen",
				"approver_did":        "did:aethelred:agent-001",
				"passport_did":        "did:aethelred:agent-001",
				"policy_receipt_id":   "receipt-001",
				"policy_receipt_hash": "hash-001",
				"action":              "payments.release.approve",
				"resource":            "acct:treasury-main",
				"decision":            "allow",
				"trace_link_id":       "link-001",
				"seal_id":             "seal-001",
				"authorized_at":       "2026-04-14T10:01:30Z",
				"comment":             "Approved by treasury controller",
				"metadata": map[string]string{
					"approval_stage": "final",
				},
			},
		},
		Settlements: []map[string]any{
			{
				"id":                  "value-settlement:settlement-001",
				"settlement_id":       "settlement-001",
				"workflow_id":         "ledger-001",
				"network":             "aethelred",
				"method":              "stablecoin",
				"counterparty":        "Trusted Vendor",
				"beneficiary":         "Trusted Vendor",
				"fiat_amount":         75000,
				"fiat_currency":       "USD",
				"token_amount":        75000,
				"token_denomination":  "USDC",
				"exchange_rate":       1.0,
				"status":              "settled",
				"reason_code":         "treasury_release",
				"reference":           "ledger-001",
				"tx_hash":             "0xsettlement001",
				"policy_receipt_id":   "receipt-001",
				"policy_receipt_hash": "hash-001",
				"seal_id":             "seal-001",
				"settled_at":          "2026-04-14T10:02:30Z",
			},
		},
		Receipts: []map[string]any{
			{
				"id":           "receipt-001",
				"request_id":   "req-001",
				"actor":        "did:aethelred:agent-001",
				"action":       "payments.release",
				"resource":     "acct:treasury-main",
				"decision":     "allow",
				"audit_trail":  "trace-001",
				"signer":       "did:aethelred:policy-gateway-1",
				"content_hash": "hash-001",
				"evaluated_at": "2026-04-14T10:01:00Z",
			},
		},
		Seals: []map[string]any{
			{
				"seal_id":         "seal-001",
				"job_id":          "job-001",
				"output_hash":     "out-001",
				"validator_count": 4,
				"block_height":    123,
				"timestamp":       "2026-04-14T10:02:00Z",
			},
		},
		Links: []map[string]any{
			{
				"id":                  "link-001",
				"agent_did":           "did:aethelred:agent-001",
				"policy_receipt_id":   "receipt-001",
				"policy_receipt_hash": "hash-001",
				"seal_id":             "seal-001",
				"output_hash":         "out-001",
				"linked_at":           "2026-04-14T10:03:00Z",
				"description":         "Treasury approval trace chain",
			},
		},
		TrustCompliance: []map[string]any{
			{
				"id":                       "trust-compliance-package:pkg-001",
				"package_hash":             "pkg-001",
				"payload_hash":             "payload-001",
				"document_hash":            "document-001",
				"format":                   "oscal",
				"export_version":           "1.0.0",
				"generated_at":             "2026-04-14T10:04:00Z",
				"signed":                   true,
				"signer":                   "validator:test-signer",
				"audit_anchor_sequence":    7,
				"audit_anchor_record_hash": "anchor-001",
				"audit_anchor_action":      "trust_compliance_export_anchored",
				"audit_anchor_timestamp":   "2026-04-14T10:04:05Z",
			},
		},
	}
}

func TestExportControlLedgerJSON(t *testing.T) {
	data, err := ExportControlLedgerJSON(newTestControlLedger())
	if err != nil {
		t.Fatalf("export json: %v", err)
	}

	var exported ControlLedgerExport
	if err := json.Unmarshal(data, &exported); err != nil {
		t.Fatalf("unmarshal json: %v", err)
	}

	if exported.LedgerID != "ledger-001" {
		t.Fatalf("expected ledger id ledger-001, got %q", exported.LedgerID)
	}
	if exported.Summary.TotalControls != 1 || exported.Summary.TotalApproverAttestations != 1 || exported.Summary.TotalValueSettlements != 1 || exported.Summary.TotalTraceLinks != 1 || exported.Summary.TotalTrustCompliancePackages != 1 {
		t.Fatalf("unexpected summary: %+v", exported.Summary)
	}
	if len(exported.Controls) != 1 || len(exported.Passports) != 1 || len(exported.ApproverAttestations) != 1 || len(exported.ValueSettlements) != 1 || len(exported.PolicyReceipts) != 1 || len(exported.TrustCompliancePackages) != 1 {
		t.Fatalf("unexpected section counts: %+v", exported)
	}
}

func TestExportControlLedgerCSV(t *testing.T) {
	data, err := ExportControlLedgerCSV(newTestControlLedger())
	if err != nil {
		t.Fatalf("export csv: %v", err)
	}

	reader := csv.NewReader(strings.NewReader(string(data)))
	rows, err := reader.ReadAll()
	if err != nil {
		t.Fatalf("read csv: %v", err)
	}

	if len(rows) != 10 {
		t.Fatalf("expected 10 csv rows including header, got %d", len(rows))
	}
	if rows[0][0] != "row_type" {
		t.Fatalf("unexpected header: %v", rows[0])
	}
	if rows[1][0] != "summary" || rows[2][0] != "control" || rows[3][0] != "passport" {
		t.Fatalf("unexpected row ordering: %v", rows[1:4])
	}
	if rows[4][0] != "approver_attestation" {
		t.Fatalf("unexpected approval attestation row ordering: %v", rows[1:5])
	}
	if rows[5][0] != "value_settlement" {
		t.Fatalf("unexpected value settlement row ordering: %v", rows[1:6])
	}
	if rows[8][0] != "trace_link" || rows[9][0] != "trust_compliance_package" {
		t.Fatalf("unexpected final row ordering: %v", rows[8:])
	}
}

func TestExportControlLedgerOSCAL(t *testing.T) {
	data, err := ExportControlLedgerOSCAL(newTestControlLedger())
	if err != nil {
		t.Fatalf("export oscal: %v", err)
	}

	var doc ControlLedgerOSCALDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("unmarshal oscal: %v", err)
	}

	if doc.AssessmentResults.Metadata.Title != "Aethelred Control Ledger Assessment" {
		t.Fatalf("unexpected title: %q", doc.AssessmentResults.Metadata.Title)
	}
	if len(doc.AssessmentResults.Results) != 1 {
		t.Fatalf("expected one assessment result, got %d", len(doc.AssessmentResults.Results))
	}
	result := doc.AssessmentResults.Results[0]
	if len(result.Findings) != 1 || len(result.Observations) < 7 {
		t.Fatalf("unexpected result shape: findings=%d observations=%d", len(result.Findings), len(result.Observations))
	}
	if len(result.Attestations) < 3 {
		t.Fatalf("expected summary plus approver attestations, got %d", len(result.Attestations))
	}
	if result.ReviewedControls.ControlSelections[0].IncludeControls[0].WithIDs[0] != "CTRL-001" {
		t.Fatalf("unexpected reviewed control ids: %+v", result.ReviewedControls)
	}
}

func TestExportControlLedgerNil(t *testing.T) {
	if _, err := ExportControlLedgerJSON(nil); err == nil {
		t.Fatal("expected json export to fail on nil ledger")
	}
	if _, err := ExportControlLedgerCSV(nil); err == nil {
		t.Fatal("expected csv export to fail on nil ledger")
	}
	if _, err := ExportControlLedgerOSCAL(nil); err == nil {
		t.Fatal("expected oscal export to fail on nil ledger")
	}
}

func TestExportControlLedgerJSON_TypedLedger(t *testing.T) {
	ledger := evidence.NewControlLedger("finance-control-ledger")
	ledger.AddRecord(evidence.Record{
		ID:        "record-001",
		Type:      "governance",
		Action:    "payments.release.authorized",
		Actor:     "did:aethelred:agent-001",
		Timestamp: "2026-04-14T10:00:00Z",
	})
	ledger.AddAgentPassport(evidence.AgentPassportEvidence{
		DID:           "did:aethelred:agent-001",
		Issuer:        "did:aethelred:issuer-001",
		PublicKeyHash: "abcd",
		HumanOwner:    "alice.chen",
		IssuedAt:      "2026-04-14T10:00:00Z",
	})
	if err := ledger.AddApproverAttestation(evidence.ApproverAttestationEvidence{
		ID:                "approver-attestation:approval-001",
		ApprovalRecordID:  "record-001",
		Approver:          "did:aethelred:agent-001",
		ApproverDID:       "did:aethelred:agent-001",
		PassportDID:       "did:aethelred:agent-001",
		PolicyReceiptID:   "receipt-001",
		PolicyReceiptHash: "hash-001",
		Action:            "payments.release.approve",
		Resource:          "acct:treasury-main",
		Decision:          "allow",
		TraceLinkID:       "link-001",
		SealID:            "seal-001",
		AuthorizedAt:      "2026-04-14T10:01:30Z",
		Comment:           "Approved by treasury controller",
		Metadata: map[string]string{
			"approval_stage": "final",
		},
	}); err != nil {
		t.Fatalf("add approver attestation: %v", err)
	}
	if err := ledger.AddValueSettlement(evidence.ValueSettlementEvidence{
		ID:                "value-settlement:settlement-001",
		SettlementID:      "settlement-001",
		WorkflowID:        "ledger-001",
		Network:           "aethelred",
		Method:            "stablecoin",
		Counterparty:      "Trusted Vendor",
		Beneficiary:       "Trusted Vendor",
		FiatAmount:        75000,
		FiatCurrency:      "USD",
		TokenAmount:       75000,
		TokenDenomination: "USDC",
		ExchangeRate:      1.0,
		Status:            "settled",
		ReasonCode:        "treasury_release",
		Reference:         "ledger-001",
		TxHash:            "0xsettlement001",
		PolicyReceiptID:   "receipt-001",
		PolicyReceiptHash: "hash-001",
		SealID:            "seal-001",
		SettledAt:         "2026-04-14T10:02:30Z",
	}); err != nil {
		t.Fatalf("add value settlement: %v", err)
	}
	ledger.AddPolicyReceipt(evidence.PolicyReceiptEvidence{
		ID:          "receipt-001",
		RequestID:   "req-001",
		Actor:       "did:aethelred:agent-001",
		Action:      "payments.release",
		Decision:    "allow",
		ContentHash: "hash-001",
		Signer:      "did:aethelred:policy-gateway-1",
		EvaluatedAt: "2026-04-14T10:01:00Z",
	})
	ledger.AddSeal(evidence.Seal{
		SealID:         "seal-001",
		JobID:          "job-001",
		OutputHash:     "out-001",
		ValidatorCount: 4,
		Timestamp:      "2026-04-14T10:02:00Z",
	})
	ledger.AddTraceLink(evidence.TraceLink{
		ID:                "link-001",
		AgentDID:          "did:aethelred:agent-001",
		PolicyReceiptID:   "receipt-001",
		PolicyReceiptHash: "hash-001",
		SealID:            "seal-001",
		LinkedAt:          "2026-04-14T10:03:00Z",
	})
	if err := ledger.AddTrustCompliancePackage(evidence.TrustCompliancePackageEvidence{
		ID:            "trust-compliance-package:pkg-001",
		PackageHash:   "pkg-001",
		PayloadHash:   "payload-001",
		DocumentHash:  "document-001",
		Format:        "json",
		ExportVersion: "1.0.0",
		GeneratedAt:   "2026-04-14T10:04:00Z",
		AuditAnchor: &evidence.TrustComplianceAuditAnchorEvidence{
			Sequence:    7,
			RecordHash:  "anchor-001",
			Action:      "trust_compliance_export_anchored",
			Actor:       "validator:test-signer",
			Timestamp:   "2026-04-14T10:04:05Z",
			BlockHeight: 123,
		},
	}); err != nil {
		t.Fatalf("add trust compliance package: %v", err)
	}
	if err := ledger.AddControl(evidence.LedgerControl{
		ControlID:   "CTRL-001",
		ControlName: "Treasury Release Approval",
		Status:      evidence.ControlSatisfied,
		EvidenceRefs: evidence.ControlEvidenceRefs{
			RecordIDs:                 []string{"record-001"},
			ApproverAttestationIDs:    []string{"approver-attestation:approval-001"},
			ValueSettlementIDs:        []string{"value-settlement:settlement-001"},
			PolicyReceiptIDs:          []string{"receipt-001"},
			SealIDs:                   []string{"seal-001"},
			TraceLinkIDs:              []string{"link-001"},
			TrustCompliancePackageIDs: []string{"trust-compliance-package:pkg-001"},
		},
	}); err != nil {
		t.Fatalf("add control: %v", err)
	}

	data, err := ExportControlLedgerJSON(ledger)
	if err != nil {
		t.Fatalf("export typed ledger json: %v", err)
	}

	var exported ControlLedgerExport
	if err := json.Unmarshal(data, &exported); err != nil {
		t.Fatalf("unmarshal typed ledger json: %v", err)
	}
	if exported.Summary.TotalControls != 1 || exported.Summary.TotalApproverAttestations != 1 || exported.Summary.TotalValueSettlements != 1 || len(exported.Controls) != 1 || len(exported.PolicyReceipts) != 1 || exported.Summary.TotalTrustCompliancePackages != 1 {
		t.Fatalf("unexpected typed export summary: %+v", exported.Summary)
	}
	if len(exported.TrustCompliancePackages) != 1 {
		t.Fatalf("expected one trust compliance export section, got %+v", exported)
	}
	if len(exported.ApproverAttestations) != 1 {
		t.Fatalf("expected one approver attestation export section, got %+v", exported)
	}
	if len(exported.ValueSettlements) != 1 {
		t.Fatalf("expected one value settlement export section, got %+v", exported)
	}
	if exported.Controls[0].EvidenceCount != 7 {
		t.Fatalf("expected flattened evidence count 7, got %d", exported.Controls[0].EvidenceCount)
	}
}
