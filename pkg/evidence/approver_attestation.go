package evidence

import (
	"fmt"
	"strings"
	"time"

	"github.com/aethelred/aethelred/pkg/governance/policy"
	"github.com/aethelred/aethelred/pkg/protocol/agent"
)

// ApproverAttestationEvidence captures one authenticated approval action in a
// workflow as a first-class, auditor-readable artifact.
type ApproverAttestationEvidence struct {
	ID                string            `json:"id"`
	ApprovalRecordID  string            `json:"approval_record_id,omitempty"`
	Approver          string            `json:"approver"`
	ApproverDID       string            `json:"approver_did,omitempty"`
	PassportDID       string            `json:"passport_did,omitempty"`
	PolicyReceiptID   string            `json:"policy_receipt_id"`
	PolicyReceiptHash string            `json:"policy_receipt_hash"`
	Action            string            `json:"action,omitempty"`
	Resource          string            `json:"resource,omitempty"`
	Decision          string            `json:"decision,omitempty"`
	TraceLinkID       string            `json:"trace_link_id,omitempty"`
	SealID            string            `json:"seal_id,omitempty"`
	AuthorizedAt      string            `json:"authorized_at"`
	Comment           string            `json:"comment,omitempty"`
	Metadata          map[string]string `json:"metadata,omitempty"`
}

// Normalize validates and fills deterministic defaults for approver
// attestations.
func (aa *ApproverAttestationEvidence) Normalize() error {
	if aa == nil {
		return fmt.Errorf("evidence/approver_attestation: nil approver attestation")
	}
	aa.Approver = strings.TrimSpace(aa.Approver)
	aa.ApproverDID = strings.TrimSpace(aa.ApproverDID)
	aa.PassportDID = strings.TrimSpace(aa.PassportDID)
	aa.ApprovalRecordID = strings.TrimSpace(aa.ApprovalRecordID)
	aa.PolicyReceiptID = strings.TrimSpace(aa.PolicyReceiptID)
	aa.PolicyReceiptHash = strings.TrimSpace(aa.PolicyReceiptHash)
	aa.Action = strings.TrimSpace(aa.Action)
	aa.Resource = strings.TrimSpace(aa.Resource)
	aa.Decision = strings.TrimSpace(aa.Decision)
	aa.TraceLinkID = strings.TrimSpace(aa.TraceLinkID)
	aa.SealID = strings.TrimSpace(aa.SealID)
	aa.AuthorizedAt = strings.TrimSpace(aa.AuthorizedAt)
	aa.Comment = strings.TrimSpace(aa.Comment)
	aa.Metadata = cloneStringMapPreserve(aa.Metadata)

	if aa.Approver == "" {
		return fmt.Errorf("evidence/approver_attestation: approver is required")
	}
	if aa.PassportDID == "" && aa.ApproverDID != "" {
		aa.PassportDID = aa.ApproverDID
	}
	if aa.ApproverDID == "" && aa.PassportDID != "" {
		aa.ApproverDID = aa.PassportDID
	}
	if aa.PolicyReceiptID == "" {
		return fmt.Errorf("evidence/approver_attestation: policy receipt ID is required")
	}
	if aa.PolicyReceiptHash == "" {
		return fmt.Errorf("evidence/approver_attestation: policy receipt hash is required")
	}
	if aa.AuthorizedAt == "" {
		return fmt.Errorf("evidence/approver_attestation: authorized_at is required")
	}
	if _, err := time.Parse(time.RFC3339Nano, aa.AuthorizedAt); err != nil {
		return fmt.Errorf("evidence/approver_attestation: authorized_at must be RFC3339Nano: %w", err)
	}
	if aa.Decision != "" && !strings.EqualFold(aa.Decision, policy.Allow.String()) {
		return fmt.Errorf("evidence/approver_attestation: decision %q does not represent an authorization", aa.Decision)
	}
	if aa.ID == "" {
		switch {
		case aa.ApprovalRecordID != "":
			aa.ID = "approver-attestation:" + aa.ApprovalRecordID
		case aa.TraceLinkID != "":
			aa.ID = "approver-attestation:" + aa.TraceLinkID
		default:
			aa.ID = "approver-attestation:" + aa.PolicyReceiptID
		}
	}
	return nil
}

// NewApproverAttestationEvidence converts authenticated approval identity and
// receipt data into a canonical approver attestation artifact.
func NewApproverAttestationEvidence(
	identity *agent.AgentIdentity,
	receipt *policy.SignedPolicyReceipt,
	approvalRecordID string,
	traceLinkID string,
	sealID string,
	authorizedAt time.Time,
	comment string,
	metadata map[string]string,
) (ApproverAttestationEvidence, error) {
	if identity == nil {
		return ApproverAttestationEvidence{}, fmt.Errorf("evidence/approver_attestation: nil identity")
	}
	if err := agent.VerifyIdentity(identity); err != nil {
		return ApproverAttestationEvidence{}, fmt.Errorf("evidence/approver_attestation: invalid identity: %w", err)
	}
	if receipt == nil {
		return ApproverAttestationEvidence{}, fmt.Errorf("evidence/approver_attestation: nil policy receipt")
	}
	if strings.TrimSpace(receipt.ID) == "" || strings.TrimSpace(receipt.ContentHash) == "" {
		return ApproverAttestationEvidence{}, fmt.Errorf("evidence/approver_attestation: approval policy receipt is missing required fields")
	}
	if !strings.EqualFold(receipt.Actor, identity.AgentID()) {
		return ApproverAttestationEvidence{}, fmt.Errorf("evidence/approver_attestation: receipt actor %q does not match approver DID %q", receipt.Actor, identity.AgentID())
	}
	if !strings.EqualFold(receipt.Decision, policy.Allow.String()) {
		return ApproverAttestationEvidence{}, fmt.Errorf("evidence/approver_attestation: receipt decision %q does not authorize approval", receipt.Decision)
	}
	if authorizedAt.IsZero() {
		authorizedAt = time.Now().UTC()
	}

	attestation := ApproverAttestationEvidence{
		ApprovalRecordID:  approvalRecordID,
		Approver:          identity.AgentID(),
		ApproverDID:       identity.AgentID(),
		PassportDID:       identity.AgentID(),
		PolicyReceiptID:   receipt.ID,
		PolicyReceiptHash: receipt.ContentHash,
		Action:            receipt.Action,
		Resource:          receipt.Resource,
		Decision:          receipt.Decision,
		TraceLinkID:       traceLinkID,
		SealID:            sealID,
		AuthorizedAt:      authorizedAt.UTC().Format(time.RFC3339Nano),
		Comment:           strings.TrimSpace(comment),
		Metadata:          cloneStringMapPreserve(metadata),
	}
	if err := (&attestation).Normalize(); err != nil {
		return ApproverAttestationEvidence{}, err
	}
	return attestation, nil
}
