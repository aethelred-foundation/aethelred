package app

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/aethelred/aethelred/pkg/governance/policy"
	securecellsintegration "github.com/aethelred/aethelred/pkg/integrations/securecells"
)

type secureCellFederationIncidentDirectiveCreateRequest struct {
	ActorIdentity       json.RawMessage                                                      `json:"actor_identity,omitempty"`
	PolicyReceipt       *policy.SignedPolicyReceipt                                          `json:"policy_receipt,omitempty"`
	DirectiveType       string                                                               `json:"directive_type,omitempty"`
	Title               string                                                               `json:"title,omitempty"`
	Summary             string                                                               `json:"summary,omitempty"`
	Description         string                                                               `json:"description,omitempty"`
	Priority            securecellsintegration.SecureCellFederationIncidentDirectivePriority `json:"priority,omitempty"`
	AssigneeParty       securecellsintegration.SecureCellFederationIncidentResponseParty     `json:"assignee_party,omitempty"`
	ReviewerParty       securecellsintegration.SecureCellFederationIncidentResponseParty     `json:"reviewer_party,omitempty"`
	AssigneeDID         string                                                               `json:"assignee_did,omitempty"`
	ReviewerDID         string                                                               `json:"reviewer_did,omitempty"`
	RelatedReportIDs    []string                                                             `json:"related_report_ids,omitempty"`
	RelatedAmendmentIDs []string                                                             `json:"related_amendment_ids,omitempty"`
	EvidenceIDs         []string                                                             `json:"evidence_ids,omitempty"`
	DueAt               *time.Time                                                           `json:"due_at,omitempty"`
	Reason              string                                                               `json:"reason,omitempty"`
	Metadata            map[string]string                                                    `json:"metadata,omitempty"`
}

type secureCellFederationIncidentDirectiveAcknowledgeRequest struct {
	ActorIdentity      json.RawMessage                                                  `json:"actor_identity,omitempty"`
	PolicyReceipt      *policy.SignedPolicyReceipt                                      `json:"policy_receipt,omitempty"`
	AcknowledgingParty securecellsintegration.SecureCellFederationIncidentResponseParty `json:"acknowledging_party,omitempty"`
	Reason             string                                                           `json:"reason,omitempty"`
	Metadata           map[string]string                                                `json:"metadata,omitempty"`
}

type secureCellFederationIncidentDirectiveCompleteRequest struct {
	ActorIdentity         json.RawMessage                                                  `json:"actor_identity,omitempty"`
	PolicyReceipt         *policy.SignedPolicyReceipt                                      `json:"policy_receipt,omitempty"`
	CompletingParty       securecellsintegration.SecureCellFederationIncidentResponseParty `json:"completing_party,omitempty"`
	CompletionSummary     string                                                           `json:"completion_summary,omitempty"`
	CompletionDescription string                                                           `json:"completion_description,omitempty"`
	EvidenceIDs           []string                                                         `json:"evidence_ids,omitempty"`
	Reason                string                                                           `json:"reason,omitempty"`
	Metadata              map[string]string                                                `json:"metadata,omitempty"`
}

type secureCellFederationIncidentDirectiveVerifyRequest struct {
	ActorIdentity           json.RawMessage                                                                  `json:"actor_identity,omitempty"`
	PolicyReceipt           *policy.SignedPolicyReceipt                                                      `json:"policy_receipt,omitempty"`
	ReviewingParty          securecellsintegration.SecureCellFederationIncidentResponseParty                 `json:"reviewing_party,omitempty"`
	Decision                securecellsintegration.SecureCellFederationIncidentDirectiveVerificationDecision `json:"decision,omitempty"`
	VerificationSummary     string                                                                           `json:"verification_summary,omitempty"`
	VerificationDescription string                                                                           `json:"verification_description,omitempty"`
	EvidenceIDs             []string                                                                         `json:"evidence_ids,omitempty"`
	Reason                  string                                                                           `json:"reason,omitempty"`
	Metadata                map[string]string                                                                `json:"metadata,omitempty"`
}

type secureCellFederationIncidentDirectiveListResponse struct {
	Items []securecellsintegration.SecureCellFederationIncidentDirectiveSummary `json:"items"`
}

type secureCellOverdueFederationIncidentDirectiveListResponse struct {
	Items []securecellsintegration.SecureCellOverdueFederationIncidentDirective `json:"items"`
}

type secureCellFederationIncidentDirectiveActionListResponse struct {
	Items []securecellsintegration.SecureCellFederationIncidentDirectiveActionRecord `json:"items"`
}

type secureCellFederationIncidentDirectiveAutomationActionListResponse struct {
	Items []securecellsintegration.SecureCellFederationIncidentDirectiveAutomationActionRecord `json:"items"`
}

type secureCellFederationIncidentDirectiveQueryResponse struct {
	Result *securecellsintegration.SecureCellFederationIncidentDirective `json:"result,omitempty"`
}

func parseSecureCellFederationIncidentDirectiveFilter(r *http.Request) (securecellsintegration.SecureCellFederationIncidentDirectiveFilter, error) {
	filter := securecellsintegration.SecureCellFederationIncidentDirectiveFilter{
		CellID:         strings.TrimSpace(r.URL.Query().Get("cell_id")),
		OrganizationID: strings.TrimSpace(r.URL.Query().Get("organization_id")),
		IncidentID:     strings.TrimSpace(r.URL.Query().Get("incident_id")),
		ResponseID:     strings.TrimSpace(r.URL.Query().Get("response_id")),
		DirectiveID:    strings.TrimSpace(r.URL.Query().Get("directive_id")),
		AssigneeParty:  securecellsintegration.SecureCellFederationIncidentResponseParty(strings.TrimSpace(r.URL.Query().Get("assignee_party"))),
		ReviewerParty:  securecellsintegration.SecureCellFederationIncidentResponseParty(strings.TrimSpace(r.URL.Query().Get("reviewer_party"))),
		Status:         securecellsintegration.SecureCellFederationIncidentDirectiveStatus(strings.TrimSpace(r.URL.Query().Get("status"))),
		Priority:       securecellsintegration.SecureCellFederationIncidentDirectivePriority(strings.TrimSpace(r.URL.Query().Get("priority"))),
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		limit, err := strconv.Atoi(raw)
		if err != nil {
			return filter, err
		}
		filter.Limit = limit
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("since")); raw != "" {
		since, err := time.Parse(time.RFC3339Nano, raw)
		if err != nil {
			return filter, err
		}
		filter.Since = &since
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("until")); raw != "" {
		until, err := time.Parse(time.RFC3339Nano, raw)
		if err != nil {
			return filter, err
		}
		filter.Until = &until
	}
	return filter, nil
}

func parseSecureCellOverdueFederationIncidentDirectiveFilter(r *http.Request) (securecellsintegration.SecureCellOverdueFederationIncidentDirectiveFilter, error) {
	filter := securecellsintegration.SecureCellOverdueFederationIncidentDirectiveFilter{
		CellID:         strings.TrimSpace(r.URL.Query().Get("cell_id")),
		OrganizationID: strings.TrimSpace(r.URL.Query().Get("organization_id")),
		IncidentID:     strings.TrimSpace(r.URL.Query().Get("incident_id")),
		ResponseID:     strings.TrimSpace(r.URL.Query().Get("response_id")),
		DirectiveID:    strings.TrimSpace(r.URL.Query().Get("directive_id")),
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		limit, err := strconv.Atoi(raw)
		if err != nil {
			return filter, err
		}
		filter.Limit = limit
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("before")); raw != "" {
		before, err := time.Parse(time.RFC3339Nano, raw)
		if err != nil {
			return filter, err
		}
		filter.Before = &before
	}
	return filter, nil
}

func parseSecureCellFederationIncidentDirectiveActionFilter(r *http.Request) (securecellsintegration.SecureCellFederationIncidentDirectiveActionFilter, error) {
	filter := securecellsintegration.SecureCellFederationIncidentDirectiveActionFilter{
		CellID:         strings.TrimSpace(r.URL.Query().Get("cell_id")),
		OrganizationID: strings.TrimSpace(r.URL.Query().Get("organization_id")),
		IncidentID:     strings.TrimSpace(r.URL.Query().Get("incident_id")),
		ResponseID:     strings.TrimSpace(r.URL.Query().Get("response_id")),
		DirectiveID:    strings.TrimSpace(r.URL.Query().Get("directive_id")),
		Action:         strings.TrimSpace(r.URL.Query().Get("action")),
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		limit, err := strconv.Atoi(raw)
		if err != nil {
			return filter, err
		}
		filter.Limit = limit
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("since")); raw != "" {
		since, err := time.Parse(time.RFC3339Nano, raw)
		if err != nil {
			return filter, err
		}
		filter.Since = &since
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("until")); raw != "" {
		until, err := time.Parse(time.RFC3339Nano, raw)
		if err != nil {
			return filter, err
		}
		filter.Until = &until
	}
	return filter, nil
}

func parseSecureCellFederationIncidentDirectiveAutomationActionFilter(r *http.Request) (securecellsintegration.SecureCellFederationIncidentDirectiveAutomationActionFilter, error) {
	filter := securecellsintegration.SecureCellFederationIncidentDirectiveAutomationActionFilter{
		CellID:         strings.TrimSpace(r.URL.Query().Get("cell_id")),
		OrganizationID: strings.TrimSpace(r.URL.Query().Get("organization_id")),
		IncidentID:     strings.TrimSpace(r.URL.Query().Get("incident_id")),
		ResponseID:     strings.TrimSpace(r.URL.Query().Get("response_id")),
		DirectiveID:    strings.TrimSpace(r.URL.Query().Get("directive_id")),
		ContractID:     strings.TrimSpace(r.URL.Query().Get("contract_id")),
		Action:         strings.TrimSpace(r.URL.Query().Get("action")),
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		limit, err := strconv.Atoi(raw)
		if err != nil {
			return filter, err
		}
		filter.Limit = limit
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("since")); raw != "" {
		since, err := time.Parse(time.RFC3339Nano, raw)
		if err != nil {
			return filter, err
		}
		filter.Since = &since
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("until")); raw != "" {
		until, err := time.Parse(time.RFC3339Nano, raw)
		if err != nil {
			return filter, err
		}
		filter.Until = &until
	}
	return filter, nil
}

func parseSecureCellFederationIncidentDirectiveActionPath(path, suffix string) (string, string, error) {
	path = strings.TrimSpace(path)
	suffix = strings.TrimSpace(suffix)
	trimmed := strings.TrimPrefix(path, secureCellsItemPrefix)
	if suffix != "" {
		if !strings.HasSuffix(trimmed, suffix) {
			return "", "", http.ErrNotSupported
		}
		trimmed = strings.TrimSuffix(trimmed, suffix)
	}
	parts := strings.Split(strings.Trim(trimmed, "/"), "/")
	if len(parts) != 4 || parts[1] != "federation" || parts[2] != "incident-directives" {
		return "", "", http.ErrNotSupported
	}
	return parts[0], parts[3], nil
}
