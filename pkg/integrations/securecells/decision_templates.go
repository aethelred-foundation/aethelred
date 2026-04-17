package securecells

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

// SecureCellDecisionSLATemplateTier defines one relative escalation stage for a
// reusable decision-governance template.
type SecureCellDecisionSLATemplateTier struct {
	TierID     string                                 `json:"tier_id"`
	TargetRole string                                 `json:"target_role,omitempty"`
	TargetDID  string                                 `json:"target_did,omitempty"`
	Mode       SecureCellThreadDecisionDelegationMode `json:"mode,omitempty"`
	After      time.Duration                          `json:"after,omitempty"`
	Reason     string                                 `json:"reason,omitempty"`
	Metadata   map[string]string                      `json:"metadata,omitempty"`
}

// SecureCellDecisionSLATemplate defines one reusable sector-ready decision
// governance preset.
type SecureCellDecisionSLATemplate struct {
	ID                    string                               `json:"id"`
	Name                  string                               `json:"name"`
	Description           string                               `json:"description,omitempty"`
	Sector                string                               `json:"sector,omitempty"`
	SectorPolicyPack      string                               `json:"sector_policy_pack,omitempty"`
	DefaultForPack        bool                                 `json:"default_for_pack,omitempty"`
	GovernanceTemplate    string                               `json:"governance_template,omitempty"`
	ApprovalThreshold     int                                  `json:"approval_threshold,omitempty"`
	RequiredApproverRoles []string                             `json:"required_approver_roles,omitempty"`
	AllowedVoteChoices    []SecureCellThreadDecisionVoteChoice `json:"allowed_vote_choices,omitempty"`
	RejectorRoles         []string                             `json:"rejector_roles,omitempty"`
	AbstainerRoles        []string                             `json:"abstainer_roles,omitempty"`
	ReopenRoles           []string                             `json:"reopen_roles,omitempty"`
	EscalationTiers       []SecureCellDecisionSLATemplateTier  `json:"escalation_tiers,omitempty"`
	ResolutionAfter       time.Duration                        `json:"resolution_after,omitempty"`
	Metadata              map[string]string                    `json:"metadata,omitempty"`
}

// SecureCellDecisionSLATemplateFilter narrows operator queries across
// configured decision-governance packs.
type SecureCellDecisionSLATemplateFilter struct {
	Sector             string `json:"sector,omitempty"`
	SectorPolicyPack   string `json:"sector_policy_pack,omitempty"`
	GovernanceTemplate string `json:"governance_template,omitempty"`
	Limit              int    `json:"limit,omitempty"`
}

// SecureCellDecisionSLATemplateSummaryTier is the operator-facing projection
// of one reusable escalation stage.
type SecureCellDecisionSLATemplateSummaryTier struct {
	TierID     string                                 `json:"tier_id"`
	TargetRole string                                 `json:"target_role,omitempty"`
	TargetDID  string                                 `json:"target_did,omitempty"`
	Mode       SecureCellThreadDecisionDelegationMode `json:"mode,omitempty"`
	After      string                                 `json:"after,omitempty"`
	Reason     string                                 `json:"reason,omitempty"`
	Metadata   map[string]string                      `json:"metadata,omitempty"`
}

// SecureCellDecisionSLATemplateSummary is the operator-facing projection of a
// reusable Secure Cells decision-governance template.
type SecureCellDecisionSLATemplateSummary struct {
	ID                    string                                     `json:"id"`
	Name                  string                                     `json:"name"`
	Description           string                                     `json:"description,omitempty"`
	Sector                string                                     `json:"sector,omitempty"`
	SectorPolicyPack      string                                     `json:"sector_policy_pack,omitempty"`
	DefaultForPack        bool                                       `json:"default_for_pack,omitempty"`
	GovernanceTemplate    string                                     `json:"governance_template,omitempty"`
	ApprovalThreshold     int                                        `json:"approval_threshold,omitempty"`
	RequiredApproverRoles []string                                   `json:"required_approver_roles,omitempty"`
	AllowedVoteChoices    []SecureCellThreadDecisionVoteChoice       `json:"allowed_vote_choices,omitempty"`
	RejectorRoles         []string                                   `json:"rejector_roles,omitempty"`
	AbstainerRoles        []string                                   `json:"abstainer_roles,omitempty"`
	ReopenRoles           []string                                   `json:"reopen_roles,omitempty"`
	EscalationTiers       []SecureCellDecisionSLATemplateSummaryTier `json:"escalation_tiers,omitempty"`
	ResolutionAfter       string                                     `json:"resolution_after,omitempty"`
	Metadata              map[string]string                          `json:"metadata,omitempty"`
}

func defaultSecureCellDecisionSLATemplates() []SecureCellDecisionSLATemplate {
	return []SecureCellDecisionSLATemplate{
		{
			ID:                 "finance_payment_release",
			Name:               "Finance Payment Release",
			Description:        "Dual-control treasury release with manager and compliance escalation.",
			Sector:             "finance",
			SectorPolicyPack:   "finance",
			DefaultForPack:     true,
			GovernanceTemplate: "dual_control",
			ApprovalThreshold:  2,
			RequiredApproverRoles: []string{
				"treasury_reviewer",
			},
			EscalationTiers: []SecureCellDecisionSLATemplateTier{
				{
					TierID:     "manager_review",
					TargetRole: "treasury_manager",
					Mode:       SecureCellThreadDecisionDelegationModeEscalate,
					After:      30 * time.Minute,
					Reason:     "treasury manager review overdue",
				},
				{
					TierID:     "compliance_review",
					TargetRole: "compliance_officer",
					Mode:       SecureCellThreadDecisionDelegationModeEscalate,
					After:      90 * time.Minute,
					Reason:     "compliance escalation overdue",
				},
			},
			ResolutionAfter: 4 * time.Hour,
			Metadata: map[string]string{
				"sector": "finance",
				"pack":   "finance",
			},
		},
		{
			ID:                 "finance_exception_review",
			Name:               "Finance Exception Review",
			Description:        "Board-style exception review for treasury events that need risk oversight.",
			Sector:             "finance",
			SectorPolicyPack:   "finance",
			GovernanceTemplate: "board_escalation",
			ApprovalThreshold:  2,
			RequiredApproverRoles: []string{
				"risk_officer",
				"board_reviewer",
			},
			EscalationTiers: []SecureCellDecisionSLATemplateTier{
				{
					TierID:     "risk_committee",
					TargetRole: "risk_committee",
					Mode:       SecureCellThreadDecisionDelegationModeEscalate,
					After:      2 * time.Hour,
					Reason:     "risk committee escalation overdue",
				},
			},
			ResolutionAfter: 8 * time.Hour,
			Metadata: map[string]string{
				"sector": "finance",
				"pack":   "finance",
			},
		},
		{
			ID:                 "healthcare_clinical_review",
			Name:               "Healthcare Clinical Review",
			Description:        "Clinical review ladder with supervisor and privacy escalation.",
			Sector:             "healthcare",
			SectorPolicyPack:   "healthcare",
			DefaultForPack:     true,
			GovernanceTemplate: "standard_review",
			ApprovalThreshold:  2,
			RequiredApproverRoles: []string{
				"clinical_reviewer",
			},
			EscalationTiers: []SecureCellDecisionSLATemplateTier{
				{
					TierID:     "care_supervisor",
					TargetRole: "care_supervisor",
					Mode:       SecureCellThreadDecisionDelegationModeEscalate,
					After:      45 * time.Minute,
					Reason:     "care supervisor escalation overdue",
				},
				{
					TierID:     "privacy_officer",
					TargetRole: "privacy_officer",
					Mode:       SecureCellThreadDecisionDelegationModeEscalate,
					After:      3 * time.Hour,
					Reason:     "privacy escalation overdue",
				},
			},
			ResolutionAfter: 8 * time.Hour,
			Metadata: map[string]string{
				"sector": "healthcare",
				"pack":   "healthcare",
			},
		},
		{
			ID:                 "critical_incident_command",
			Name:               "Critical Incident Command",
			Description:        "Fast incident governance with safety and executive escalation.",
			Sector:             "critical_infrastructure",
			SectorPolicyPack:   "critical_infrastructure",
			DefaultForPack:     true,
			GovernanceTemplate: "board_escalation",
			ApprovalThreshold:  2,
			RequiredApproverRoles: []string{
				"incident_commander",
			},
			EscalationTiers: []SecureCellDecisionSLATemplateTier{
				{
					TierID:     "safety_officer",
					TargetRole: "safety_officer",
					Mode:       SecureCellThreadDecisionDelegationModeEscalate,
					After:      15 * time.Minute,
					Reason:     "safety escalation overdue",
				},
				{
					TierID:     "executive_sponsor",
					TargetRole: "executive_sponsor",
					Mode:       SecureCellThreadDecisionDelegationModeEscalate,
					After:      60 * time.Minute,
					Reason:     "executive escalation overdue",
				},
			},
			ResolutionAfter: 2 * time.Hour,
			Metadata: map[string]string{
				"sector": "critical_infrastructure",
				"pack":   "critical_infrastructure",
			},
		},
	}
}

func normalizeSecureCellDecisionSLATemplates(extra []SecureCellDecisionSLATemplate) ([]SecureCellDecisionSLATemplate, error) {
	templates := defaultSecureCellDecisionSLATemplates()
	index := make(map[string]int, len(templates))
	for idx, template := range templates {
		index[template.ID] = idx
	}
	for _, candidate := range extra {
		normalized, err := normalizeSecureCellDecisionSLATemplate(candidate)
		if err != nil {
			return nil, err
		}
		if idx, ok := index[normalized.ID]; ok {
			templates[idx] = normalized
			continue
		}
		index[normalized.ID] = len(templates)
		templates = append(templates, normalized)
	}
	normalized := make([]SecureCellDecisionSLATemplate, 0, len(templates))
	packDefaults := make(map[string]struct{}, len(templates))
	for _, template := range templates {
		item, err := normalizeSecureCellDecisionSLATemplate(template)
		if err != nil {
			return nil, err
		}
		pack := strings.TrimSpace(item.SectorPolicyPack)
		if item.DefaultForPack && pack != "" {
			if _, ok := packDefaults[pack]; ok {
				return nil, fmt.Errorf("securecells/service: duplicate default SLA template for sector policy pack %q", pack)
			}
			packDefaults[pack] = struct{}{}
		}
		normalized = append(normalized, item)
	}
	sort.SliceStable(normalized, func(i, j int) bool {
		if normalized[i].SectorPolicyPack == normalized[j].SectorPolicyPack {
			if normalized[i].DefaultForPack != normalized[j].DefaultForPack {
				return normalized[i].DefaultForPack
			}
			return normalized[i].ID < normalized[j].ID
		}
		return normalized[i].SectorPolicyPack < normalized[j].SectorPolicyPack
	})
	return normalized, nil
}

func normalizeSecureCellDecisionSLATemplate(template SecureCellDecisionSLATemplate) (SecureCellDecisionSLATemplate, error) {
	template.ID = strings.TrimSpace(strings.ToLower(template.ID))
	if template.ID == "" {
		return SecureCellDecisionSLATemplate{}, fmt.Errorf("securecells/service: decision SLA template id is required")
	}
	template.Name = strings.TrimSpace(template.Name)
	if template.Name == "" {
		return SecureCellDecisionSLATemplate{}, fmt.Errorf("securecells/service: decision SLA template %q name is required", template.ID)
	}
	template.Description = strings.TrimSpace(template.Description)
	template.Sector = strings.TrimSpace(strings.ToLower(template.Sector))
	template.SectorPolicyPack = strings.TrimSpace(strings.ToLower(template.SectorPolicyPack))
	template.GovernanceTemplate = strings.TrimSpace(strings.ToLower(template.GovernanceTemplate))
	switch template.GovernanceTemplate {
	case "", "standard_review", "dual_control", "board_escalation":
	default:
		return SecureCellDecisionSLATemplate{}, fmt.Errorf("securecells/service: decision SLA template %q governance template %q is unsupported", template.ID, template.GovernanceTemplate)
	}
	template.RequiredApproverRoles = uniqueSecureCellDecisionRoles(template.RequiredApproverRoles)
	template.AllowedVoteChoices = normalizeSecureCellDecisionVoteChoices(template.AllowedVoteChoices)
	template.RejectorRoles = uniqueSecureCellDecisionRoles(template.RejectorRoles)
	template.AbstainerRoles = uniqueSecureCellDecisionRoles(template.AbstainerRoles)
	template.ReopenRoles = uniqueSecureCellDecisionRoles(template.ReopenRoles)
	template.Metadata = cloneStringMap(template.Metadata)
	escalationTiers, err := normalizeSecureCellDecisionSLATemplateTiers(template.ID, template.EscalationTiers)
	if err != nil {
		return SecureCellDecisionSLATemplate{}, err
	}
	template.EscalationTiers = escalationTiers
	if template.ResolutionAfter < 0 {
		return SecureCellDecisionSLATemplate{}, fmt.Errorf("securecells/service: decision SLA template %q resolution_after must be positive", template.ID)
	}
	return template, nil
}

func normalizeSecureCellDecisionSLATemplateTiers(templateID string, tiers []SecureCellDecisionSLATemplateTier) ([]SecureCellDecisionSLATemplateTier, error) {
	normalized := make([]SecureCellDecisionSLATemplateTier, 0, len(tiers))
	seen := make(map[string]struct{}, len(tiers))
	for idx, tier := range tiers {
		tierID := strings.TrimSpace(tier.TierID)
		if tierID == "" {
			tierID = fmt.Sprintf("tier_%d", idx+1)
		}
		if _, ok := seen[tierID]; ok {
			return nil, fmt.Errorf("securecells/service: decision SLA template %q has duplicate escalation tier %q", templateID, tierID)
		}
		seen[tierID] = struct{}{}
		tier.TargetRole = strings.TrimSpace(strings.ToLower(tier.TargetRole))
		tier.TargetDID = strings.TrimSpace(tier.TargetDID)
		if tier.TargetRole == "" && tier.TargetDID == "" {
			return nil, fmt.Errorf("securecells/service: decision SLA template %q escalation tier %q requires target_role or target_did", templateID, tierID)
		}
		if tier.After <= 0 {
			return nil, fmt.Errorf("securecells/service: decision SLA template %q escalation tier %q after must be positive", templateID, tierID)
		}
		mode := tier.Mode
		if mode == "" {
			mode = SecureCellThreadDecisionDelegationModeEscalate
		}
		if mode != SecureCellThreadDecisionDelegationModeEscalate && mode != SecureCellThreadDecisionDelegationModeDelegate {
			return nil, fmt.Errorf("securecells/service: decision SLA template %q escalation tier %q mode %q is unsupported", templateID, tierID, mode)
		}
		normalized = append(normalized, SecureCellDecisionSLATemplateTier{
			TierID:     tierID,
			TargetRole: tier.TargetRole,
			TargetDID:  tier.TargetDID,
			Mode:       mode,
			After:      tier.After,
			Reason:     strings.TrimSpace(tier.Reason),
			Metadata:   cloneStringMap(tier.Metadata),
		})
	}
	sort.SliceStable(normalized, func(i, j int) bool {
		if normalized[i].After == normalized[j].After {
			return normalized[i].TierID < normalized[j].TierID
		}
		return normalized[i].After < normalized[j].After
	})
	return normalized, nil
}

func (s *Service) resolveDecisionSLATemplate(templateID, policyPack string) (SecureCellDecisionSLATemplate, bool, error) {
	if s == nil {
		return SecureCellDecisionSLATemplate{}, false, nil
	}
	templateID = strings.TrimSpace(strings.ToLower(templateID))
	policyPack = strings.TrimSpace(strings.ToLower(policyPack))
	if templateID == "" && policyPack == "" {
		return SecureCellDecisionSLATemplate{}, false, nil
	}
	var matched *SecureCellDecisionSLATemplate
	for idx := range s.decisionSLATemplates {
		template := s.decisionSLATemplates[idx]
		if templateID != "" && template.ID == templateID {
			if policyPack != "" && template.SectorPolicyPack != policyPack {
				return SecureCellDecisionSLATemplate{}, false, fmt.Errorf("securecells/service: SLA template %q does not belong to sector policy pack %q", templateID, policyPack)
			}
			return cloneSecureCellDecisionSLATemplate(template), true, nil
		}
		if policyPack != "" && template.SectorPolicyPack == policyPack {
			if matched == nil || (!matched.DefaultForPack && template.DefaultForPack) {
				candidate := cloneSecureCellDecisionSLATemplate(template)
				matched = &candidate
			}
		}
	}
	if matched != nil {
		return *matched, true, nil
	}
	if templateID != "" {
		return SecureCellDecisionSLATemplate{}, false, fmt.Errorf("securecells/service: unsupported decision SLA template %q", templateID)
	}
	return SecureCellDecisionSLATemplate{}, false, fmt.Errorf("securecells/service: unsupported sector policy pack %q", policyPack)
}

func (s *Service) applyDecisionSLATemplate(run *secureCellRun, thread SecureCellSessionThread, proposedAt time.Time, decision SecureCellThreadDecisionRequest) (SecureCellThreadDecisionRequest, SecureCellDecisionSLATemplate, bool, error) {
	template, ok, err := s.resolveDecisionSLATemplate(decision.SLATemplate, decision.SectorPolicyPack)
	if err != nil || !ok {
		return decision, template, ok, err
	}
	if current := strings.TrimSpace(strings.ToLower(decision.GovernanceTemplate)); current != "" && current != template.GovernanceTemplate {
		return decision, SecureCellDecisionSLATemplate{}, false, fmt.Errorf("securecells/service: decision governance template %q conflicts with SLA template %q governance %q", current, template.ID, template.GovernanceTemplate)
	}
	decision.GovernanceTemplate = firstNonEmpty(decision.GovernanceTemplate, template.GovernanceTemplate)
	decision.SLATemplate = template.ID
	decision.SectorPolicyPack = template.SectorPolicyPack
	if decision.ApprovalThreshold <= 0 && template.ApprovalThreshold > 0 {
		decision.ApprovalThreshold = template.ApprovalThreshold
	}
	if len(decision.RequiredApproverRoles) == 0 && len(template.RequiredApproverRoles) > 0 {
		decision.RequiredApproverRoles = append([]string(nil), template.RequiredApproverRoles...)
	}
	if len(decision.AllowedVoteChoices) == 0 && len(template.AllowedVoteChoices) > 0 {
		decision.AllowedVoteChoices = append([]SecureCellThreadDecisionVoteChoice(nil), template.AllowedVoteChoices...)
	}
	if len(decision.RejectorRoles) == 0 && len(template.RejectorRoles) > 0 {
		decision.RejectorRoles = append([]string(nil), template.RejectorRoles...)
	}
	if len(decision.AbstainerRoles) == 0 && len(template.AbstainerRoles) > 0 {
		decision.AbstainerRoles = append([]string(nil), template.AbstainerRoles...)
	}
	if len(decision.ReopenRoles) == 0 && len(template.ReopenRoles) > 0 {
		decision.ReopenRoles = append([]string(nil), template.ReopenRoles...)
	}
	if len(decision.EscalationLadder) == 0 && strings.TrimSpace(decision.AutoEscalateToDID) == "" && (decision.EscalationDueAt == nil || decision.EscalationDueAt.IsZero()) && len(template.EscalationTiers) > 0 {
		ladder := make([]SecureCellDecisionEscalationTier, 0, len(template.EscalationTiers))
		for _, tier := range template.EscalationTiers {
			targetDID, resolveErr := secureCellDecisionResolveSLATierTarget(run, thread, tier.TargetRole, tier.TargetDID)
			if resolveErr != nil {
				return decision, SecureCellDecisionSLATemplate{}, false, resolveErr
			}
			dueAt := proposedAt.Add(tier.After).UTC()
			metadata := cloneStringMap(tier.Metadata)
			if metadata == nil {
				metadata = map[string]string{}
			}
			if tier.TargetRole != "" {
				metadata["target_role"] = tier.TargetRole
			}
			metadata["sla_template"] = template.ID
			metadata["sector_policy_pack"] = template.SectorPolicyPack
			ladder = append(ladder, SecureCellDecisionEscalationTier{
				TierID:    tier.TierID,
				TargetDID: targetDID,
				Mode:      tier.Mode,
				DueAt:     &dueAt,
				Reason:    tier.Reason,
				Metadata:  metadata,
			})
		}
		decision.EscalationLadder = ladder
	}
	if (decision.ResolutionDueAt == nil || decision.ResolutionDueAt.IsZero()) && template.ResolutionAfter > 0 {
		resolutionDueAt := proposedAt.Add(template.ResolutionAfter).UTC()
		decision.ResolutionDueAt = &resolutionDueAt
	}
	return decision, template, true, nil
}

func secureCellDecisionResolveSLATierTarget(run *secureCellRun, thread SecureCellSessionThread, targetRole string, targetDID string) (string, error) {
	targetDID = strings.TrimSpace(targetDID)
	if targetDID != "" {
		if !secureCellDecisionParticipantAllowed(run, targetDID) {
			return "", fmt.Errorf("securecells/service: SLA escalation target %q is not active in the secure cell", targetDID)
		}
		return targetDID, nil
	}
	targetRole = strings.TrimSpace(strings.ToLower(targetRole))
	if targetRole == "" {
		return "", fmt.Errorf("securecells/service: SLA escalation tier target is required")
	}
	if targetRole == "owner" && run != nil && run.request.OwnerIdentity != nil {
		return run.request.OwnerIdentity.AgentID(), nil
	}
	for _, participantDID := range thread.ParticipantDIDs {
		if strings.EqualFold(secureCellActorRole(run, participantDID), targetRole) {
			return participantDID, nil
		}
	}
	if run != nil && run.result != nil {
		for _, participant := range run.result.Participants {
			if participant.Status != SecureCellParticipantStatusActive {
				continue
			}
			if strings.EqualFold(strings.TrimSpace(participant.Role), targetRole) {
				return strings.TrimSpace(participant.ParticipantDID), nil
			}
		}
	}
	return "", fmt.Errorf("securecells/service: no active participant with role %q is available for SLA escalation", targetRole)
}

func (s *Service) ListDecisionSLATemplates(_ context.Context, filter SecureCellDecisionSLATemplateFilter) ([]SecureCellDecisionSLATemplateSummary, error) {
	if s == nil {
		return nil, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	sector := strings.TrimSpace(strings.ToLower(filter.Sector))
	pack := strings.TrimSpace(strings.ToLower(filter.SectorPolicyPack))
	governance := strings.TrimSpace(strings.ToLower(filter.GovernanceTemplate))
	items := make([]SecureCellDecisionSLATemplateSummary, 0, len(s.decisionSLATemplates))
	for _, template := range s.decisionSLATemplates {
		if sector != "" && template.Sector != sector {
			continue
		}
		if pack != "" && template.SectorPolicyPack != pack {
			continue
		}
		if governance != "" && template.GovernanceTemplate != governance {
			continue
		}
		items = append(items, secureCellDecisionSLATemplateSummary(template))
	}
	if filter.Limit > 0 && len(items) > filter.Limit {
		items = items[:filter.Limit]
	}
	return items, nil
}

func secureCellDecisionSLATemplateSummary(template SecureCellDecisionSLATemplate) SecureCellDecisionSLATemplateSummary {
	summary := SecureCellDecisionSLATemplateSummary{
		ID:                    template.ID,
		Name:                  template.Name,
		Description:           template.Description,
		Sector:                template.Sector,
		SectorPolicyPack:      template.SectorPolicyPack,
		DefaultForPack:        template.DefaultForPack,
		GovernanceTemplate:    template.GovernanceTemplate,
		ApprovalThreshold:     template.ApprovalThreshold,
		RequiredApproverRoles: append([]string(nil), template.RequiredApproverRoles...),
		AllowedVoteChoices:    append([]SecureCellThreadDecisionVoteChoice(nil), template.AllowedVoteChoices...),
		RejectorRoles:         append([]string(nil), template.RejectorRoles...),
		AbstainerRoles:        append([]string(nil), template.AbstainerRoles...),
		ReopenRoles:           append([]string(nil), template.ReopenRoles...),
		ResolutionAfter:       template.ResolutionAfter.String(),
		Metadata:              cloneStringMap(template.Metadata),
	}
	if len(template.EscalationTiers) > 0 {
		summary.EscalationTiers = make([]SecureCellDecisionSLATemplateSummaryTier, 0, len(template.EscalationTiers))
		for _, tier := range template.EscalationTiers {
			summary.EscalationTiers = append(summary.EscalationTiers, SecureCellDecisionSLATemplateSummaryTier{
				TierID:     tier.TierID,
				TargetRole: tier.TargetRole,
				TargetDID:  tier.TargetDID,
				Mode:       tier.Mode,
				After:      tier.After.String(),
				Reason:     tier.Reason,
				Metadata:   cloneStringMap(tier.Metadata),
			})
		}
	}
	return summary
}

func cloneSecureCellDecisionSLATemplate(template SecureCellDecisionSLATemplate) SecureCellDecisionSLATemplate {
	out := template
	out.RequiredApproverRoles = append([]string(nil), template.RequiredApproverRoles...)
	out.AllowedVoteChoices = append([]SecureCellThreadDecisionVoteChoice(nil), template.AllowedVoteChoices...)
	out.RejectorRoles = append([]string(nil), template.RejectorRoles...)
	out.AbstainerRoles = append([]string(nil), template.AbstainerRoles...)
	out.ReopenRoles = append([]string(nil), template.ReopenRoles...)
	out.Metadata = cloneStringMap(template.Metadata)
	if len(template.EscalationTiers) > 0 {
		out.EscalationTiers = make([]SecureCellDecisionSLATemplateTier, 0, len(template.EscalationTiers))
		for _, tier := range template.EscalationTiers {
			out.EscalationTiers = append(out.EscalationTiers, SecureCellDecisionSLATemplateTier{
				TierID:     tier.TierID,
				TargetRole: tier.TargetRole,
				TargetDID:  tier.TargetDID,
				Mode:       tier.Mode,
				After:      tier.After,
				Reason:     tier.Reason,
				Metadata:   cloneStringMap(tier.Metadata),
			})
		}
	}
	return out
}
