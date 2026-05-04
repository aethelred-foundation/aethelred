// Package templates provides pre-built sector-specific policy templates for
// regulated industries. Each template returns a fully configured PolicySet
// with rules tailored to the sector's regulatory requirements.
package templates

import (
	"time"

	"github.com/aethelred/aethelred/pkg/governance/policy"
)

// FinancePolicySet returns a PolicySet with rules tailored for the financial
// services sector, including transaction limits, dual-approval thresholds,
// and sanctions screening requirements.
func FinancePolicySet() *policy.PolicySet {
	now := time.Now().UTC()
	return &policy.PolicySet{
		ID:          "finance-sector-v1",
		Name:        "Finance Sector Policy",
		Description: "Transaction limits, dual-approval thresholds, sanctions screening",
		Priority:    100,
		Enabled:     true,
		CreatedAt:   now,
		UpdatedAt:   now,
		Scope: &policy.Scope{
			Sectors: []string{"finance"},
		},
		Rules: []policy.Rule{
			// High-value transactions require dual control.
			policy.NewApprovalRule(
				"finance_high_value_dual_control",
				policy.DualControl,
				2,
				[]string{"financial_officer", "compliance_officer"},
				24*time.Hour,
				"Transactions above threshold require dual approval",
				[]policy.Condition{
					{Field: "amount", Operator: policy.GreaterThan, Value: "100000"},
				},
			),
			// Deny transactions to sanctioned entities.
			policy.NewDenyRule(
				"finance_sanctions_block",
				"Entity is on sanctions list",
				[]policy.Condition{
					{Field: "sanctions_status", Operator: policy.Equals, Value: "sanctioned"},
				},
			),
			// Wire transfers require approval.
			policy.NewApprovalRule(
				"finance_wire_transfer_approval",
				policy.Single,
				1,
				[]string{"treasury_officer"},
				8*time.Hour,
				"Wire transfers require single approval",
				[]policy.Condition{
					{Field: "transaction_type", Operator: policy.Equals, Value: "wire_transfer"},
				},
			),
			// Outside business hours require escalation for large transactions.
			policy.NewThresholdRule(
				"finance_after_hours_threshold",
				"amount",
				50000,
				policy.Escalate,
				policy.Allow,
			),
			// Allow standard transactions.
			policy.NewAllowRule(
				"finance_standard_allow",
				[]policy.Condition{
					{Field: "sanctions_status", Operator: policy.NotEquals, Value: "sanctioned"},
					{Field: "amount", Operator: policy.LessThan, Value: "100000"},
				},
			),
		},
	}
}

// HealthcarePolicySet returns a PolicySet with rules tailored for the healthcare
// sector, including consent requirements, data access controls, and HIPAA compliance.
func HealthcarePolicySet() *policy.PolicySet {
	now := time.Now().UTC()
	return &policy.PolicySet{
		ID:          "healthcare-sector-v1",
		Name:        "Healthcare Sector Policy",
		Description: "Consent requirements, PHI access controls, HIPAA compliance",
		Priority:    100,
		Enabled:     true,
		CreatedAt:   now,
		UpdatedAt:   now,
		Scope: &policy.Scope{
			Sectors: []string{"healthcare"},
		},
		Rules: []policy.Rule{
			// PHI access requires consent verification.
			policy.NewApprovalRule(
				"healthcare_phi_consent",
				policy.Single,
				1,
				[]string{"data_protection_officer", "treating_physician"},
				12*time.Hour,
				"PHI access requires consent verification",
				[]policy.Condition{
					{Field: "data_type", Operator: policy.In, Value: "phi,patient_record,medical_image"},
				},
			),
			// Deny access to records without minimum necessary justification.
			policy.NewDenyRule(
				"healthcare_minimum_necessary",
				"Access denied: minimum necessary justification not provided",
				[]policy.Condition{
					{Field: "data_type", Operator: policy.In, Value: "phi,patient_record"},
					{Field: "justification", Operator: policy.Equals, Value: ""},
				},
			),
			// Bulk data exports require committee approval.
			policy.NewApprovalRule(
				"healthcare_bulk_export",
				policy.Committee,
				3,
				[]string{"privacy_officer", "chief_medical_officer", "compliance_officer"},
				72*time.Hour,
				"Bulk PHI export requires committee approval",
				[]policy.Condition{
					{Field: "operation", Operator: policy.Equals, Value: "bulk_export"},
					{Field: "data_type", Operator: policy.In, Value: "phi,patient_record"},
				},
			),
			// Allow de-identified data access.
			policy.NewAllowRule(
				"healthcare_deidentified_allow",
				[]policy.Condition{
					{Field: "data_type", Operator: policy.Equals, Value: "de_identified"},
				},
			),
		},
	}
}

// DefensePolicySet returns a PolicySet with rules tailored for the defense
// sector, including classification enforcement, need-to-know, and air-gap requirements.
func DefensePolicySet() *policy.PolicySet {
	now := time.Now().UTC()
	return &policy.PolicySet{
		ID:          "defense-sector-v1",
		Name:        "Defense Sector Policy",
		Description: "Classification enforcement, need-to-know, air-gap requirements",
		Priority:    200,
		Enabled:     true,
		CreatedAt:   now,
		UpdatedAt:   now,
		Scope: &policy.Scope{
			Sectors: []string{"defense"},
		},
		Rules: []policy.Rule{
			// Deny access without clearance.
			policy.NewDenyRule(
				"defense_clearance_required",
				"Access denied: insufficient security clearance",
				[]policy.Condition{
					{Field: "classification", Operator: policy.In, Value: "secret,top_secret"},
					{Field: "clearance_level", Operator: policy.NotIn, Value: "secret,top_secret"},
				},
			),
			// Top secret requires committee.
			policy.NewApprovalRule(
				"defense_top_secret_committee",
				policy.Committee,
				3,
				[]string{"security_officer", "commanding_officer", "intelligence_officer"},
				48*time.Hour,
				"Top secret access requires committee approval",
				[]policy.Condition{
					{Field: "classification", Operator: policy.Equals, Value: "top_secret"},
				},
			),
			// Secret requires dual control.
			policy.NewApprovalRule(
				"defense_secret_dual_control",
				policy.DualControl,
				2,
				[]string{"security_officer", "commanding_officer"},
				24*time.Hour,
				"Secret access requires dual approval",
				[]policy.Condition{
					{Field: "classification", Operator: policy.Equals, Value: "secret"},
				},
			),
			// Deny cross-domain transfers.
			policy.NewDenyRule(
				"defense_cross_domain_block",
				"Cross-domain transfer prohibited without explicit authorization",
				[]policy.Condition{
					{Field: "operation", Operator: policy.Equals, Value: "cross_domain_transfer"},
					{Field: "air_gap_exempt", Operator: policy.NotEquals, Value: "true"},
				},
			),
			// Allow unclassified access.
			policy.NewAllowRule(
				"defense_unclassified_allow",
				[]policy.Condition{
					{Field: "classification", Operator: policy.Equals, Value: "unclassified"},
				},
			),
		},
	}
}

// AutonomousMobilityPolicySet returns a PolicySet with rules tailored for
// autonomous vehicle and mobility systems, including safety overrides, ODD
// enforcement, and incident response.
func AutonomousMobilityPolicySet() *policy.PolicySet {
	now := time.Now().UTC()
	return &policy.PolicySet{
		ID:          "autonomous-mobility-sector-v1",
		Name:        "Autonomous Mobility Policy",
		Description: "Safety overrides, ODD enforcement, incident response",
		Priority:    200,
		Enabled:     true,
		CreatedAt:   now,
		UpdatedAt:   now,
		Scope: &policy.Scope{
			Sectors: []string{"autonomous_mobility"},
		},
		Rules: []policy.Rule{
			// Deny operation outside ODD (Operational Design Domain).
			policy.NewDenyRule(
				"av_outside_odd",
				"Operation outside Operational Design Domain is prohibited",
				[]policy.Condition{
					{Field: "odd_compliant", Operator: policy.Equals, Value: "false"},
				},
			),
			// Safety-critical changes require dual control.
			policy.NewApprovalRule(
				"av_safety_critical",
				policy.DualControl,
				2,
				[]string{"safety_engineer", "systems_engineer"},
				4*time.Hour,
				"Safety-critical changes require dual approval",
				[]policy.Condition{
					{Field: "change_type", Operator: policy.Equals, Value: "safety_critical"},
				},
			),
			// High-risk conditions require committee.
			policy.NewConditionRule(
				"av_high_risk_conditions",
				[]policy.Condition{
					{Field: "risk_score", Operator: policy.GreaterThan, Value: "8"},
				},
				policy.RequireCommittee,
				policy.Allow,
			),
			// Allow normal operations.
			policy.NewAllowRule(
				"av_normal_operations",
				[]policy.Condition{
					{Field: "odd_compliant", Operator: policy.Equals, Value: "true"},
					{Field: "risk_score", Operator: policy.LessThanOrEqual, Value: "8"},
				},
			),
		},
	}
}

// AgentToAgentPolicySet returns a PolicySet with rules for agent-to-agent
// interactions, including delegation limits, trust verification, and action authorization.
func AgentToAgentPolicySet() *policy.PolicySet {
	now := time.Now().UTC()
	return &policy.PolicySet{
		ID:          "agent-to-agent-v1",
		Name:        "Agent-to-Agent Policy",
		Description: "Delegation limits, trust verification, action authorization",
		Priority:    150,
		Enabled:     true,
		CreatedAt:   now,
		UpdatedAt:   now,
		Scope: &policy.Scope{
			Sectors: []string{"agent_operations"},
		},
		Rules: []policy.Rule{
			// Deny unverified agent interactions.
			policy.NewDenyRule(
				"a2a_unverified_deny",
				"Agent identity not verified",
				[]policy.Condition{
					{Field: "agent_verified", Operator: policy.Equals, Value: "false"},
				},
			),
			// High-value delegations require approval.
			policy.NewApprovalRule(
				"a2a_high_value_delegation",
				policy.DualControl,
				2,
				[]string{"platform_admin", "security_officer"},
				8*time.Hour,
				"High-value agent delegations require dual approval",
				[]policy.Condition{
					{Field: "delegation_value", Operator: policy.GreaterThan, Value: "10000"},
				},
			),
			// Deny deep delegation chains.
			policy.NewDenyRule(
				"a2a_deep_delegation_deny",
				"Delegation chain too deep",
				[]policy.Condition{
					{Field: "delegation_depth", Operator: policy.GreaterThan, Value: "5"},
				},
			),
			// Allow verified agent operations.
			policy.NewAllowRule(
				"a2a_verified_allow",
				[]policy.Condition{
					{Field: "agent_verified", Operator: policy.Equals, Value: "true"},
					{Field: "delegation_depth", Operator: policy.LessThanOrEqual, Value: "5"},
				},
			),
		},
	}
}
