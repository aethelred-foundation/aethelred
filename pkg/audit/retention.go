package audit

import (
	"context"
	"fmt"
	"time"

	"github.com/aethelred/aethelred/x/pouw/keeper"
)

// ---------------------------------------------------------------------------
// Retention Policy Management
// ---------------------------------------------------------------------------
//
// Retention policies govern how long audit records must be kept to satisfy
// regulatory and compliance requirements. Different jurisdictions and
// frameworks impose different minimum retention periods.
//
// Key design decisions:
//   - Policies are additive: the longest applicable retention wins
//   - Jurisdictional overrides take precedence over defaults
//   - Framework requirements provide a baseline per compliance standard
//   - Records are never physically deleted by this package; they are
//     marked as "expired" for the storage layer to handle
// ---------------------------------------------------------------------------

// RetentionDuration wraps a time.Duration with a human-readable description.
type RetentionDuration struct {
	Duration    time.Duration `json:"duration"`
	Description string        `json:"description"`
}

// RetentionPolicy defines how long audit records must be retained.
type RetentionPolicy struct {
	// DefaultRetention is the fallback retention period when no more
	// specific rule applies.
	DefaultRetention RetentionDuration `json:"default_retention"`

	// JurisdictionOverrides maps jurisdiction identifiers to their
	// required retention durations.
	JurisdictionOverrides map[string]RetentionDuration `json:"jurisdiction_overrides,omitempty"`

	// FrameworkRequirements maps compliance framework identifiers to
	// their required retention durations.
	FrameworkRequirements map[ComplianceFramework]RetentionDuration `json:"framework_requirements,omitempty"`
}

// RetentionCheckResult describes the outcome of a retention check.
type RetentionCheckResult struct {
	// RecordSequence identifies the checked record.
	RecordSequence uint64 `json:"record_sequence"`

	// Retained is true if the record must still be retained.
	Retained bool `json:"retained"`

	// ExpiresAt is the earliest time the record may be released.
	ExpiresAt time.Time `json:"expires_at"`

	// Reason describes which policy rule determined the retention.
	Reason string `json:"reason"`

	// ApplicablePolicy is the policy name or jurisdiction that applied.
	ApplicablePolicy string `json:"applicable_policy"`
}

// ---------------------------------------------------------------------------
// Pre-built policies
// ---------------------------------------------------------------------------

// PolicyGDPR returns a retention policy compliant with GDPR requirements.
// GDPR generally requires 6 years for records that may be relevant to
// enforcement actions (statute of limitations).
func PolicyGDPR() RetentionPolicy {
	return RetentionPolicy{
		DefaultRetention: RetentionDuration{
			Duration:    6 * 365 * 24 * time.Hour, // 6 years
			Description: "GDPR default: 6 years (enforcement statute of limitations)",
		},
		JurisdictionOverrides: map[string]RetentionDuration{
			"EU": {
				Duration:    6 * 365 * 24 * time.Hour,
				Description: "EU GDPR: 6 years",
			},
			"UK": {
				Duration:    6 * 365 * 24 * time.Hour,
				Description: "UK GDPR: 6 years",
			},
		},
		FrameworkRequirements: map[ComplianceFramework]RetentionDuration{
			FrameworkGDPR: {
				Duration:    6 * 365 * 24 * time.Hour,
				Description: "GDPR Article 83: up to 6 years for enforcement",
			},
		},
	}
}

// PolicyHIPAA returns a retention policy compliant with HIPAA requirements.
// HIPAA requires 6 years for security-related records.
func PolicyHIPAA() RetentionPolicy {
	return RetentionPolicy{
		DefaultRetention: RetentionDuration{
			Duration:    6 * 365 * 24 * time.Hour,
			Description: "HIPAA default: 6 years",
		},
		FrameworkRequirements: map[ComplianceFramework]RetentionDuration{
			FrameworkHIPAA: {
				Duration:    6 * 365 * 24 * time.Hour,
				Description: "HIPAA 45 CFR 164.530(j): 6 years from creation or last effective date",
			},
		},
	}
}

// PolicySOX returns a retention policy compliant with Sarbanes-Oxley
// requirements. SOX requires 7 years for audit work papers.
func PolicySOX() RetentionPolicy {
	return RetentionPolicy{
		DefaultRetention: RetentionDuration{
			Duration:    7 * 365 * 24 * time.Hour,
			Description: "SOX default: 7 years",
		},
		FrameworkRequirements: map[ComplianceFramework]RetentionDuration{
			FrameworkSOC2: {
				Duration:    7 * 365 * 24 * time.Hour,
				Description: "SOX Section 802: 7 years for audit work papers",
			},
		},
	}
}

// PolicyDefense returns a retention policy suitable for defense and
// national security contexts. Typically 10 years or indefinite.
func PolicyDefense() RetentionPolicy {
	return RetentionPolicy{
		DefaultRetention: RetentionDuration{
			Duration:    10 * 365 * 24 * time.Hour,
			Description: "Defense default: 10 years",
		},
		JurisdictionOverrides: map[string]RetentionDuration{
			"US-DOD": {
				Duration:    10 * 365 * 24 * time.Hour,
				Description: "DoD 5015.02-STD: 10 years for critical records",
			},
		},
		FrameworkRequirements: map[ComplianceFramework]RetentionDuration{
			FrameworkNIST80053: {
				Duration:    10 * 365 * 24 * time.Hour,
				Description: "NIST 800-53 AU-11: organization-defined retention (10 years for defense)",
			},
			FrameworkFedRAMP: {
				Duration:    10 * 365 * 24 * time.Hour,
				Description: "FedRAMP: 10 years for high-impact systems",
			},
		},
	}
}

// MergeRetentionPolicies combines multiple policies by taking the longest
// retention period for each category. This ensures compliance with all
// applicable requirements simultaneously.
func MergeRetentionPolicies(policies ...RetentionPolicy) RetentionPolicy {
	merged := RetentionPolicy{
		JurisdictionOverrides: make(map[string]RetentionDuration),
		FrameworkRequirements: make(map[ComplianceFramework]RetentionDuration),
	}

	for _, p := range policies {
		if p.DefaultRetention.Duration > merged.DefaultRetention.Duration {
			merged.DefaultRetention = p.DefaultRetention
		}
		for k, v := range p.JurisdictionOverrides {
			if existing, ok := merged.JurisdictionOverrides[k]; !ok || v.Duration > existing.Duration {
				merged.JurisdictionOverrides[k] = v
			}
		}
		for k, v := range p.FrameworkRequirements {
			if existing, ok := merged.FrameworkRequirements[k]; !ok || v.Duration > existing.Duration {
				merged.FrameworkRequirements[k] = v
			}
		}
	}

	return merged
}

// ---------------------------------------------------------------------------
// Retention checks
// ---------------------------------------------------------------------------

// CheckRetention evaluates whether a record must still be retained under
// the given policy. It returns a detailed result including the expiration
// time and the reason for retention.
func CheckRetention(record keeper.AuditRecord, policy RetentionPolicy) (*RetentionCheckResult, error) {
	recordTime, err := parseTimestamp(record.Timestamp)
	if err != nil {
		return nil, fmt.Errorf("audit/retention: failed to parse record timestamp: %w", err)
	}

	now := time.Now().UTC()
	result := &RetentionCheckResult{
		RecordSequence: record.Sequence,
	}

	// Find the longest applicable retention period.
	longestDuration := policy.DefaultRetention.Duration
	longestReason := policy.DefaultRetention.Description
	longestPolicy := "default"

	// Check framework requirements.
	for fw, req := range policy.FrameworkRequirements {
		if req.Duration > longestDuration {
			longestDuration = req.Duration
			longestReason = req.Description
			longestPolicy = string(fw)
		}
	}

	// Check jurisdiction overrides (these take precedence).
	for jur, req := range policy.JurisdictionOverrides {
		if req.Duration > longestDuration {
			longestDuration = req.Duration
			longestReason = req.Description
			longestPolicy = jur
		}
	}

	// Critical and security records get an additional 25% retention buffer.
	if record.Severity == keeper.AuditSeverityCritical ||
		record.Category == keeper.AuditCategorySecurity {
		longestDuration = longestDuration + longestDuration/4
		longestReason += " (+25% security/critical buffer)"
	}

	expiresAt := recordTime.Add(longestDuration)
	result.ExpiresAt = expiresAt
	result.Retained = now.Before(expiresAt)
	result.Reason = longestReason
	result.ApplicablePolicy = longestPolicy

	return result, nil
}

// ApplyRetention evaluates all records from the source against the policy
// and returns results for records that have expired (no longer need to be
// retained). Records that must still be retained are not included in the
// result.
func ApplyRetention(_ context.Context, source LogSource, policy RetentionPolicy) ([]RetentionCheckResult, error) {
	if source == nil {
		return nil, fmt.Errorf("audit/retention: LogSource is required")
	}

	records := source.GetRecords()
	var expired []RetentionCheckResult

	for _, r := range records {
		result, err := CheckRetention(r, policy)
		if err != nil {
			continue // Skip records with unparseable timestamps.
		}
		if !result.Retained {
			expired = append(expired, *result)
		}
	}

	return expired, nil
}

// RetentionSummary provides an overview of the retention state.
type RetentionSummary struct {
	TotalRecords   int    `json:"total_records"`
	RetainedCount  int    `json:"retained_count"`
	ExpiredCount   int    `json:"expired_count"`
	EarliestExpiry string `json:"earliest_expiry"`
	LatestExpiry   string `json:"latest_expiry"`
}

// SummarizeRetention returns aggregate retention statistics for all records
// in the source.
func SummarizeRetention(source LogSource, policy RetentionPolicy) (*RetentionSummary, error) {
	if source == nil {
		return nil, fmt.Errorf("audit/retention: LogSource is required")
	}

	records := source.GetRecords()
	summary := &RetentionSummary{
		TotalRecords: len(records),
	}

	var earliest, latest time.Time
	for _, r := range records {
		result, err := CheckRetention(r, policy)
		if err != nil {
			continue
		}

		if result.Retained {
			summary.RetainedCount++
		} else {
			summary.ExpiredCount++
		}

		if earliest.IsZero() || result.ExpiresAt.Before(earliest) {
			earliest = result.ExpiresAt
		}
		if result.ExpiresAt.After(latest) {
			latest = result.ExpiresAt
		}
	}

	if !earliest.IsZero() {
		summary.EarliestExpiry = earliest.Format(time.RFC3339)
	}
	if !latest.IsZero() {
		summary.LatestExpiry = latest.Format(time.RFC3339)
	}

	return summary, nil
}
