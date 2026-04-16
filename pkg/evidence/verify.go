package evidence

import (
	"fmt"
)

// ---------------------------------------------------------------------------
// Standalone Bundle Verifier
// ---------------------------------------------------------------------------
//
// StandaloneVerifier performs offline verification of evidence bundles
// without any network access. It validates cryptographic integrity,
// record hashes, chain-of-custody, and optionally cross-references
// linked bundles.
// ---------------------------------------------------------------------------

// StandaloneVerifier verifies evidence bundles offline.
type StandaloneVerifier struct {
	// TrustedPlatforms lists accepted TEE platforms.
	TrustedPlatforms []string

	// StrictMode enforces additional checks (e.g., all records must have
	// valid hashes, all attestations must match a trusted platform).
	StrictMode bool
}

// NewStandaloneVerifier creates a verifier with the given configuration.
func NewStandaloneVerifier(trustedPlatforms []string, strict bool) *StandaloneVerifier {
	if trustedPlatforms == nil {
		trustedPlatforms = []string{}
	}
	return &StandaloneVerifier{
		TrustedPlatforms: trustedPlatforms,
		StrictMode:       strict,
	}
}

// VerifyBundle performs comprehensive verification of a single evidence bundle.
func (sv *StandaloneVerifier) VerifyBundle(bundle *EvidenceBundle) error {
	if bundle == nil {
		return fmt.Errorf("evidence/verify: nil bundle")
	}

	// Structural validation.
	if err := bundle.Validate(); err != nil {
		return fmt.Errorf("evidence/verify: validation failed: %w", err)
	}

	// Verify record hashes.
	for i, r := range bundle.Records {
		expected := r.ComputeHash()
		if r.Hash != expected {
			return fmt.Errorf("evidence/verify: record %d (%s) hash mismatch: expected %s, got %s",
				i, r.ID, expected, r.Hash)
		}
	}

	// Verify chain of custody.
	if len(bundle.ChainOfCustody) > 0 {
		if err := VerifyCustodyChain(bundle.ChainOfCustody); err != nil {
			return fmt.Errorf("evidence/verify: custody chain failed: %w", err)
		}
	}

	// In strict mode, verify attestation platforms.
	if sv.StrictMode && len(sv.TrustedPlatforms) > 0 {
		for _, att := range bundle.Attestations {
			trusted := false
			for _, tp := range sv.TrustedPlatforms {
				if tp == att.Platform {
					trusted = true
					break
				}
			}
			if !trusted {
				return fmt.Errorf("evidence/verify: untrusted attestation platform: %s", att.Platform)
			}
		}
	}

	return nil
}

// VerifyControlLedger performs comprehensive offline verification of a control
// ledger, including both the ledger-specific control mappings and the
// underlying evidence bundle.
func (sv *StandaloneVerifier) VerifyControlLedger(ledger *ControlLedger) error {
	if ledger == nil {
		return fmt.Errorf("evidence/verify: nil control ledger")
	}
	if err := ledger.Validate(); err != nil {
		return fmt.Errorf("evidence/verify: control ledger validation failed: %w", err)
	}

	bundle, err := ledger.ToEvidenceBundle()
	if err != nil {
		return fmt.Errorf("evidence/verify: control ledger bundle snapshot failed: %w", err)
	}
	if err := sv.VerifyBundle(bundle); err != nil {
		return fmt.Errorf("evidence/verify: control ledger bundle verification failed: %w", err)
	}

	return nil
}

// VerifyChain verifies a sequence of linked evidence bundles. Bundles are
// considered linked if they share framework context and their custody
// chains connect via hash references.
func (sv *StandaloneVerifier) VerifyChain(bundles []*EvidenceBundle) error {
	if len(bundles) == 0 {
		return fmt.Errorf("evidence/verify: no bundles to verify")
	}

	// Verify each bundle individually.
	for i, b := range bundles {
		if err := sv.VerifyBundle(b); err != nil {
			return fmt.Errorf("evidence/verify: bundle %d failed: %w", i, err)
		}
	}

	// Verify temporal ordering.
	for i := 1; i < len(bundles); i++ {
		prev := bundles[i-1]
		curr := bundles[i]
		if curr.CreatedAt < prev.CreatedAt {
			return fmt.Errorf("evidence/verify: bundle %d created before bundle %d (temporal ordering violated)", i, i-1)
		}
	}

	// Verify custody chain continuity across bundles.
	for i := 1; i < len(bundles); i++ {
		prev := bundles[i-1]
		curr := bundles[i]

		if len(prev.ChainOfCustody) == 0 || len(curr.ChainOfCustody) == 0 {
			continue
		}

		// The first custody entry of the current bundle should reference
		// the last custody hash of the previous bundle via metadata.
		lastPrevHash := prev.ChainOfCustody[len(prev.ChainOfCustody)-1].Hash
		firstCurrPrev := curr.ChainOfCustody[0].PreviousHash

		// Cross-bundle linking is optional; only verify if the previous
		// hash is non-empty and matches.
		if firstCurrPrev != "" && firstCurrPrev != lastPrevHash {
			return fmt.Errorf("evidence/verify: custody chain break between bundle %d and %d", i-1, i)
		}
	}

	return nil
}
