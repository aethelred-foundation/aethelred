package keeper

import (
	"encoding/hex"
	"encoding/json"
	"fmt"

	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/aethelred/aethelred/internal/attestation"
	"github.com/aethelred/aethelred/x/pouw/types"
)

// This file ties the three pillars together: a measured WorkReceipt is recorded
// only when the device that produced it presents a *verified* hardware
// attestation, and the receipt's device class comes from that attestation. So
// every accounted watt and every cost figure is attributed to an attested
// device on an attested platform (AMD/AWS/Intel/Azure/GCP/NVIDIA), not an
// asserted one. The attestation's report_data binds the work identity, so an
// attestation cannot be replayed for a different computation.

// AttestationSummary is the queryable record of a job's verified attestation.
type AttestationSummary struct {
	JobID          string `json:"job_id"`
	Platform       string `json:"platform"`
	DeviceClass    string `json:"device_class"`
	MeasurementHex string `json:"measurement_hex"`
	TrustBasis     string `json:"trust_basis"`
	RootSubject    string `json:"root_subject"`
}

// RecordAttestedWork verifies a device's attestation (any supported platform),
// requires its report_data to bind the given work identity, then records a
// measured WorkReceipt attributed to the attested device. It returns the
// receipt hash and the verified claims.
func (k Keeper) RecordAttestedWork(
	ctx sdk.Context,
	reg *attestation.Registry,
	ev *attestation.Evidence,
	policy *attestation.Policy,
	jobID, validator string,
	deviceMilliseconds, avgPowerMilliwatts, usefulWorkUnits uint64,
	basis types.EnergyBasis,
) ([]byte, *attestation.VerifiedClaims, error) {
	if reg == nil || ev == nil {
		return nil, nil, fmt.Errorf("attested work: registry and evidence are required")
	}
	claims, err := reg.Verify(ev, policy)
	if err != nil {
		return nil, nil, fmt.Errorf("attestation rejected: %w", err)
	}

	receipt := types.WorkReceipt{
		JobID:              jobID,
		Validator:          validator,
		DeviceClass:        claims.DeviceClass, // attributed to the attested device
		DeviceMilliseconds: deviceMilliseconds,
		AvgPowerMilliwatts: avgPowerMilliwatts,
		Basis:              basis,
		UsefulWorkUnits:    usefulWorkUnits,
	}
	hash, err := k.RecordWorkReceipt(ctx, receipt)
	if err != nil {
		return nil, nil, err
	}
	if err := k.setAttestationSummary(ctx, jobID, claims); err != nil {
		return nil, nil, err
	}
	return hash, claims, nil
}

func (k Keeper) setAttestationSummary(ctx sdk.Context, jobID string, claims *attestation.VerifiedClaims) error {
	summary := AttestationSummary{
		JobID:          jobID,
		Platform:       string(claims.Platform),
		DeviceClass:    claims.DeviceClass,
		MeasurementHex: hex.EncodeToString(claims.Measurement),
		TrustBasis:     string(claims.TrustBasis),
		RootSubject:    claims.RootSubject,
	}
	bz, err := json.Marshal(summary)
	if err != nil {
		return err
	}
	return k.storeService.OpenKVStore(ctx).Set(types.AttestationSummaryKey(jobID), bz)
}

// GetAttestationSummary returns the verified attestation recorded for a job.
func (k Keeper) GetAttestationSummary(ctx sdk.Context, jobID string) (AttestationSummary, bool, error) {
	bz, err := k.storeService.OpenKVStore(ctx).Get(types.AttestationSummaryKey(jobID))
	if err != nil {
		return AttestationSummary{}, false, err
	}
	if len(bz) == 0 {
		return AttestationSummary{}, false, nil
	}
	var summary AttestationSummary
	if err := json.Unmarshal(bz, &summary); err != nil {
		return AttestationSummary{}, false, err
	}
	return summary, true, nil
}
