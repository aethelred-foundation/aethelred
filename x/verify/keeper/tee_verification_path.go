package keeper

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"time"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/aethelred/aethelred/x/verify/types"
)

const maxTEEAttestationFutureSkew = 2 * time.Minute

var simulatedTEEQuoteMagic = []byte("AETSIMQ1")

const (
	simulatedTEEQuoteVersion   = byte(1)
	simulatedTEEQuoteMACSize   = sha256.Size
	simulatedTEEQuoteHeaderLen = 8 + 1 + 4 + simulatedTEEQuoteMACSize
	simulatedTEEKeyMinLen      = 32
)

// VerifyTEEAttestation verifies a TEE attestation.
func (k Keeper) VerifyTEEAttestation(ctx context.Context, attestation *types.TEEAttestation) (*types.VerificationResult, error) {
	sdkCtx := sdk.UnwrapSDKContext(ctx)
	startTime := time.Now()

	result := &types.VerificationResult{
		VerificationType: types.VerificationTypeTEE,
		Timestamp:        timestamppb.Now(),
	}

	// Validate attestation structure.
	if attestation == nil {
		result.Success = false
		result.ErrorMessage = "attestation cannot be nil"
		return result, nil
	}
	if err := attestation.Validate(); err != nil {
		result.Success = false
		result.ErrorMessage = fmt.Sprintf("invalid attestation: %v", err)
		return result, nil
	}

	// Get TEE config for this platform.
	config, err := k.TEEConfigs.Get(ctx, attestation.Platform.String())
	if err != nil {
		result.Success = false
		result.ErrorMessage = fmt.Sprintf("unknown TEE platform: %s", attestation.Platform.String())
		return result, nil
	}

	params, _ := k.GetParams(ctx)
	if params == nil {
		params = types.DefaultParams()
	}

	if !config.IsActive {
		result.Success = false
		result.ErrorMessage = fmt.Sprintf("TEE platform %s is not active", attestation.Platform.String())
		return result, nil
	}

	// SECURITY: production configurations must explicitly bound attestation age.
	if config.MaxQuoteAge == nil && !params.AllowSimulated {
		result.Success = false
		result.ErrorMessage = "SECURITY: max quote age must be configured in production"
		return result, nil
	}

	// Check quote age.
	if attestation.Timestamp == nil {
		result.Success = false
		result.ErrorMessage = "attestation timestamp missing"
		return result, nil
	}
	if config.MaxQuoteAge != nil {
		blockTime := sdkCtx.BlockTime()
		if blockTime.IsZero() {
			if params.AllowSimulated {
				sdkCtx.Logger().Warn("Block time not set; skipping attestation freshness check in simulated mode")
			} else {
				result.Success = false
				result.ErrorMessage = "missing block time for deterministic attestation freshness check"
				return result, nil
			}
		} else {
			attestationTime := attestation.Timestamp.AsTime()
			if attestationTime.After(blockTime.Add(maxTEEAttestationFutureSkew)) {
				result.Success = false
				result.ErrorMessage = "attestation timestamp is too far in the future"
				return result, nil
			}
			if blockTime.Sub(attestationTime) > config.MaxQuoteAge.AsDuration() {
				result.Success = false
				result.ErrorMessage = "attestation quote is too old"
				return result, nil
			}
		}
	}

	// Verify the measurement is trusted.
	measurementTrusted := false
	for _, trusted := range config.TrustedMeasurements {
		if bytes.Equal(trusted, attestation.Measurement) {
			measurementTrusted = true
			break
		}
	}

	// SECURITY FIX: In production, we MUST have trusted measurements configured.
	if len(config.TrustedMeasurements) == 0 {
		if params.AllowSimulated {
			sdkCtx.Logger().Warn("SECURITY WARNING: No trusted measurements configured - allowing any measurement (dev mode only)",
				"platform", attestation.Platform.String(),
				"measurement", fmt.Sprintf("%x", attestation.Measurement),
			)
			measurementTrusted = true
		} else {
			result.Success = false
			result.ErrorMessage = "SECURITY: no trusted measurements configured for this TEE platform"
			return result, nil
		}
	}

	if !measurementTrusted {
		result.Success = false
		result.ErrorMessage = fmt.Sprintf("enclave measurement %x not in trusted list", attestation.Measurement)
		return result, nil
	}

	// SECURITY: require an anti-replay nonce for AWS Nitro attestations in production.
	if attestation.Platform == types.TEEPlatformAWSNitro && !params.AllowSimulated && len(attestation.Nonce) == 0 {
		result.Success = false
		result.ErrorMessage = "SECURITY: AWS Nitro attestation nonce is required in production"
		return result, nil
	}

	// Verify the attestation quote.
	verified, err := k.verifyAttestationInternal(ctx, attestation, &config, params.AllowSimulated)
	if err != nil {
		result.Success = false
		result.ErrorMessage = fmt.Sprintf("attestation verification failed: %v", err)
		return result, nil
	}
	if verified {
		if err := k.checkAndRecordTEEReplay(ctx, attestation, &config, params); err != nil {
			result.Success = false
			result.ErrorMessage = fmt.Sprintf("attestation replay check failed: %v", err)
			return result, nil
		}
	}

	result.Success = verified
	result.TeeAttestationVerified = verified
	result.VerificationTimeMs = time.Since(startTime).Milliseconds()

	// Emit event.
	sdkCtx.EventManager().EmitEvent(
		sdk.NewEvent(
			"tee_attestation_verified",
			sdk.NewAttribute("platform", attestation.Platform.String()),
			sdk.NewAttribute("success", fmt.Sprintf("%t", verified)),
			sdk.NewAttribute("verification_time_ms", fmt.Sprintf("%d", result.VerificationTimeMs)),
		),
	)

	return result, nil
}

// verifyAttestationInternal performs the actual TEE attestation verification.
// SECURITY: This function MUST NOT return true without cryptographic verification
// in production mode (AllowSimulated=false).
func (k Keeper) verifyAttestationInternal(ctx context.Context, attestation *types.TEEAttestation, config *types.TEEConfig, allowSimulated bool) (bool, error) {
	sdkCtx := sdk.UnwrapSDKContext(ctx)

	// SECURITY: Remote verification is the primary path for production.
	if config.AttestationEndpoint != "" {
		sdkCtx.Logger().Info("Calling remote TEE attestation verifier",
			"endpoint", config.AttestationEndpoint,
			"platform", attestation.Platform.String(),
		)
		return k.callRemoteAttestationVerifier(ctx, config.AttestationEndpoint, attestation)
	}

	// SECURITY: In production mode, verification MUST NOT pass without a configured verifier.
	if !allowSimulated {
		sdkCtx.Logger().Error("TEE attestation verification failed: no verifier endpoint configured",
			"platform", attestation.Platform.String(),
			"allow_simulated", allowSimulated,
		)
		return false, fmt.Errorf("SECURITY: attestation endpoint not configured and simulation disabled - cannot verify attestation")
	}

	// WARNING: Simulated verification (DEVELOPMENT/TESTING ONLY).
	sdkCtx.Logger().Warn("SIMULATED TEE ATTESTATION - NOT FOR PRODUCTION",
		"platform", attestation.Platform.String(),
		"quote_size", len(attestation.Quote),
	)

	// Even in simulation mode, perform structural validation.
	if len(attestation.Quote) == 0 {
		return false, fmt.Errorf("attestation quote cannot be empty")
	}
	if len(attestation.Measurement) == 0 {
		return false, fmt.Errorf("attestation measurement cannot be empty")
	}

	return verifyAuthenticatedSimulatedAttestation(attestation, config.RootCertificate)
}

func verifyPlatformQuoteBody(platform types.TEEPlatform, quote []byte) (bool, error) {
	switch platform {
	case types.TEEPlatformAWSNitro:
		return verifyAWSNitroQuoteBody(quote)
	case types.TEEPlatformIntelSGX:
		return verifyIntelSGXQuoteBody(quote)
	case types.TEEPlatformIntelTDX:
		return verifyIntelTDXQuoteBody(quote)
	case types.TEEPlatformAMDSEV:
		return verifyAMDSEVQuoteBody(quote)
	default:
		return false, fmt.Errorf("unsupported TEE platform: %s", platform.String())
	}
}

func verifyAWSNitroAttestation(attestation *types.TEEAttestation) (bool, error) {
	return verifyAWSNitroQuoteBody(attestation.Quote)
}

func verifyIntelSGXAttestation(attestation *types.TEEAttestation) (bool, error) {
	return verifyIntelSGXQuoteBody(attestation.Quote)
}

func verifyIntelTDXAttestation(attestation *types.TEEAttestation) (bool, error) {
	return verifyIntelTDXQuoteBody(attestation.Quote)
}

func verifyAMDSEVAttestation(attestation *types.TEEAttestation) (bool, error) {
	return verifyAMDSEVQuoteBody(attestation.Quote)
}

func verifyAWSNitroQuoteBody(quote []byte) (bool, error) {
	if len(quote) < 1000 {
		return false, fmt.Errorf("AWS Nitro attestation document too small: %d bytes", len(quote))
	}
	allZero := true
	for _, b := range quote {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return false, fmt.Errorf("AWS Nitro attestation document cannot be all zeros")
	}
	return true, nil
}

func verifyIntelSGXQuoteBody(quote []byte) (bool, error) {
	if len(quote) < 432 {
		return false, fmt.Errorf("Intel SGX quote too small: %d bytes (minimum 432)", len(quote))
	}
	return true, nil
}

func verifyIntelTDXQuoteBody(quote []byte) (bool, error) {
	if len(quote) < 584 {
		return false, fmt.Errorf("Intel TDX quote too small: %d bytes (minimum 584)", len(quote))
	}
	return true, nil
}

func verifyAMDSEVQuoteBody(quote []byte) (bool, error) {
	// SEV-SNP report blobs are expected to be >= 672 bytes in our adapter.
	if len(quote) < 672 {
		return false, fmt.Errorf("AMD SEV attestation report too small: %d bytes (minimum 672)", len(quote))
	}
	return true, nil
}

func verifyAuthenticatedSimulatedAttestation(attestation *types.TEEAttestation, simulationVerifierKey []byte) (bool, error) {
	rawQuoteBody, err := parseAndVerifySimulatedAttestationQuote(attestation, simulationVerifierKey)
	if err != nil {
		return false, err
	}
	return verifyPlatformQuoteBody(attestation.Platform, rawQuoteBody)
}

func parseAndVerifySimulatedAttestationQuote(attestation *types.TEEAttestation, simulationVerifierKey []byte) ([]byte, error) {
	if len(simulationVerifierKey) < simulatedTEEKeyMinLen {
		return nil, fmt.Errorf("simulation attestation verifier key must be at least %d bytes", simulatedTEEKeyMinLen)
	}
	if len(attestation.Quote) < simulatedTEEQuoteHeaderLen {
		return nil, fmt.Errorf("simulated attestation quote too small: %d bytes", len(attestation.Quote))
	}
	if !bytes.Equal(attestation.Quote[:len(simulatedTEEQuoteMagic)], simulatedTEEQuoteMagic) {
		return nil, fmt.Errorf("simulated attestation quote missing authenticated envelope")
	}
	if attestation.Quote[len(simulatedTEEQuoteMagic)] != simulatedTEEQuoteVersion {
		return nil, fmt.Errorf("unsupported simulated attestation quote version: %d", attestation.Quote[len(simulatedTEEQuoteMagic)])
	}

	offset := len(simulatedTEEQuoteMagic) + 1
	rawQuoteLen := binary.BigEndian.Uint32(attestation.Quote[offset : offset+4])
	offset += 4

	expectedLen := offset + simulatedTEEQuoteMACSize + int(rawQuoteLen)
	if len(attestation.Quote) != expectedLen {
		return nil, fmt.Errorf("simulated attestation quote length mismatch: got %d want %d", len(attestation.Quote), expectedLen)
	}

	macBytes := attestation.Quote[offset : offset+simulatedTEEQuoteMACSize]
	offset += simulatedTEEQuoteMACSize
	rawQuoteBody := attestation.Quote[offset:]

	expectedMAC := computeSimulatedAttestationMAC(attestation, rawQuoteBody, simulationVerifierKey)
	if !hmac.Equal(macBytes, expectedMAC) {
		return nil, fmt.Errorf("simulated attestation authentication failed")
	}

	return rawQuoteBody, nil
}

func buildSimulatedAttestationQuote(attestation *types.TEEAttestation, simulationVerifierKey, rawQuoteBody []byte) ([]byte, error) {
	if len(simulationVerifierKey) < simulatedTEEKeyMinLen {
		return nil, fmt.Errorf("simulation attestation verifier key must be at least %d bytes", simulatedTEEKeyMinLen)
	}
	if len(rawQuoteBody) == 0 {
		return nil, fmt.Errorf("simulated attestation quote body cannot be empty")
	}
	if int64(len(rawQuoteBody)) > int64(^uint32(0)) {
		return nil, fmt.Errorf("simulated attestation quote body exceeds uint32 wire limit")
	}

	macBytes := computeSimulatedAttestationMAC(attestation, rawQuoteBody, simulationVerifierKey)
	quote := make([]byte, 0, simulatedTEEQuoteHeaderLen+len(rawQuoteBody))
	quote = append(quote, simulatedTEEQuoteMagic...)
	quote = append(quote, simulatedTEEQuoteVersion)

	var lenBuf [4]byte
	// #nosec G115 -- rawQuoteBody is explicitly bounded to uint32 above.
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(rawQuoteBody)))
	quote = append(quote, lenBuf[:]...)
	quote = append(quote, macBytes...)
	quote = append(quote, rawQuoteBody...)

	return quote, nil
}

func computeSimulatedAttestationMAC(attestation *types.TEEAttestation, rawQuoteBody, simulationVerifierKey []byte) []byte {
	mac := hmac.New(sha256.New, simulationVerifierKey)
	mac.Write(canonicalSimulatedAttestationInput(attestation, rawQuoteBody))
	return mac.Sum(nil)
}

func canonicalSimulatedAttestationInput(attestation *types.TEEAttestation, rawQuoteBody []byte) []byte {
	var out []byte
	// #nosec G115 -- Platform is a validated non-negative protobuf enum.
	out = appendUvarintField(out, uint64(attestation.Platform))
	out = appendLengthPrefixedField(out, []byte(attestation.EnclaveId))
	out = appendLengthPrefixedField(out, attestation.Measurement)
	out = appendLengthPrefixedField(out, attestation.UserData)
	if attestation.Timestamp != nil {
		out = appendUvarintField(out, uint64(attestation.Timestamp.AsTime().UTC().UnixNano()))
	} else {
		out = appendUvarintField(out, 0)
	}
	out = appendUvarintField(out, uint64(len(attestation.CertificateChain)))
	for _, cert := range attestation.CertificateChain {
		out = appendLengthPrefixedField(out, cert)
	}
	out = appendLengthPrefixedField(out, attestation.Nonce)
	out = appendLengthPrefixedField(out, rawQuoteBody)
	return out
}

func appendLengthPrefixedField(dst, field []byte) []byte {
	var lenBuf [4]byte
	// #nosec G115 -- attestation fields are bounded by the module request/quote limits.
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(field)))
	dst = append(dst, lenBuf[:]...)
	dst = append(dst, field...)
	return dst
}

func appendUvarintField(dst []byte, value uint64) []byte {
	var buf [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(buf[:], value)
	return append(dst, buf[:n]...)
}
