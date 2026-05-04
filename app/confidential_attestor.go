package app

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"

	servertypes "github.com/cosmos/cosmos-sdk/server/types"
	"github.com/spf13/cast"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/aethelred/aethelred/pkg/confidential"
	sealsdk "github.com/aethelred/aethelred/pkg/seal/sdk"
	sealtypes "github.com/aethelred/aethelred/x/seal/types"
)

type workflowTEEAttestor struct {
	app              *AethelredApp
	workflow         string
	validatorAddress string
	signingKey       *ecdsa.PrivateKey
}

func (a *workflowTEEAttestor) Attest(ctx context.Context, req confidential.AttestationRequest) ([]*sealtypes.TEEAttestation, error) {
	if a == nil || a.app == nil {
		return nil, fmt.Errorf("confidential attestor is unavailable")
	}
	if a.app.teeClient == nil {
		return nil, fmt.Errorf("TEE client is not configured")
	}
	if a.signingKey == nil {
		return nil, fmt.Errorf("TEE attestation signing key is not configured")
	}

	bindingHash := req.BindingHash()
	modelSeed := sha256.Sum256([]byte(firstNonEmpty(a.workflow, req.Workflow) + ":" + strings.TrimSpace(req.Stage) + ":confidential-execution"))
	inputSeed := sha256.Sum256([]byte(bindingHash))

	teeResult, err := a.app.teeClient.Execute(ctx, &TEEExecutionRequest{
		JobID:      strings.TrimSpace(req.JobID) + ":" + strings.TrimSpace(req.Stage) + ":confidential-execution",
		ModelHash:  modelSeed[:],
		InputHash:  inputSeed[:],
		Timeout:    30 * time.Second,
		Metadata:   cloneStringMap(req.Metadata),
		InputData:  nil,
		InputURI:   "",
		ModelURI:   "",
		RequireZKProof: false,
	})
	if err != nil {
		return nil, fmt.Errorf("confidential execution failed: %w", err)
	}
	if teeResult == nil || !teeResult.Success {
		if teeResult != nil && strings.TrimSpace(teeResult.ErrorMessage) != "" {
			return nil, fmt.Errorf("confidential execution failed: %s", teeResult.ErrorMessage)
		}
		return nil, fmt.Errorf("confidential execution did not return a successful result")
	}
	if teeResult.Attestation == nil {
		return nil, fmt.Errorf("confidential execution did not return an attestation")
	}

	validatorAddress := firstNonEmpty(strings.TrimSpace(a.validatorAddress), strings.TrimSpace(req.Workflow))
	measurement := append([]byte(nil), teeResult.Attestation.Measurement...)
	platformQuote := append([]byte(nil), teeResult.Attestation.Quote...)
	teeAttestation := &sealtypes.TEEAttestation{
		ValidatorAddress: validatorAddress,
		Platform:         strings.TrimSpace(teeResult.Attestation.Platform),
		EnclaveId:        firstNonEmpty(strings.TrimSpace(teeResult.Attestation.EnclaveID), "unknown-enclave"),
		Measurement:      measurement,
		Timestamp:        timestamppb.New(teeResult.Attestation.Timestamp.UTC()),
	}
	envelope := confidential.BuildQuoteEnvelope(req, teeAttestation, platformQuote, teeResult.Attestation.UserData, teeResult.Attestation.Nonce, teeResult.Attestation.Timestamp.UTC())
	quote, err := confidential.EncodeQuoteEnvelope(envelope)
	if err != nil {
		return nil, err
	}
	teeAttestation.Quote = quote

	sig, err := signTEEAttestation(a.signingKey, teeAttestation)
	if err != nil {
		return nil, fmt.Errorf("sign confidential execution attestation: %w", err)
	}
	teeAttestation.Signature = sig
	return []*sealtypes.TEEAttestation{teeAttestation}, nil
}

func signTEEAttestation(privateKey *ecdsa.PrivateKey, att *sealtypes.TEEAttestation) ([]byte, error) {
	if privateKey == nil {
		return nil, fmt.Errorf("private key is required")
	}
	if att == nil {
		return nil, fmt.Errorf("attestation is required")
	}
	h := sha256.New()
	h.Write([]byte(att.GetValidatorAddress()))
	h.Write([]byte(att.GetPlatform()))
	h.Write([]byte(att.GetEnclaveId()))
	h.Write(att.GetMeasurement())
	h.Write(att.GetQuote())
	digest := h.Sum(nil)

	sig, err := ecdsa.SignASN1(rand.Reader, privateKey, digest)
	if err != nil {
		return nil, err
	}
	return sig, nil
}

func newWorkflowTEEAttestor(app *AethelredApp, workflow string, validatorAddress string, signingKey *ecdsa.PrivateKey) confidential.Attestor {
	if app == nil || signingKey == nil {
		return nil
	}
	return &workflowTEEAttestor{
		app:              app,
		workflow:         strings.TrimSpace(workflow),
		validatorAddress: strings.TrimSpace(validatorAddress),
		signingKey:       signingKey,
	}
}

func resolveConfidentialExecutionPolicy(appOpts servertypes.AppOptions, primaryPrefix string, fallbackPrefix string, defaultRequired bool, trustedKeys map[string]*ecdsa.PublicKey) confidential.Policy {
	policy := confidential.Policy{
		Required:             defaultRequired,
		TrustedPlatforms:     sealsdk.DefaultTrustedPlatforms(),
		MaxAttestationAge:    24 * time.Hour,
		RequireQuoteBinding:  true,
		TrustedValidatorKeys: trustedKeys,
	}

	if raw := appOptionString(appOpts, primaryPrefix+".confidential_execution.required", fallbackPrefix+".confidential_execution.required"); raw != "" {
		policy.Required = cast.ToBool(raw)
	}
	if raw := appOptionString(appOpts, primaryPrefix+".confidential_execution.minimum_valid_attestations", fallbackPrefix+".confidential_execution.minimum_valid_attestations"); raw != "" {
		policy.MinimumValidAttestations = cast.ToInt(raw)
	}
	if raw := appOptionString(appOpts, primaryPrefix+".confidential_execution.trusted_platforms", fallbackPrefix+".confidential_execution.trusted_platforms"); raw != "" {
		if values := parseAppCSVValues(raw); len(values) > 0 {
			policy.TrustedPlatforms = values
		}
	}
	if raw := appOptionString(appOpts, primaryPrefix+".confidential_execution.max_attestation_age_seconds", fallbackPrefix+".confidential_execution.max_attestation_age_seconds"); raw != "" {
		if seconds := cast.ToDuration(raw); seconds > 0 {
			policy.MaxAttestationAge = seconds
		} else if cast.ToInt64(raw) > 0 {
			policy.MaxAttestationAge = time.Duration(cast.ToInt64(raw)) * time.Second
		}
	}
	if raw := appOptionString(appOpts, primaryPrefix+".confidential_execution.allowed_enclave_ids", fallbackPrefix+".confidential_execution.allowed_enclave_ids"); raw != "" {
		policy.AllowedEnclaveIDs = parseAppCSVValues(raw)
	}
	if raw := appOptionString(appOpts, primaryPrefix+".confidential_execution.allowed_measurements", fallbackPrefix+".confidential_execution.allowed_measurements"); raw != "" {
		policy.AllowedMeasurements = normalizeMeasurementAllowlist(parseAppCSVValues(raw))
	}
	if raw := appOptionString(appOpts, primaryPrefix+".confidential_execution.require_quote_binding", fallbackPrefix+".confidential_execution.require_quote_binding"); raw != "" {
		policy.RequireQuoteBinding = cast.ToBool(raw)
	}
	return policy
}

func appOptionString(appOpts servertypes.AppOptions, primary string, fallback string) string {
	value := firstNonEmpty(cast.ToString(appOpts.Get(primary)), cast.ToString(appOpts.Get(fallback)))
	if strings.TrimSpace(value) != "" {
		return strings.TrimSpace(value)
	}
	envKey := strings.ToUpper(strings.NewReplacer(".", "_", "-", "_").Replace(primary))
	return strings.TrimSpace(os.Getenv(envKey))
}

func parseAppCSVValues(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	values := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			values = append(values, trimmed)
		}
	}
	return values
}

func normalizeMeasurementAllowlist(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(strings.ToLower(value))
		if value == "" {
			continue
		}
		if decoded, err := hex.DecodeString(value); err == nil {
			out = append(out, hex.EncodeToString(decoded))
			continue
		}
		out = append(out, value)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
