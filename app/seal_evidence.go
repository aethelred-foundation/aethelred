package app

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"

	abci "github.com/cometbft/cometbft/abci/types"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	sdk "github.com/cosmos/cosmos-sdk/types"

	pouwkeeper "github.com/aethelred/aethelred/x/pouw/keeper"
)

type committedValidator struct {
	power     int64
	committed bool
}

// validateSelfContainedSealEvidence authenticates every agreeing validator
// directly from evidence carried by the seal transaction. Consensus safety
// therefore does not depend on a process-local vote-extension cache surviving
// restarts, snapshot restore, or competing rounds.
func (app *AethelredApp) validateSelfContainedSealEvidence(
	ctx sdk.Context,
	txBytes []byte,
	commit abci.CommitInfo,
	expectedVoteBlockHash []byte,
) error {
	if app.StakingKeeper == nil && app.consensusValidatorResolver == nil {
		return fmt.Errorf("staking keeper is not configured")
	}
	if len(expectedVoteBlockHash) != 32 {
		return fmt.Errorf(
			"expected finalized block hash has invalid length: got %d, expected 32",
			len(expectedVoteBlockHash),
		)
	}
	validationMode := app.voteExtensionValidationMode(ctx)
	maxPastSkew, maxFutureSkew := app.voteExtensionTimeBounds(ctx)
	verificationTime, hasVerificationTime := app.lastBlockTime(ctx)
	if !hasVerificationTime {
		if validationMode == ValidationModeStrict {
			return fmt.Errorf("last committed block time is unavailable")
		}
		verificationTime = ctx.BlockTime()
	}

	var sealTx pouwkeeper.SealCreationTx
	if err := json.Unmarshal(txBytes, &sealTx); err != nil {
		return fmt.Errorf("decode self-contained seal evidence: %w", err)
	}

	commitByAddress := make(map[string]committedValidator, len(commit.Votes))
	totalPower := int64(0)
	for i, vote := range commit.Votes {
		if len(vote.Validator.Address) == 0 {
			return fmt.Errorf("commit validator %d has an empty address", i)
		}
		if vote.Validator.Power < 0 {
			return fmt.Errorf("commit validator %d has negative power", i)
		}
		if totalPower > math.MaxInt64-vote.Validator.Power {
			return fmt.Errorf("commit voting power overflows int64")
		}
		key := hex.EncodeToString(vote.Validator.Address)
		if _, duplicate := commitByAddress[key]; duplicate {
			return fmt.Errorf("duplicate validator in decided commit: %s", key)
		}
		commitByAddress[key] = committedValidator{
			power:     vote.Validator.Power,
			committed: vote.BlockIdFlag == cmtproto.BlockIDFlagCommit,
		}
		totalPower += vote.Validator.Power
	}

	if sealTx.TotalVotes != len(commit.Votes) {
		return fmt.Errorf(
			"seal total votes mismatch: got %d, expected %d",
			sealTx.TotalVotes,
			len(commit.Votes),
		)
	}
	if sealTx.TotalPower != totalPower {
		return fmt.Errorf(
			"seal total power mismatch: got %d, expected %d",
			sealTx.TotalPower,
			totalPower,
		)
	}
	if sealTx.ValidatorCount != len(sealTx.ValidatorResults) {
		return fmt.Errorf("seal validator count does not match embedded results")
	}

	seenValidators := make(map[string]struct{}, len(sealTx.ValidatorResults))
	agreementPower := int64(0)
	var previousConsensusAddress []byte
	var voteBlockHash []byte
	for i := range sealTx.ValidatorResults {
		result := &sealTx.ValidatorResults[i]
		if i > 0 && bytes.Compare(previousConsensusAddress, result.ValidatorConsensusAddress) >= 0 {
			return fmt.Errorf("validator results are not in canonical consensus-address order")
		}
		previousConsensusAddress = append(
			previousConsensusAddress[:0],
			result.ValidatorConsensusAddress...,
		)
		if result.ValidatorSignatureVersion != ComputeVerificationSignatureVersion {
			return fmt.Errorf(
				"validator result %d has unsupported signature version %d",
				i,
				result.ValidatorSignatureVersion,
			)
		}
		if len(result.VoteBlockHash) != 32 {
			return fmt.Errorf("validator result %d has invalid vote block hash length", i)
		}
		if !bytes.Equal(result.VoteBlockHash, expectedVoteBlockHash) {
			return fmt.Errorf(
				"validator result %d does not attest the finalized block",
				i,
			)
		}
		if i == 0 {
			voteBlockHash = append([]byte(nil), result.VoteBlockHash...)
		} else if !bytes.Equal(voteBlockHash, result.VoteBlockHash) {
			return fmt.Errorf("validator results attest different proposal block hashes")
		}
		if len(result.ExtensionNonce) != 32 {
			return fmt.Errorf("validator result %d has invalid extension nonce length", i)
		}
		if !bytes.Equal(result.OutputHash, sealTx.OutputHash) {
			return fmt.Errorf("validator result %d output hash mismatch", i)
		}
		consensusKey := hex.EncodeToString(result.ValidatorConsensusAddress)
		commitValidator, ok := commitByAddress[consensusKey]
		if !ok {
			return fmt.Errorf("validator result %d is not in the decided commit", i)
		}
		if !commitValidator.committed {
			return fmt.Errorf("validator result %d did not commit the previous block", i)
		}
		if commitValidator.power <= 0 {
			return fmt.Errorf("validator result %d has no positive voting power", i)
		}
		if _, duplicate := seenValidators[consensusKey]; duplicate {
			return fmt.Errorf("duplicate signed validator evidence: %s", consensusKey)
		}
		seenValidators[consensusKey] = struct{}{}
		if agreementPower > math.MaxInt64-commitValidator.power {
			return fmt.Errorf("agreement voting power overflows int64")
		}
		agreementPower += commitValidator.power

		verification := computeVerificationFromValidatorResult(result, &sealTx)
		if err := verification.validate(validationMode); err != nil {
			return fmt.Errorf("validator result %d validation failed: %w", i, err)
		}
		if result.Timestamp.IsZero() {
			return fmt.Errorf("validator result %d timestamp is missing", i)
		}
		if result.Timestamp.After(verificationTime.Add(maxFutureSkew)) {
			return fmt.Errorf("validator result %d timestamp is in the future", i)
		}
		if result.Timestamp.Before(verificationTime.Add(-maxPastSkew)) {
			return fmt.Errorf("validator result %d timestamp is too old", i)
		}
		domainEnvelope := &VoteExtension{
			Height:        sealTx.BlockHeight - 1,
			ChainID:       ctx.ChainID(),
			Verifications: []ComputeVerification{verification},
		}
		if err := domainEnvelope.validateAttestationDomain(ctx.ChainID()); err != nil {
			return fmt.Errorf("validator result %d TEE domain validation failed: %w", i, err)
		}

		validator, err := app.validatorByConsensusAddress(
			ctx,
			sdk.ConsAddress(result.ValidatorConsensusAddress),
		)
		if err != nil {
			return fmt.Errorf("resolve validator result %d signer: %w", i, err)
		}
		validatorAddress, err := sdk.ValAddressFromBech32(validator.GetOperator())
		if err != nil {
			return fmt.Errorf("decode validator result %d operator address: %w", i, err)
		}
		if sdk.AccAddress(validatorAddress).String() != result.ValidatorAddress {
			return fmt.Errorf("validator result %d account address mismatch", i)
		}
		publicKey, err := validator.ConsPubKey()
		if err != nil {
			return fmt.Errorf("load validator result %d consensus public key: %w", i, err)
		}
		if len(publicKey.Bytes()) != ed25519.PublicKeySize {
			return fmt.Errorf("validator result %d does not use an ed25519 consensus key", i)
		}
		if !bytes.Equal(publicKey.Address(), result.ValidatorConsensusAddress) {
			return fmt.Errorf("validator result %d consensus public key address mismatch", i)
		}
		if !verifyComputeVerificationSignature(
			verification,
			sealTx.BlockHeight-1,
			ctx.ChainID(),
			result.ValidatorConsensusAddress,
			result.Timestamp,
			ed25519.PublicKey(publicKey.Bytes()),
		) {
			return fmt.Errorf("validator result %d compact signature is invalid", i)
		}
	}

	if sealTx.AgreementPower != agreementPower {
		return fmt.Errorf(
			"seal agreement power mismatch: got %d, authenticated %d",
			sealTx.AgreementPower,
			agreementPower,
		)
	}
	requiredPower := requiredConsensusPower(totalPower, app.getConsensusThreshold(ctx))
	if totalPower <= 0 || agreementPower < requiredPower {
		return fmt.Errorf(
			"authenticated agreement power below threshold: got %d, need %d",
			agreementPower,
			requiredPower,
		)
	}
	return nil
}

func aggregatedResultBindsToFinalizedBlock(
	result *pouwkeeper.AggregatedResult,
	expectedVoteBlockHash []byte,
) bool {
	if result == nil ||
		!result.HasConsensus ||
		len(expectedVoteBlockHash) != 32 ||
		len(result.ValidatorResults) == 0 {
		return false
	}
	for i := range result.ValidatorResults {
		if !bytes.Equal(
			result.ValidatorResults[i].VoteBlockHash,
			expectedVoteBlockHash,
		) {
			return false
		}
	}
	return true
}

func computeVerificationFromValidatorResult(
	result *pouwkeeper.ValidatorResult,
	sealTx *pouwkeeper.SealCreationTx,
) ComputeVerification {
	if result == nil || sealTx == nil {
		return ComputeVerification{}
	}
	return ComputeVerification{
		JobID:                     sealTx.JobID,
		ModelHash:                 append([]byte(nil), sealTx.ModelHash...),
		InputHash:                 append([]byte(nil), sealTx.InputHash...),
		OutputHash:                append([]byte(nil), result.OutputHash...),
		AttestationType:           AttestationType(result.AttestationType),
		TEEAttestation:            teeAttestationFromWire(result.TEEAttestation),
		ZKProof:                   zkProofFromWire(result.ZKProof),
		ExecutionTimeMs:           result.ExecutionTimeMs,
		Success:                   true,
		Nonce:                     append([]byte(nil), result.Nonce...),
		ValidatorSignatureVersion: result.ValidatorSignatureVersion,
		VoteBlockHash:             append([]byte(nil), result.VoteBlockHash...),
		ExtensionNonce:            append([]byte(nil), result.ExtensionNonce...),
		ValidatorSignature:        append([]byte(nil), result.ValidatorSignature...),
	}
}

func teeAttestationFromWire(attestation *pouwkeeper.TEEAttestationWire) *TEEAttestationData {
	if attestation == nil {
		return nil
	}
	return &TEEAttestationData{
		Platform:         attestation.Platform,
		EnclaveID:        attestation.EnclaveID,
		Measurement:      append([]byte(nil), attestation.Measurement...),
		Quote:            append([]byte(nil), attestation.Quote...),
		UserData:         append([]byte(nil), attestation.UserData...),
		CertificateChain: cloneByteSlices(attestation.CertificateChain),
		Timestamp:        attestation.Timestamp,
		Nonce:            append([]byte(nil), attestation.Nonce...),
		Signature:        append([]byte(nil), attestation.Signature...),
		BlockHeight:      attestation.BlockHeight,
		ChainID:          attestation.ChainID,
	}
}

func zkProofFromWire(proof *pouwkeeper.ZKProofWire) *ZKProofData {
	if proof == nil {
		return nil
	}
	return &ZKProofData{
		ProofSystem:      proof.ProofSystem,
		Proof:            append([]byte(nil), proof.Proof...),
		PublicInputs:     append([]byte(nil), proof.PublicInputs...),
		VerifyingKeyHash: append([]byte(nil), proof.VerifyingKeyHash...),
		CircuitHash:      append([]byte(nil), proof.CircuitHash...),
		ProofSize:        proof.ProofSize,
	}
}

func cloneByteSlices(values [][]byte) [][]byte {
	cloned := make([][]byte, len(values))
	for i := range values {
		cloned[i] = append([]byte(nil), values[i]...)
	}
	return cloned
}
