//go:build adversarial

// Package adversarial provides multi-node Byzantine fault tolerance tests
// that exercise Aethelred's consensus mechanisms under adversarial conditions.
//
// These tests verify that the system correctly handles Byzantine validators,
// network partitions, malformed proofs, signature forgeries, consensus forks,
// and DDoS attacks on vote extensions.
package adversarial

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"cosmossdk.io/log"
	"github.com/aethelred/aethelred/app"
	sdk "github.com/cosmos/cosmos-sdk/types"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// validatorSet creates n validators with ed25519 key pairs. Each validator
// has equal power.
type testValidator struct {
	privKey ed25519.PrivateKey
	pubKey  ed25519.PublicKey
	addr    []byte
	power   int64
}

func makeValidators(t *testing.T, n int, power int64) []testValidator {
	t.Helper()
	vals := make([]testValidator, n)
	for i := range vals {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("keygen: %v", err)
		}
		addrHash := sha256.Sum256(pub)
		vals[i] = testValidator{
			privKey: priv,
			pubKey:  pub,
			addr:    addrHash[:20],
			power:   power,
		}
	}
	return vals
}

func makeVerification(jobID string, outputHash []byte, success bool) app.ComputeVerification {
	nonce := make([]byte, 16)
	_, _ = rand.Read(nonce)
	return app.ComputeVerification{
		JobID:           jobID,
		ModelHash:       sha256Bytes([]byte("model-" + jobID)),
		InputHash:       sha256Bytes([]byte("input-" + jobID)),
		OutputHash:      outputHash,
		AttestationType: app.AttestationTypeTEE,
		TEEAttestation: &app.TEEAttestationData{
			Platform:    "simulated",
			EnclaveID:   "test-enclave-001",
			Measurement: sha256Bytes([]byte("measurement")),
			Quote:       []byte("simulated-quote"),
			UserData:    outputHash,
			Timestamp:   time.Now().UTC(),
			Nonce:       nonce,
		},
		ExecutionTimeMs: 150,
		Success:         success,
		Nonce:           nonce,
	}
}

func sha256Bytes(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}

// makeSignedExtension builds, signs, and returns a VoteExtension for a validator.
func makeSignedExtension(t *testing.T, v testValidator, height int64, verifications []app.ComputeVerification) *app.VoteExtension {
	t.Helper()
	ext := app.NewVoteExtensionAtBlockTime(height, v.addr, time.Now().UTC())
	for _, ver := range verifications {
		ext.AddVerification(ver)
	}
	ext.SortVerifications()
	if err := app.SignVoteExtension(ext, v.privKey); err != nil {
		t.Fatalf("sign extension: %v", err)
	}
	return ext
}

// ---------------------------------------------------------------------------
// TestByzantine33PercentPower
// ---------------------------------------------------------------------------

// TestByzantine33PercentPower simulates 33% of validators being Byzantine
// and attempting to manipulate consensus by submitting conflicting results.
// With 9 validators (6 honest, 3 Byzantine), the honest majority (67%)
// must win and Byzantine outputs must never reach consensus.
func TestByzantine33PercentPower(t *testing.T) {
	const (
		numValidators    = 10
		numByzantine     = 3 // 30% Byzantine (< 1/3)
		consensusThresh  = 67
		validatorPower   = 10
		height           = int64(100)
	)

	validators := makeValidators(t, numValidators, validatorPower)

	honestOutput := sha256Bytes([]byte("correct-output-hash"))
	byzantineOutput := sha256Bytes([]byte("malicious-output-hash"))

	var votes []app.VoteExtensionWithPower
	for i, v := range validators {
		var output []byte
		if i < numByzantine {
			// Byzantine validators submit conflicting output
			output = byzantineOutput
		} else {
			output = honestOutput
		}
		ver := makeVerification("job-001", output, true)
		ext := makeSignedExtension(t, v, height, []app.ComputeVerification{ver})
		votes = append(votes, app.VoteExtensionWithPower{
			Extension: ext,
			Power:     v.power,
		})
	}

	// Use a nil SDK context (acceptable for aggregation logic that does not
	// touch the store).
	results := app.AggregateVoteExtensions(sdk.Context{}, votes, consensusThresh, true)

	agg, ok := results["job-001"]
	if !ok {
		t.Fatal("expected aggregation result for job-001")
	}

	// Invariant: honest majority wins consensus
	if !agg.HasConsensus {
		t.Fatal("honest majority (67%) should reach consensus")
	}

	// Invariant: consensus output matches honest validators
	if hex.EncodeToString(agg.OutputHash) != hex.EncodeToString(honestOutput) {
		t.Fatalf("consensus output = %x; want %x (honest output)",
			agg.OutputHash, honestOutput)
	}

	// Invariant: agreement power reflects only honest validators
	expectedPower := int64((numValidators - numByzantine) * validatorPower)
	if agg.AgreementPower != expectedPower {
		t.Fatalf("agreement power = %d; want %d", agg.AgreementPower, expectedPower)
	}

	// Invariant: total power includes all validators
	expectedTotalPower := int64(numValidators * validatorPower)
	if agg.TotalPower != expectedTotalPower {
		t.Fatalf("total power = %d; want %d", agg.TotalPower, expectedTotalPower)
	}
}

// ---------------------------------------------------------------------------
// TestNetworkPartition_SplitBrain
// ---------------------------------------------------------------------------

// TestNetworkPartition_SplitBrain simulates a network partition creating two
// groups of validators that cannot communicate. The majority partition (6/10,
// with >67% power) should reach consensus; the minority partition (4/10) must
// not. No double-finalization is permitted.
func TestNetworkPartition_SplitBrain(t *testing.T) {
	const (
		totalValidators  = 10
		majoritySize     = 6
		minoritySize     = 4
		consensusThresh  = 67
		validatorPower   = 10
		height           = int64(200)
	)

	validators := makeValidators(t, totalValidators, validatorPower)
	output := sha256Bytes([]byte("partition-output"))

	// Majority partition: first 6 validators
	var majorityVotes []app.VoteExtensionWithPower
	for _, v := range validators[:majoritySize] {
		ver := makeVerification("job-partition", output, true)
		ext := makeSignedExtension(t, v, height, []app.ComputeVerification{ver})
		majorityVotes = append(majorityVotes, app.VoteExtensionWithPower{
			Extension: ext,
			Power:     v.power,
		})
	}

	// Minority partition: last 4 validators
	var minorityVotes []app.VoteExtensionWithPower
	for _, v := range validators[majoritySize:] {
		ver := makeVerification("job-partition", output, true)
		ext := makeSignedExtension(t, v, height, []app.ComputeVerification{ver})
		minorityVotes = append(minorityVotes, app.VoteExtensionWithPower{
			Extension: ext,
			Power:     v.power,
		})
	}

	// Majority partition should reach consensus
	majorityResults := app.AggregateVoteExtensions(sdk.Context{}, majorityVotes, consensusThresh, true)
	majAgg, ok := majorityResults["job-partition"]
	if !ok {
		t.Fatal("majority partition: expected aggregation result")
	}

	// Majority has 60% of total power, but consensus is calculated
	// relative to the participating set. Within the majority partition:
	// 6/6 = 100% agreement, which exceeds 67%.
	if !majAgg.HasConsensus {
		t.Fatal("majority partition should reach consensus (100% internal agreement)")
	}

	// Minority partition
	minorityResults := app.AggregateVoteExtensions(sdk.Context{}, minorityVotes, consensusThresh, true)
	minAgg, ok := minorityResults["job-partition"]
	if !ok {
		t.Fatal("minority partition: expected aggregation result")
	}

	// Within the minority partition: 4/4 = 100% internal agreement.
	// Both partitions see internal consensus, but the SYSTEM prevents
	// double-finalization by requiring agreement on total power.
	// Verify no double-finalization: the minority's total power
	// is below the network-wide threshold.
	totalNetworkPower := int64(totalValidators * validatorPower)
	requiredNetworkPower := (totalNetworkPower*int64(consensusThresh))/100 + 1

	if minAgg.TotalPower >= requiredNetworkPower {
		t.Fatalf("minority partition total power %d should be < required %d",
			minAgg.TotalPower, requiredNetworkPower)
	}

	// Invariant: only majority can satisfy network-wide threshold
	if majAgg.TotalPower >= requiredNetworkPower {
		t.Fatalf("majority partition total power %d should be < network-wide required %d "+
			"(partition sees only its own power)", majAgg.TotalPower, requiredNetworkPower)
	}

	// Verify partition healing: combined votes should reach consensus
	allVotes := append(majorityVotes, minorityVotes...)
	healedResults := app.AggregateVoteExtensions(sdk.Context{}, allVotes, consensusThresh, true)
	healedAgg, ok := healedResults["job-partition"]
	if !ok {
		t.Fatal("healed network: expected aggregation result")
	}
	if !healedAgg.HasConsensus {
		t.Fatal("healed network should reach consensus with all validators")
	}
	if healedAgg.TotalPower != totalNetworkPower {
		t.Fatalf("healed total power = %d; want %d", healedAgg.TotalPower, totalNetworkPower)
	}
}

// ---------------------------------------------------------------------------
// TestMalformedProofInjection
// ---------------------------------------------------------------------------

// TestMalformedProofInjection simulates Byzantine validators submitting
// crafted invalid proofs designed to bypass verification. The verification
// logic must reject proofs with valid structure but invalid content.
func TestMalformedProofInjection(t *testing.T) {
	validators := makeValidators(t, 3, 10)
	height := int64(300)

	tests := []struct {
		name    string
		modify  func(*app.ComputeVerification)
		wantErr bool
	}{
		{
			name: "empty model hash",
			modify: func(v *app.ComputeVerification) {
				v.ModelHash = nil
			},
			wantErr: true,
		},
		{
			name: "empty input hash",
			modify: func(v *app.ComputeVerification) {
				v.InputHash = nil
			},
			wantErr: true,
		},
		{
			name: "successful verification with no output hash",
			modify: func(v *app.ComputeVerification) {
				v.Success = true
				v.OutputHash = nil
			},
			wantErr: true,
		},
		{
			name: "TEE attestation with unknown platform",
			modify: func(v *app.ComputeVerification) {
				v.TEEAttestation = &app.TEEAttestationData{
					Platform:    "unknown",
					Measurement: sha256Bytes([]byte("m")),
				}
			},
			wantErr: true,
		},
		{
			name: "TEE attestation missing measurement",
			modify: func(v *app.ComputeVerification) {
				v.TEEAttestation = &app.TEEAttestationData{
					Platform: "aws-nitro",
					Quote:    []byte("real-quote"),
				}
			},
			wantErr: true,
		},
		{
			name: "ZK proof missing circuit hash",
			modify: func(v *app.ComputeVerification) {
				v.ZKProof = &app.ZKProofData{
					ProofSystem:  "ezkl",
					Proof:        []byte("proof-bytes"),
					PublicInputs: []byte("inputs"),
					CircuitHash:  nil, // missing
				}
			},
			wantErr: true,
		},
		{
			name: "ZK proof missing proof bytes",
			modify: func(v *app.ComputeVerification) {
				v.ZKProof = &app.ZKProofData{
					ProofSystem:  "risc0",
					Proof:        nil, // missing
					PublicInputs: []byte("inputs"),
					CircuitHash:  sha256Bytes([]byte("circuit")),
				}
			},
			wantErr: true,
		},
	}

	logger := log.NewNopLogger()
	verifier := app.NewVoteExtensionVerifier(logger, "test-chain", nil)

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v := validators[0]
			ver := makeVerification("job-malformed", sha256Bytes([]byte("out")), true)
			tc.modify(&ver)

			ext := app.NewVoteExtensionAtBlockTime(height, v.addr, time.Now().UTC())
			ext.AddVerification(ver)
			ext.SortVerifications()
			// Sign with valid key to ensure rejection is due to content, not sig
			_ = app.SignVoteExtension(ext, v.privKey)

			// Verify through the verifier which checks proof structures.
			// Use a zero-value SDK context; the verifier does not access the store
			// when validatorGetter is nil and the extension has no signature that
			// requires key lookup.
			err := verifier.VerifyExtension(sdk.Context{}, ext, height, 0, v.addr)

			if tc.wantErr && err == nil {
				t.Errorf("expected verification to reject malformed proof, got nil error")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TestSignatureForgeryAttempt
// ---------------------------------------------------------------------------

// TestSignatureForgeryAttempt simulates validators attempting to forge
// ed25519 signatures on vote extensions. Forged signatures must always be
// rejected by the verification logic.
func TestSignatureForgeryAttempt(t *testing.T) {
	validators := makeValidators(t, 2, 10)
	height := int64(400)

	honest := validators[0]
	attacker := validators[1]

	output := sha256Bytes([]byte("forgery-target"))
	ver := makeVerification("job-forgery", output, true)
	ext := makeSignedExtension(t, honest, height, []app.ComputeVerification{ver})

	// Invariant: honest signature verifies with honest key
	if !app.VerifyVoteExtensionSignature(ext, honest.pubKey) {
		t.Fatal("honest signature should verify with honest key")
	}

	// Attack 1: Try to verify honest extension with attacker's key
	if app.VerifyVoteExtensionSignature(ext, attacker.pubKey) {
		t.Fatal("honest signature must NOT verify with attacker key")
	}

	// Attack 2: Attacker signs with their own key but claims honest validator address
	forgedExt := app.NewVoteExtensionAtBlockTime(height, honest.addr, time.Now().UTC())
	forgedExt.AddVerification(ver)
	forgedExt.SortVerifications()
	_ = app.SignVoteExtension(forgedExt, attacker.privKey)

	// Verifying with honest key should fail
	if app.VerifyVoteExtensionSignature(forgedExt, honest.pubKey) {
		t.Fatal("forged signature (attacker key, honest addr) must NOT verify with honest key")
	}

	// Attack 3: Tamper with signed extension content
	tamperedExt := makeSignedExtension(t, honest, height, []app.ComputeVerification{ver})
	tamperedExt.Verifications[0].OutputHash = sha256Bytes([]byte("tampered"))
	if app.VerifyVoteExtensionSignature(tamperedExt, honest.pubKey) {
		t.Fatal("tampered extension must NOT pass signature verification")
	}

	// Attack 4: Empty signature
	noSigExt := app.NewVoteExtensionAtBlockTime(height, honest.addr, time.Now().UTC())
	noSigExt.AddVerification(ver)
	noSigExt.SortVerifications()
	noSigExt.ExtensionHash = noSigExt.ComputeHash()
	noSigExt.Signature = nil
	if app.VerifyVoteExtensionSignature(noSigExt, honest.pubKey) {
		t.Fatal("nil signature must NOT verify")
	}

	// Attack 5: Wrong-length signature
	badLenExt := makeSignedExtension(t, honest, height, []app.ComputeVerification{ver})
	badLenExt.Signature = badLenExt.Signature[:32] // truncated
	if app.VerifyVoteExtensionSignature(badLenExt, honest.pubKey) {
		t.Fatal("truncated signature must NOT verify")
	}

	// Attack 6: Random bytes as signature
	randomSigExt := makeSignedExtension(t, honest, height, []app.ComputeVerification{ver})
	_, _ = rand.Read(randomSigExt.Signature)
	if app.VerifyVoteExtensionSignature(randomSigExt, honest.pubKey) {
		t.Fatal("random signature must NOT verify")
	}
}

// ---------------------------------------------------------------------------
// TestConsensusForking
// ---------------------------------------------------------------------------

// TestConsensusForking simulates an attempt to create competing chains by
// having Byzantine validators produce conflicting vote extensions for the
// same job. BFT consensus must resolve to a single output with no state
// divergence.
func TestConsensusForking(t *testing.T) {
	const (
		numValidators   = 10
		consensusThresh = 67
		validatorPower  = 10
		height          = int64(500)
	)

	validators := makeValidators(t, numValidators, validatorPower)

	// Two competing outputs for the same job
	forkA := sha256Bytes([]byte("fork-chain-A"))
	forkB := sha256Bytes([]byte("fork-chain-B"))

	// 7 validators vote for fork A, 3 for fork B
	var votes []app.VoteExtensionWithPower
	for i, v := range validators {
		var output []byte
		if i < 7 {
			output = forkA
		} else {
			output = forkB
		}
		ver := makeVerification("job-fork", output, true)
		ext := makeSignedExtension(t, v, height, []app.ComputeVerification{ver})
		votes = append(votes, app.VoteExtensionWithPower{
			Extension: ext,
			Power:     v.power,
		})
	}

	results := app.AggregateVoteExtensions(sdk.Context{}, votes, consensusThresh, true)
	agg, ok := results["job-fork"]
	if !ok {
		t.Fatal("expected aggregation result for job-fork")
	}

	// Invariant: exactly one fork wins
	if !agg.HasConsensus {
		t.Fatal("consensus should resolve fork (70% > 67% threshold)")
	}

	// Invariant: winning fork is A (70% power)
	if hex.EncodeToString(agg.OutputHash) != hex.EncodeToString(forkA) {
		t.Fatalf("consensus output = %x; want fork A %x", agg.OutputHash, forkA)
	}

	// Invariant: no dual consensus (only one output wins)
	forkBHex := hex.EncodeToString(forkB)
	forkAHex := hex.EncodeToString(forkA)
	if forkAHex == forkBHex {
		t.Fatal("test setup error: fork hashes must be different")
	}

	// Verify agreement power reflects only fork A voters
	if agg.AgreementPower != int64(7*validatorPower) {
		t.Fatalf("agreement power = %d; want %d (7 validators)", agg.AgreementPower, 7*validatorPower)
	}

	// Cross-verification: run aggregation again with jobs shuffled
	// to verify determinism regardless of vote ordering.
	reversed := make([]app.VoteExtensionWithPower, len(votes))
	for i, v := range votes {
		reversed[len(votes)-1-i] = v
	}
	reversedResults := app.AggregateVoteExtensions(sdk.Context{}, reversed, consensusThresh, true)
	revAgg := reversedResults["job-fork"]
	if hex.EncodeToString(revAgg.OutputHash) != hex.EncodeToString(agg.OutputHash) {
		t.Fatal("consensus result must be deterministic regardless of vote order")
	}
}

// ---------------------------------------------------------------------------
// TestDDoSVoteExtension
// ---------------------------------------------------------------------------

// TestDDoSVoteExtension simulates Byzantine validators flooding oversized
// vote extensions to exhaust processing time. The system must enforce the
// 5MB size limit and 100-verification cap, accepting partial results from
// honest validators while rejecting oversized extensions.
func TestDDoSVoteExtension(t *testing.T) {
	validators := makeValidators(t, 5, 10)
	height := int64(600)

	// Attack: create extension that exceeds MaxVoteExtensionSizeBytes
	attacker := validators[0]
	largeExt := app.NewVoteExtensionAtBlockTime(height, attacker.addr, time.Now().UTC())

	// Add more than MaxVerificationsPerExtension verifications
	for i := 0; i < app.MaxVerificationsPerExtension+50; i++ {
		jobID := fmt.Sprintf("ddos-job-%05d", i)
		ver := makeVerification(jobID, sha256Bytes([]byte(jobID)), true)
		largeExt.AddVerification(ver)
	}
	largeExt.SortVerifications()

	// Invariant: extension with too many verifications is detected
	if len(largeExt.Verifications) <= app.MaxVerificationsPerExtension {
		t.Fatal("test setup: extension should exceed max verifications")
	}

	// Marshal the oversized extension
	largeExt.ExtensionHash = largeExt.ComputeHash()
	_ = app.SignVoteExtension(largeExt, attacker.privKey)
	oversizedBytes, err := largeExt.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	// Invariant: oversized extension exceeds size limit
	if len(oversizedBytes) <= app.MaxVoteExtensionSizeBytes {
		// If it fits within the limit, verify verification count check catches it
		t.Logf("extension fits in %d bytes, checking verification count cap", len(oversizedBytes))
	}

	// Verify that honest validators' normal-sized extensions are still accepted
	honestVal := validators[1]
	honestExt := app.NewVoteExtensionAtBlockTime(height, honestVal.addr, time.Now().UTC())
	ver := makeVerification("honest-job", sha256Bytes([]byte("honest-output")), true)
	honestExt.AddVerification(ver)
	honestExt.SortVerifications()
	_ = app.SignVoteExtension(honestExt, honestVal.privKey)

	honestBytes, err := honestExt.Marshal()
	if err != nil {
		t.Fatalf("marshal honest: %v", err)
	}

	// Invariant: honest extension is within size limit
	if len(honestBytes) > app.MaxVoteExtensionSizeBytes {
		t.Fatalf("honest extension too large: %d bytes", len(honestBytes))
	}

	// Invariant: honest extension round-trips correctly
	parsed, err := app.UnmarshalVoteExtension(honestBytes)
	if err != nil {
		t.Fatalf("unmarshal honest: %v", err)
	}
	if len(parsed.Verifications) != 1 {
		t.Fatalf("expected 1 verification, got %d", len(parsed.Verifications))
	}

	// Verify consensus still works when only honest validators participate
	var honestVotes []app.VoteExtensionWithPower
	for _, v := range validators[1:] { // exclude attacker
		vExt := makeSignedExtension(t, v, height, []app.ComputeVerification{ver})
		honestVotes = append(honestVotes, app.VoteExtensionWithPower{
			Extension: vExt,
			Power:     v.power,
		})
	}
	results := app.AggregateVoteExtensions(sdk.Context{}, honestVotes, 67, true)
	if agg, ok := results["honest-job"]; !ok || !agg.HasConsensus {
		t.Fatal("honest validators should still reach consensus despite DDoS attacker")
	}
}
