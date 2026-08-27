package types

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	"github.com/aethelred/aethelred/crypto/pqc"
)

// makeValidators builds n validator wallets with the given powers and returns
// the registry plus the wallets (for signing).
func makeValidators(t *testing.T, powers []int64) (map[string]ValidatorVotingInfo, []*pqc.DualKeyWallet, []string) {
	t.Helper()
	reg := make(map[string]ValidatorVotingInfo, len(powers))
	wallets := make([]*pqc.DualKeyWallet, len(powers))
	addrs := make([]string, len(powers))
	for i, p := range powers {
		w, err := pqc.NewDualKeyWallet(pqc.DilithiumLevel3)
		if err != nil {
			t.Fatal(err)
		}
		addr := fmt.Sprintf("aethelvaloper1%02d", i)
		reg[addr] = ValidatorVotingInfo{HybridPubKey: w.HybridPublicKey(), Power: p}
		wallets[i] = w
		addrs[i] = addr
	}
	return reg, wallets, addrs
}

func sampleClaim() SealClaim {
	return SealClaim{
		ChainID:          "aethelred-testnet-1",
		JobID:            "job-abc-123",
		ModelCommitment:  bytes.Repeat([]byte{0x11}, 32),
		InputCommitment:  bytes.Repeat([]byte{0x22}, 32),
		OutputCommitment: bytes.Repeat([]byte{0x33}, 32),
	}
}

func signClaim(t *testing.T, w *pqc.DualKeyWallet, addr string, claim SealClaim) SealSignature {
	t.Helper()
	sig, err := w.SignHybrid(claim.SigningBytes())
	if err != nil {
		t.Fatal(err)
	}
	return NewValidatorSealSignature(addr, w.HybridPublicKey(), sig, time.Unix(0, 0).UTC())
}

func TestVerifySealQuorum_ReachedAndRejected(t *testing.T) {
	// 4 validators, equal power 10 each => total 40, required (40*67/100)+1 = 27.
	reg, wallets, addrs := makeValidators(t, []int64{10, 10, 10, 10})
	claim := sampleClaim()

	// 3 of 4 sign (power 30 >= 27) => quorum reached.
	var sigs []SealSignature
	for i := 0; i < 3; i++ {
		sigs = append(sigs, signClaim(t, wallets[i], addrs[i], claim))
	}
	res, err := VerifySealQuorum(claim, sigs, reg, 67)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Reached {
		t.Fatalf("expected quorum: agreed=%d required=%d total=%d", res.AgreedPower, res.RequiredPower, res.TotalPower)
	}
	if res.AgreedPower != 30 || len(res.ValidSigners) != 3 {
		t.Fatalf("unexpected result: agreed=%d signers=%v", res.AgreedPower, res.ValidSigners)
	}

	// Only 2 of 4 sign (power 20 < 27) => quorum NOT reached.
	res2, err := VerifySealQuorum(claim, sigs[:2], reg, 67)
	if err != nil {
		t.Fatal(err)
	}
	if res2.Reached {
		t.Fatalf("did not expect quorum with power %d (required %d)", res2.AgreedPower, res2.RequiredPower)
	}
}

func TestVerifySealQuorum_PowerWeighted(t *testing.T) {
	// One whale (power 100) + 3 minnows (power 1) => total 103, required 70.
	reg, wallets, addrs := makeValidators(t, []int64{100, 1, 1, 1})
	claim := sampleClaim()

	// Whale alone signs => 100 >= 70 => reached.
	whale := []SealSignature{signClaim(t, wallets[0], addrs[0], claim)}
	res, err := VerifySealQuorum(claim, whale, reg, 67)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Reached || res.AgreedPower != 100 {
		t.Fatalf("whale should reach quorum: %+v", res)
	}

	// All three minnows sign => 3 < 70 => not reached.
	var minnows []SealSignature
	for i := 1; i < 4; i++ {
		minnows = append(minnows, signClaim(t, wallets[i], addrs[i], claim))
	}
	res2, _ := VerifySealQuorum(claim, minnows, reg, 67)
	if res2.Reached {
		t.Fatalf("minnows should not reach quorum: %+v", res2)
	}
}

func TestVerifySealQuorum_RejectsBadSignatures(t *testing.T) {
	reg, wallets, addrs := makeValidators(t, []int64{10, 10, 10})
	claim := sampleClaim()

	// Valid signature from validator 0.
	good := signClaim(t, wallets[0], addrs[0], claim)

	// Signature over a DIFFERENT claim (wrong output) must not count.
	otherClaim := claim
	otherClaim.OutputCommitment = bytes.Repeat([]byte{0x99}, 32)
	wrongClaimSig := signClaim(t, wallets[1], addrs[1], otherClaim)

	// Signature from an unregistered signer must not count.
	stranger, _ := pqc.NewDualKeyWallet(pqc.DilithiumLevel3)
	strangerSig := NewValidatorSealSignature("aethelvaloper1ZZ", stranger.HybridPublicKey(), mustSign(t, stranger, claim), time.Now())

	// Duplicate of validator 0 must be counted once.
	dup := good

	sigs := []SealSignature{good, wrongClaimSig, strangerSig, dup}
	res, err := VerifySealQuorum(claim, sigs, reg, 67)
	if err != nil {
		t.Fatal(err)
	}
	if res.AgreedPower != 10 || len(res.ValidSigners) != 1 {
		t.Fatalf("only validator 0 should count once: agreed=%d signers=%v", res.AgreedPower, res.ValidSigners)
	}
}

func mustSign(t *testing.T, w *pqc.DualKeyWallet, claim SealClaim) []byte {
	t.Helper()
	sig, err := w.SignHybrid(claim.SigningBytes())
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

func TestSealClaimRoundtripFromSeal(t *testing.T) {
	claim := sampleClaim()
	// A seal carrying the same fields must produce identical signing bytes, so a
	// validator's pre-seal signature verifies against the finished seal.
	seal := &EnhancedDigitalSeal{
		Version: CurrentSealVersion,
		JobID:   claim.JobID,
		ChainID: claim.ChainID,
	}
	seal.ModelCommitment = claim.ModelCommitment
	seal.InputCommitment = claim.InputCommitment
	seal.OutputCommitment = claim.OutputCommitment

	if !bytes.Equal(seal.SealClaim().SigningBytes(), claim.SigningBytes()) {
		t.Fatal("seal-derived claim bytes differ from validator-side claim bytes")
	}
}
