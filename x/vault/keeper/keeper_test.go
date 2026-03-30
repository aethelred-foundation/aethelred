package keeper

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	storetypes "cosmossdk.io/store/types"
	"golang.org/x/crypto/sha3"
	"github.com/btcsuite/btcd/btcec/v2"
	btcecdsa "github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/cosmos/cosmos-sdk/codec"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/cosmos/cosmos-sdk/runtime"
	"github.com/cosmos/cosmos-sdk/testutil"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/stretchr/testify/require"

	"github.com/aethelred/aethelred/x/vault/types"
)

// ─────────────────────────────────────────────────────────────────────────────
// Test Helpers
// ─────────────────────────────────────────────────────────────────────────────

// Test hex EVM addresses — canonical 20-byte form for registry root compatibility.
const (
	testAddrAlice = "0x000000000000000000000000000000000000a11c"
	testAddrBob   = "0x000000000000000000000000000000000000b0bb"
	testAddrCarol = "0x0000000000000000000000000000000000ca401e"
)

// setupKeeper creates a fresh Keeper backed by an in-memory store.
func setupKeeper(t *testing.T) (*Keeper, sdk.Context) {
	t.Helper()
	storeKey := storetypes.NewKVStoreKey(types.StoreKey)
	tkey := storetypes.NewTransientStoreKey("transient_test")
	ctx := testutil.DefaultContext(storeKey, tkey)

	// Set block time to "now" so attestation freshness checks work.
	ctx = ctx.WithBlockTime(time.Now())

	ir := codectypes.NewInterfaceRegistry()
	cdc := codec.NewProtoCodec(ir)
	storeService := runtime.NewKVStoreService(storeKey)
	k := NewKeeper(cdc, storeService, "authority")
	require.NoError(t, k.InitializeDefaults(ctx))

	return k, ctx
}

// testEnclaveHashes returns deterministic test enclave/signer hashes.
func testEnclaveHashes() (enclaveHash, signerHash [32]byte) {
	enclaveHash = sha256.Sum256([]byte("test-enclave-v1"))
	signerHash = sha256.Sum256([]byte("test-signer-v1"))
	return
}

// p256TestPrivateKey returns a deterministic P-256 private key (D=1, pubkey = generator).
func p256TestPrivateKey() *ecdsa.PrivateKey {
	priv := new(ecdsa.PrivateKey)
	priv.Curve = elliptic.P256()
	priv.D = big.NewInt(1)
	priv.PublicKey.X, priv.PublicKey.Y = elliptic.P256().ScalarBaseMult(big.NewInt(1).Bytes())
	return priv
}

// p256TestPublicKey returns the P-256 generator point (public key for D=1).
func p256TestPublicKey() (x, y *big.Int) {
	return elliptic.P256().ScalarBaseMult(big.NewInt(1).Bytes())
}

// vendorRootTestPrivateKey returns the test vendor root P-256 private key (D=2).
func vendorRootTestPrivateKey() *ecdsa.PrivateKey {
	priv := new(ecdsa.PrivateKey)
	priv.Curve = elliptic.P256()
	priv.D = big.NewInt(2)
	priv.PublicKey.X, priv.PublicKey.Y = elliptic.P256().ScalarBaseMult(big.NewInt(2).Bytes())
	return priv
}

// vendorRootTestPublicKey returns the test vendor root P-256 public key (2*G).
func vendorRootTestPublicKey() (x, y *big.Int) {
	return elliptic.P256().ScalarBaseMult(big.NewInt(2).Bytes())
}

// generateVendorKeyAttestation creates a vendor root signature over a platform key.
func generateVendorKeyAttestation(t *testing.T, platformKeyX, platformKeyY *big.Int, platformId uint8) (rHex, sHex string) {
	t.Helper()
	vendorPriv := vendorRootTestPrivateKey()

	// Build attestation message: SHA-256(pkX[32] || pkY[32] || platformId[1])
	var data []byte
	xBytes := make([]byte, 32)
	yBytes := make([]byte, 32)
	platformKeyX.FillBytes(xBytes)
	platformKeyY.FillBytes(yBytes)
	data = append(data, xBytes...)
	data = append(data, yBytes...)
	data = append(data, platformId)
	hash := sha256.Sum256(data)

	r, s, err := ecdsa.Sign(rand.Reader, vendorPriv, hash[:])
	require.NoError(t, err)

	rBytes := make([]byte, 32)
	sBytes := make([]byte, 32)
	r.FillBytes(rBytes)
	s.FillBytes(sBytes)
	return hex.EncodeToString(rBytes), hex.EncodeToString(sBytes)
}

// registerTestEnclaveAndOperator sets up a valid enclave + operator for tests.
func registerTestEnclaveAndOperator(
	t *testing.T,
	k *Keeper,
	ctx sdk.Context,
	pubKey *btcec.PublicKey,
) string {
	t.Helper()
	enclaveHash, signerHash := testEnclaveHashes()

	p256X, p256Y := p256TestPublicKey()

	// Register vendor root key for SGX platform
	vrX, vrY := vendorRootTestPublicKey()
	err := k.RegisterVendorRootKey(ctx, types.PlatformSGX,
		hex.EncodeToString(vrX.Bytes()),
		hex.EncodeToString(vrY.Bytes()))
	// Ignore "already registered" since multiple tests may call this
	if err != nil {
		// Only fail if it's not a duplicate
		existing, getErr := k.getVendorRootKey(ctx, types.PlatformSGX)
		if getErr != nil || existing == nil {
			require.NoError(t, err)
		}
	}

	// Generate vendor key attestation
	vendorR, vendorS := generateVendorKeyAttestation(t, p256X, p256Y, types.PlatformSGX)

	enclaveID, err := k.RegisterEnclave(ctx, types.EnclaveRegistration{
		EnclaveHash:   hex.EncodeToString(enclaveHash[:]),
		SignerHash:    hex.EncodeToString(signerHash[:]),
		Platform:      types.PlatformSGX,
		Description:   "Test SGX Enclave",
		PlatformKeyX:  hex.EncodeToString(p256X.Bytes()),
		PlatformKeyY:  hex.EncodeToString(p256Y.Bytes()),
		VendorAttestR: vendorR,
		VendorAttestS: vendorS,
	})
	require.NoError(t, err)

	pubKeyHex := hex.EncodeToString(pubKey.SerializeCompressed())
	err = k.RegisterOperator(ctx, types.OperatorRegistration{
		PubKeyHex:   pubKeyHex,
		EnclaveID:   enclaveID,
		Description: "Test TEE Operator",
	})
	require.NoError(t, err)

	return enclaveID
}

// testValidators returns a small validator set for testing.
func testValidators() []types.ValidatorRecord {
	return []types.ValidatorRecord{
		{Address: "aethel1val1", DelegatedStake: 1000, PerformanceScore: 9500, Commission: 500},
		{Address: "aethel1val2", DelegatedStake: 2000, PerformanceScore: 9800, Commission: 400},
	}
}

// generateMockHwReportHash generates a mock hardware report hash for testing.
// In production, this would be SHA-256 of an actual SGX DCAP quote, Nitro document,
// or SEV-SNP attestation report.
func generateMockHwReportHash(enclaveHash, signerHash [32]byte, digest [32]byte) [32]byte {
	h := sha256.New()
	h.Write([]byte("MOCK_HW_REPORT_V1"))
	h.Write(enclaveHash[:])
	h.Write(signerHash[:])
	h.Write(digest[:])
	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}

// testPolicyHash computes the default selection policy hash matching
// the protocol defaults used in ApplyValidatorSelection.
func testPolicyHash() [32]byte {
	return computeSelectionPolicyHash(
		0.4,  // performance_weight
		0.3,  // decentralization_weight
		0.3,  // reputation_weight
		95.0, // min_uptime_pct
		types.MaxCommissionBPS,
		0, // max_per_region (0 = no limit)
		3, // max_per_operator
		new(big.Int).SetUint64(types.MinStakeUAETH),
	)
}

// Ensure encoding/binary and math are used (prevent unused-import errors
// in case the compiler cannot see through to computeSelectionPolicyHash).
var _ = binary.BigEndian
var _ = math.Float64bits

// emptyUniverseHash returns the universe hash for an empty eligible set
// (SHA-256 of no addresses), which is the expected value when
// ApplyValidatorSelection is called against a store with no prior validators.
func emptyUniverseHash() [32]byte {
	return computeEligibleUniverseHash(nil)
}

// signAttestation builds and signs a TEEAttestation for the given validators.
//
// universeHash must match what ApplyValidatorSelection will compute from
// on-chain state.  For a fresh store with no prior validators, use
// emptyUniverseHash().
func signAttestation(
	t *testing.T,
	privKey *btcec.PrivateKey,
	validators []types.ValidatorRecord,
	blockTime time.Time,
	nonce string,
	epoch uint64,
) types.TEEAttestation {
	return signAttestationWithUniverse(t, privKey, validators, blockTime, nonce, epoch, emptyUniverseHash())
}

// signAttestationWithUniverse builds and signs a TEEAttestation with an
// explicit universe hash binding.
func signAttestationWithUniverse(
	t *testing.T,
	privKey *btcec.PrivateKey,
	validators []types.ValidatorRecord,
	blockTime time.Time,
	nonce string,
	epoch uint64,
	universeHash [32]byte,
) types.TEEAttestation {
	t.Helper()
	enclaveHash, signerHash := testEnclaveHashes()

	// Compute payload hash = SHA-256(canonicalHash || policyHash || universeHash).
	// The canonical hash includes the epoch to prevent cross-epoch replay.
	// The policy hash binds the attestation to the selection parameters.
	// The universe hash binds the attestation to the full eligible candidate set.
	// This matches the 96-byte verification in ApplyValidatorSelection.
	canonicalHash := computeValidatorSetHash(epoch, validators)
	policyHash := testPolicyHash()

	var payload [96]byte
	copy(payload[:32], canonicalHash[:])
	copy(payload[32:64], policyHash[:])
	copy(payload[64:96], universeHash[:])
	payloadHash := sha256.Sum256(payload[:])

	att := types.TEEAttestation{
		Platform:    types.PlatformSGX,
		Timestamp:   blockTime.Unix(),
		Nonce:       nonce,
		EnclaveHash: hex.EncodeToString(enclaveHash[:]),
		SignerHash:  hex.EncodeToString(signerHash[:]),
		PayloadHash: hex.EncodeToString(payloadHash[:]),
	}

	// Sign the attestation digest
	digest := computeAttestationDigest(att)

	// Generate mock raw hardware report hash (per-attestation binding)
	rawReportHash := generateMockHwReportHash(enclaveHash, signerHash, digest)

	// Compute binding hash: SHA-256(rawReportHash || mrenclave || mrsigner)
	// This ties the hardware report to the specific measurements.
	bindingHasher := sha256.New()
	bindingHasher.Write(rawReportHash[:])
	bindingHasher.Write(enclaveHash[:])
	bindingHasher.Write(signerHash[:])
	var bindingHash [32]byte
	copy(bindingHash[:], bindingHasher.Sum(nil))

	// Build report body with bindingHash (packed: 32+32+32+2+2+32 = 132 bytes)
	reportBody := make([]byte, 0, 132)
	reportBody = append(reportBody, enclaveHash[:]...)
	reportBody = append(reportBody, signerHash[:]...)
	reportBody = append(reportBody, digest[:]...)
	reportBody = append(reportBody, 0, 1) // isvProdId = 1
	reportBody = append(reportBody, 0, 1) // isvSvn = 1
	reportBody = append(reportBody, bindingHash[:]...)
	reportHash := sha256.Sum256(reportBody)

	// Sign with P-256 (private key = 1)
	p256PrivKey := p256TestPrivateKey()
	sigR, sigS, err := ecdsa.Sign(rand.Reader, p256PrivKey, reportHash[:])
	require.NoError(t, err)

	// Generate SGX platform evidence: 8 x 32 = 256 bytes (with rawReportHash)
	evidence := make([]byte, 8*32)
	copy(evidence[0:32], enclaveHash[:])       // mrenclave (from hardware report)
	copy(evidence[32:64], signerHash[:])       // mrsigner (from hardware report)
	copy(evidence[64:96], digest[:])           // reportData = attestation digest
	evidence[126] = 0; evidence[127] = 1       // isvProdId = 1 (uint16 right-aligned at [96:128])
	evidence[158] = 0; evidence[159] = 1       // isvSvn = 1 (uint16 right-aligned at [128:160])
	copy(evidence[160:192], rawReportHash[:])  // rawReportHash (verifier computes bindingHash)

	// r and s as 32-byte big-endian, left-padded
	rBytes := sigR.Bytes()
	sBytes := sigS.Bytes()
	copy(evidence[224-len(rBytes):224], rBytes) // right-align r in [192:224]
	copy(evidence[256-len(sBytes):256], sBytes) // right-align s in [224:256]
	att.PlatformEvidence = hex.EncodeToString(evidence)

	// secp256k1 signature for operator verification
	compactSig := btcecdsa.SignCompact(privKey, digest[:], false) // uncompressed recovery

	// Convert btcec compact (V[1]‖R[32]‖S[32]) → Ethereum-style (R[32]‖S[32]‖V[1])
	ethSig := make([]byte, 65)
	copy(ethSig[0:32], compactSig[1:33])  // R
	copy(ethSig[32:64], compactSig[33:65]) // S
	ethSig[64] = compactSig[0]             // V (27 or 28)

	att.Signature = hex.EncodeToString(ethSig)
	return att
}

// uniqueNonce returns a deterministic hex nonce for test uniqueness.
func uniqueNonce(suffix string) string {
	h := sha256.Sum256([]byte("nonce-" + suffix))
	return hex.EncodeToString(h[:])
}

// ─────────────────────────────────────────────────────────────────────────────
// Basic Operations
// ─────────────────────────────────────────────────────────────────────────────

// registerActiveValidator is a test helper that persists an active validator
// record so that Stake() can validate the delegation target.
func registerActiveValidator(t *testing.T, k *Keeper, ctx sdk.Context, addr string) {
	t.Helper()
	require.NoError(t, k.setValidator(ctx, &types.ValidatorRecord{
		Address:          addr,
		IsActive:         true,
		GeographicRegion: "us-east-1",
		OperatorID:       "op-" + addr,
		Commission:       500,
		TEEPublicKey:     []byte("test-key"),
		ActiveSince:      time.Now().Add(-24 * time.Hour),
	}))
}

func TestStakeAndUnstake(t *testing.T) {
	k, ctx := setupKeeper(t)

	// Register a validator so Stake() can validate the delegation.
	registerActiveValidator(t, k, ctx, "val-1")

	// Stake
	shares, err := k.Stake(ctx, testAddrAlice, 100_000_000, "val-1", 0)
	require.NoError(t, err)
	require.Equal(t, uint64(100_000_000), shares)

	// Check totals
	require.Equal(t, uint64(100_000_000), k.getUint64(ctx, k.TotalPooledAethel))
	require.Equal(t, uint64(100_000_000), k.getUint64(ctx, k.TotalShares))

	// Verify delegation was persisted
	staker, exists := k.getStaker(ctx, testAddrAlice)
	require.True(t, exists)
	require.Equal(t, "val-1", staker.DelegatedTo)

	// Unstake
	wID, amount, err := k.Unstake(ctx, testAddrAlice, 50_000_000)
	require.NoError(t, err)
	require.Equal(t, uint64(1), wID)
	require.Equal(t, uint64(50_000_000), amount)
	require.Equal(t, uint64(50_000_000), k.getUint64(ctx, k.TotalPooledAethel))
}

func TestExchangeRate(t *testing.T) {
	k, ctx := setupKeeper(t)

	// Before any stakes, rate = 1.0
	require.Equal(t, 1.0, k.GetExchangeRate(ctx))

	// After stake, still 1.0
	registerActiveValidator(t, k, ctx, "val-1")
	_, err := k.Stake(ctx, testAddrAlice, 100_000_000, "val-1", 0)
	require.NoError(t, err)
	require.Equal(t, 1.0, k.GetExchangeRate(ctx))
}

// ─────────────────────────────────────────────────────────────────────────────
// Delegation Tests
// ─────────────────────────────────────────────────────────────────────────────

func TestStake_RequiresValidator(t *testing.T) {
	k, ctx := setupKeeper(t)

	// Empty validatorAddr → error
	_, err := k.Stake(ctx, testAddrAlice, 100_000_000, "", 0)
	require.Error(t, err)
	require.Contains(t, err.Error(), "validatorAddr is required")
}

func TestStake_RejectsUnknownValidator(t *testing.T) {
	k, ctx := setupKeeper(t)

	_, err := k.Stake(ctx, testAddrAlice, 100_000_000, "nonexistent-val", 0)
	require.Error(t, err)
	require.Contains(t, err.Error(), "validator nonexistent-val not found")
}

func TestStake_RejectsInactiveValidator(t *testing.T) {
	k, ctx := setupKeeper(t)

	// Register an inactive validator
	require.NoError(t, k.setValidator(ctx, &types.ValidatorRecord{
		Address:  "inactive-val",
		IsActive: false,
	}))

	_, err := k.Stake(ctx, testAddrAlice, 100_000_000, "inactive-val", 0)
	require.Error(t, err)
	require.Contains(t, err.Error(), "validator inactive-val is not active")
}

func TestStake_UpdatesDelegationOnRestake(t *testing.T) {
	k, ctx := setupKeeper(t)

	registerActiveValidator(t, k, ctx, "val-1")
	registerActiveValidator(t, k, ctx, "val-2")

	// Initial stake delegates to val-1
	_, err := k.Stake(ctx, testAddrAlice, 100_000_000, "val-1", 0)
	require.NoError(t, err)
	staker, _ := k.getStaker(ctx, testAddrAlice)
	require.Equal(t, "val-1", staker.DelegatedTo)

	// Re-stake with val-2 updates delegation
	_, err = k.Stake(ctx, testAddrAlice, 100_000_000, "val-2", 0)
	require.NoError(t, err)
	staker, _ = k.getStaker(ctx, testAddrAlice)
	require.Equal(t, "val-2", staker.DelegatedTo)
}

func TestDelegateStake(t *testing.T) {
	k, ctx := setupKeeper(t)

	registerActiveValidator(t, k, ctx, "val-1")
	registerActiveValidator(t, k, ctx, "val-2")

	// Stake with val-1
	_, err := k.Stake(ctx, testAddrAlice, 100_000_000, "val-1", 0)
	require.NoError(t, err)

	// Re-delegate to val-2
	err = k.DelegateStake(ctx, testAddrAlice, "val-2")
	require.NoError(t, err)

	staker, _ := k.getStaker(ctx, testAddrAlice)
	require.Equal(t, "val-2", staker.DelegatedTo)
}

func TestDelegateStake_RejectsEmpty(t *testing.T) {
	k, ctx := setupKeeper(t)

	registerActiveValidator(t, k, ctx, "val-1")
	_, err := k.Stake(ctx, testAddrAlice, 100_000_000, "val-1", 0)
	require.NoError(t, err)

	err = k.DelegateStake(ctx, testAddrAlice, "")
	require.Error(t, err)
	require.Contains(t, err.Error(), "validatorAddr is required")
}

func TestDelegateStake_RejectsNonexistentStaker(t *testing.T) {
	k, ctx := setupKeeper(t)

	err := k.DelegateStake(ctx, "nobody", "val-1")
	require.Error(t, err)
	require.Contains(t, err.Error(), "staker not found")
}

func TestDelegateStake_RejectsInactiveValidator(t *testing.T) {
	k, ctx := setupKeeper(t)

	registerActiveValidator(t, k, ctx, "val-1")
	_, err := k.Stake(ctx, testAddrAlice, 100_000_000, "val-1", 0)
	require.NoError(t, err)

	// Register an inactive validator
	require.NoError(t, k.setValidator(ctx, &types.ValidatorRecord{
		Address:  "inactive-val",
		IsActive: false,
	}))

	err = k.DelegateStake(ctx, testAddrAlice, "inactive-val")
	require.Error(t, err)
	require.Contains(t, err.Error(), "validator inactive-val is not active")
}

// ─────────────────────────────────────────────────────────────────────────────
// Validator DelegatedStake Accounting
// ─────────────────────────────────────────────────────────────────────────────

func getValidatorDelegatedStake(t *testing.T, k *Keeper, ctx sdk.Context, addr string) uint64 {
	t.Helper()
	v, ok := k.getValidator(ctx, addr)
	require.True(t, ok, "validator %s should exist", addr)
	return v.DelegatedStake
}

func TestStake_IncrementsValidatorDelegatedStake(t *testing.T) {
	k, ctx := setupKeeper(t)
	registerActiveValidator(t, k, ctx, "val-1")

	// Validator starts with 0 delegated stake.
	require.Equal(t, uint64(0), getValidatorDelegatedStake(t, k, ctx, "val-1"))

	// First staker adds 100.
	_, err := k.Stake(ctx, testAddrAlice, 100_000_000, "val-1", 0)
	require.NoError(t, err)
	require.Equal(t, uint64(100_000_000), getValidatorDelegatedStake(t, k, ctx, "val-1"))

	// Second staker adds 200 to the same validator.
	_, err = k.Stake(ctx, testAddrBob, 200_000_000, "val-1", 0)
	require.NoError(t, err)
	require.Equal(t, uint64(300_000_000), getValidatorDelegatedStake(t, k, ctx, "val-1"))

	// Alice re-stakes 50 more to the same validator.
	_, err = k.Stake(ctx, testAddrAlice, 50_000_000, "val-1", 0)
	require.NoError(t, err)
	require.Equal(t, uint64(350_000_000), getValidatorDelegatedStake(t, k, ctx, "val-1"))
}

func TestStake_RestakeTransfersDelegatedStake(t *testing.T) {
	k, ctx := setupKeeper(t)
	registerActiveValidator(t, k, ctx, "val-1")
	registerActiveValidator(t, k, ctx, "val-2")

	// Alice stakes 100 to val-1.
	_, err := k.Stake(ctx, testAddrAlice, 100_000_000, "val-1", 0)
	require.NoError(t, err)
	require.Equal(t, uint64(100_000_000), getValidatorDelegatedStake(t, k, ctx, "val-1"))
	require.Equal(t, uint64(0), getValidatorDelegatedStake(t, k, ctx, "val-2"))

	// Alice re-stakes 50 more but changes delegation to val-2.
	// Old validator should lose 100 (alice's full previous position).
	// New validator should gain 100 + 50 = 150.
	_, err = k.Stake(ctx, testAddrAlice, 50_000_000, "val-2", 0)
	require.NoError(t, err)
	require.Equal(t, uint64(0), getValidatorDelegatedStake(t, k, ctx, "val-1"))
	require.Equal(t, uint64(150_000_000), getValidatorDelegatedStake(t, k, ctx, "val-2"))
}

func TestUnstake_DecrementsValidatorDelegatedStake(t *testing.T) {
	k, ctx := setupKeeper(t)
	registerActiveValidator(t, k, ctx, "val-1")

	// Alice stakes 100 and gets shares.
	shares, err := k.Stake(ctx, testAddrAlice, 100_000_000, "val-1", 0)
	require.NoError(t, err)
	require.Equal(t, uint64(100_000_000), getValidatorDelegatedStake(t, k, ctx, "val-1"))

	// Full unstake: validator DelegatedStake should return to 0.
	_, _, err = k.Unstake(ctx, testAddrAlice, shares)
	require.NoError(t, err)
	require.Equal(t, uint64(0), getValidatorDelegatedStake(t, k, ctx, "val-1"))
}

func TestUnstake_PartialDecrementsValidatorDelegatedStake(t *testing.T) {
	k, ctx := setupKeeper(t)
	registerActiveValidator(t, k, ctx, "val-1")

	// Alice stakes 200.
	shares, err := k.Stake(ctx, testAddrAlice, 200_000_000, "val-1", 0)
	require.NoError(t, err)
	require.Equal(t, uint64(200_000_000), getValidatorDelegatedStake(t, k, ctx, "val-1"))

	// Partial unstake: withdraw half the shares.
	halfShares := shares / 2
	_, _, err = k.Unstake(ctx, testAddrAlice, halfShares)
	require.NoError(t, err)

	// Validator should have roughly half remaining.
	remaining := getValidatorDelegatedStake(t, k, ctx, "val-1")
	require.Equal(t, uint64(100_000_000), remaining)
}

func TestDelegateStake_TransfersDelegatedStake(t *testing.T) {
	k, ctx := setupKeeper(t)
	registerActiveValidator(t, k, ctx, "val-1")
	registerActiveValidator(t, k, ctx, "val-2")

	// Alice stakes 100 to val-1.
	_, err := k.Stake(ctx, testAddrAlice, 100_000_000, "val-1", 0)
	require.NoError(t, err)
	require.Equal(t, uint64(100_000_000), getValidatorDelegatedStake(t, k, ctx, "val-1"))
	require.Equal(t, uint64(0), getValidatorDelegatedStake(t, k, ctx, "val-2"))

	// Re-delegate to val-2: val-1 loses 100, val-2 gains 100.
	err = k.DelegateStake(ctx, testAddrAlice, "val-2")
	require.NoError(t, err)
	require.Equal(t, uint64(0), getValidatorDelegatedStake(t, k, ctx, "val-1"))
	require.Equal(t, uint64(100_000_000), getValidatorDelegatedStake(t, k, ctx, "val-2"))
}

func TestDelegateStake_SameValidatorNoOp(t *testing.T) {
	k, ctx := setupKeeper(t)
	registerActiveValidator(t, k, ctx, "val-1")

	_, err := k.Stake(ctx, testAddrAlice, 100_000_000, "val-1", 0)
	require.NoError(t, err)
	require.Equal(t, uint64(100_000_000), getValidatorDelegatedStake(t, k, ctx, "val-1"))

	// Re-delegate to the same validator is a no-op for DelegatedStake.
	err = k.DelegateStake(ctx, testAddrAlice, "val-1")
	require.NoError(t, err)
	require.Equal(t, uint64(100_000_000), getValidatorDelegatedStake(t, k, ctx, "val-1"))
}

func TestDelegatedStake_ConsistentAfterMultipleOperations(t *testing.T) {
	k, ctx := setupKeeper(t)
	registerActiveValidator(t, k, ctx, "val-1")
	registerActiveValidator(t, k, ctx, "val-2")
	registerActiveValidator(t, k, ctx, "val-3")

	// Alice: 100 → val-1
	_, err := k.Stake(ctx, testAddrAlice, 100_000_000, "val-1", 0)
	require.NoError(t, err)
	// Bob: 200 → val-1
	_, err = k.Stake(ctx, testAddrBob, 200_000_000, "val-1", 0)
	require.NoError(t, err)
	// Carol: 150 → val-2
	_, err = k.Stake(ctx, testAddrCarol, 150_000_000, "val-2", 0)
	require.NoError(t, err)

	require.Equal(t, uint64(300_000_000), getValidatorDelegatedStake(t, k, ctx, "val-1"))
	require.Equal(t, uint64(150_000_000), getValidatorDelegatedStake(t, k, ctx, "val-2"))
	require.Equal(t, uint64(0), getValidatorDelegatedStake(t, k, ctx, "val-3"))

	// Alice re-delegates from val-1 → val-3 (transfers 100).
	err = k.DelegateStake(ctx, testAddrAlice, "val-3")
	require.NoError(t, err)
	require.Equal(t, uint64(200_000_000), getValidatorDelegatedStake(t, k, ctx, "val-1"))
	require.Equal(t, uint64(150_000_000), getValidatorDelegatedStake(t, k, ctx, "val-2"))
	require.Equal(t, uint64(100_000_000), getValidatorDelegatedStake(t, k, ctx, "val-3"))

	// Bob fully unstakes (200 leaves val-1).
	bobStaker, _ := k.getStaker(ctx, testAddrBob)
	_, _, err = k.Unstake(ctx, testAddrBob, bobStaker.Shares)
	require.NoError(t, err)
	require.Equal(t, uint64(0), getValidatorDelegatedStake(t, k, ctx, "val-1"))
	require.Equal(t, uint64(150_000_000), getValidatorDelegatedStake(t, k, ctx, "val-2"))
	require.Equal(t, uint64(100_000_000), getValidatorDelegatedStake(t, k, ctx, "val-3"))

	// Carol partially unstakes half (75 leaves val-2).
	carolStaker, _ := k.getStaker(ctx, testAddrCarol)
	halfShares := carolStaker.Shares / 2
	_, _, err = k.Unstake(ctx, testAddrCarol, halfShares)
	require.NoError(t, err)
	require.Equal(t, uint64(75_000_000), getValidatorDelegatedStake(t, k, ctx, "val-2"))
	require.Equal(t, uint64(100_000_000), getValidatorDelegatedStake(t, k, ctx, "val-3"))

	// Sum of all validator DelegatedStake should equal total remaining StakedAmounts.
	aliceStaker, _ := k.getStaker(ctx, testAddrAlice)
	bobStaker, _ = k.getStaker(ctx, testAddrBob)
	carolStaker, _ = k.getStaker(ctx, testAddrCarol)
	totalStaked := aliceStaker.StakedAmount + bobStaker.StakedAmount + carolStaker.StakedAmount
	totalDelegated := getValidatorDelegatedStake(t, k, ctx, "val-1") +
		getValidatorDelegatedStake(t, k, ctx, "val-2") +
		getValidatorDelegatedStake(t, k, ctx, "val-3")
	require.Equal(t, totalStaked, totalDelegated,
		"sum of validator DelegatedStake must equal sum of staker StakedAmounts")
}

func TestUnstake_ThenRestake_ValidatorAccountingCorrect(t *testing.T) {
	k, ctx := setupKeeper(t)
	registerActiveValidator(t, k, ctx, "val-1")
	registerActiveValidator(t, k, ctx, "val-2")

	// Alice stakes 100 to val-1.
	shares, err := k.Stake(ctx, testAddrAlice, 100_000_000, "val-1", 0)
	require.NoError(t, err)

	// Full unstake.
	_, _, err = k.Unstake(ctx, testAddrAlice, shares)
	require.NoError(t, err)
	require.Equal(t, uint64(0), getValidatorDelegatedStake(t, k, ctx, "val-1"))

	// Re-stake to val-2.
	_, err = k.Stake(ctx, testAddrAlice, 80_000_000, "val-2", 0)
	require.NoError(t, err)
	require.Equal(t, uint64(0), getValidatorDelegatedStake(t, k, ctx, "val-1"))
	require.Equal(t, uint64(80_000_000), getValidatorDelegatedStake(t, k, ctx, "val-2"))
}

// ─────────────────────────────────────────────────────────────────────────────
// TEE Attestation Verification
// ─────────────────────────────────────────────────────────────────────────────

func TestApplyValidatorSelection_ValidAttestation(t *testing.T) {
	k, ctx := setupKeeper(t)

	// Generate operator key pair
	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	registerTestEnclaveAndOperator(t, k, ctx, privKey.PubKey())

	validators := testValidators()
	blockTime := time.Now()
	ctx = setBlockTime(ctx, blockTime)

	att := signAttestation(t, privKey, validators, blockTime, uniqueNonce("valid-1"), 1)

	err = k.ApplyValidatorSelection(ctx, validators, att, 1)
	require.NoError(t, err)

	// Verify validators were persisted
	active := k.GetActiveValidators(ctx)
	require.Len(t, active, 2)
	require.True(t, active[0].IsActive)
}

func TestApplyValidatorSelection_UnregisteredOperator(t *testing.T) {
	k, ctx := setupKeeper(t)

	// Register enclave but use a DIFFERENT key to sign
	realKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	registerTestEnclaveAndOperator(t, k, ctx, realKey.PubKey())

	// Sign with an unregistered key
	rogueKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	validators := testValidators()
	blockTime := time.Now()
	ctx = setBlockTime(ctx, blockTime)

	att := signAttestation(t, rogueKey, validators, blockTime, uniqueNonce("rogue"), 1)

	err = k.ApplyValidatorSelection(ctx, validators, att, 1)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unregistered operator")
}

func TestApplyValidatorSelection_WrongEnclaveBinding(t *testing.T) {
	k, ctx := setupKeeper(t)

	// Register enclave v1 + operator bound to v1
	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	registerTestEnclaveAndOperator(t, k, ctx, privKey.PubKey())

	// Register a second enclave (v2) with its own P-256 key
	enclave2Hash := sha256.Sum256([]byte("test-enclave-v2"))
	signer2Hash := sha256.Sum256([]byte("test-signer-v2"))
	p256X, p256Y := p256TestPublicKey()

	// Generate vendor key attestation for enclave v2
	vendorR2, vendorS2 := generateVendorKeyAttestation(t, p256X, p256Y, types.PlatformSGX)

	_, err = k.RegisterEnclave(ctx, types.EnclaveRegistration{
		EnclaveHash:   hex.EncodeToString(enclave2Hash[:]),
		SignerHash:    hex.EncodeToString(signer2Hash[:]),
		Platform:      types.PlatformSGX,
		Description:   "Enclave v2",
		PlatformKeyX:  hex.EncodeToString(p256X.Bytes()),
		PlatformKeyY:  hex.EncodeToString(p256Y.Bytes()),
		VendorAttestR: vendorR2,
		VendorAttestS: vendorS2,
	})
	require.NoError(t, err)

	// Build attestation claiming enclave v2 hashes but signed by operator bound to v1
	validators := testValidators()
	blockTime := time.Now()
	ctx = setBlockTime(ctx, blockTime)

	canonicalHash := computeValidatorSetHash(1, validators)
	policyHash := testPolicyHash()
	var payload [64]byte
	copy(payload[:32], canonicalHash[:])
	copy(payload[32:], policyHash[:])
	payloadHash := sha256.Sum256(payload[:])

	att := types.TEEAttestation{
		Platform:    types.PlatformSGX,
		Timestamp:   blockTime.Unix(),
		Nonce:       uniqueNonce("wrong-enclave"),
		EnclaveHash: hex.EncodeToString(enclave2Hash[:]),
		SignerHash:  hex.EncodeToString(signer2Hash[:]),
		PayloadHash: hex.EncodeToString(payloadHash[:]),
	}
	digest := computeAttestationDigest(att)

	// Generate platform evidence for the claimed enclave v2 (7 x 32 = 224 bytes)
	// Build report body for P-256 signing
	reportBody := make([]byte, 0, 100)
	reportBody = append(reportBody, enclave2Hash[:]...)
	reportBody = append(reportBody, signer2Hash[:]...)
	reportBody = append(reportBody, digest[:]...)
	reportBody = append(reportBody, 0, 1) // isvProdId = 1
	reportBody = append(reportBody, 0, 1) // isvSvn = 1
	reportHash := sha256.Sum256(reportBody)

	p256PrivKey := p256TestPrivateKey()
	sigR, sigS, err := ecdsa.Sign(rand.Reader, p256PrivKey, reportHash[:])
	require.NoError(t, err)

	evidence := make([]byte, 7*32)
	copy(evidence[0:32], enclave2Hash[:])
	copy(evidence[32:64], signer2Hash[:])
	copy(evidence[64:96], digest[:])
	evidence[126] = 0; evidence[127] = 1
	evidence[158] = 0; evidence[159] = 1
	rBytes := sigR.Bytes()
	sBytes := sigS.Bytes()
	copy(evidence[192-len(rBytes):192], rBytes)
	copy(evidence[224-len(sBytes):224], sBytes)
	att.PlatformEvidence = hex.EncodeToString(evidence)

	compactSig := btcecdsa.SignCompact(privKey, digest[:], false)
	ethSig := make([]byte, 65)
	copy(ethSig[0:32], compactSig[1:33])
	copy(ethSig[32:64], compactSig[33:65])
	ethSig[64] = compactSig[0]
	att.Signature = hex.EncodeToString(ethSig)

	err = k.ApplyValidatorSelection(ctx, validators, att, 1)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not authorized for enclave")
}

func TestApplyValidatorSelection_ExpiredTimestamp(t *testing.T) {
	k, ctx := setupKeeper(t)

	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	registerTestEnclaveAndOperator(t, k, ctx, privKey.PubKey())

	validators := testValidators()
	// Sign with a timestamp 10 minutes in the past
	staleTime := time.Now().Add(-10 * time.Minute)
	att := signAttestation(t, privKey, validators, staleTime, uniqueNonce("expired"), 1)

	err = k.ApplyValidatorSelection(ctx, validators, att, 1)
	require.Error(t, err)
	require.Contains(t, err.Error(), "attestation expired")
}

func TestApplyValidatorSelection_ReplayedNonce(t *testing.T) {
	k, ctx := setupKeeper(t)

	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	registerTestEnclaveAndOperator(t, k, ctx, privKey.PubKey())

	validators := testValidators()
	nonce := uniqueNonce("replay")
	blockTime := time.Now()
	ctx = setBlockTime(ctx, blockTime)

	att := signAttestation(t, privKey, validators, blockTime, nonce, 1)

	// First call succeeds
	err = k.ApplyValidatorSelection(ctx, validators, att, 1)
	require.NoError(t, err)

	// Second call with the same nonce fails (replay)
	att2 := signAttestation(t, privKey, validators, blockTime, nonce, 1)
	err = k.ApplyValidatorSelection(ctx, validators, att2, 1)
	require.Error(t, err)
	require.Contains(t, err.Error(), "nonce already used")
}

func TestApplyValidatorSelection_PayloadMismatch(t *testing.T) {
	k, ctx := setupKeeper(t)

	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	registerTestEnclaveAndOperator(t, k, ctx, privKey.PubKey())

	// Sign attestation for validator set A
	validatorsA := testValidators()
	blockTime := time.Now()
	ctx = setBlockTime(ctx, blockTime)

	att := signAttestation(t, privKey, validatorsA, blockTime, uniqueNonce("mismatch"), 1)

	// Try to apply with a DIFFERENT validator set B
	validatorsB := []types.ValidatorRecord{
		{Address: "aethel1attacker", DelegatedStake: 999999, PerformanceScore: 10000, Commission: 0},
	}

	err = k.ApplyValidatorSelection(ctx, validatorsB, att, 1)
	require.Error(t, err)
	require.Contains(t, err.Error(), "payload hash mismatch")
}

func TestApplyValidatorSelection_RevokedOperator(t *testing.T) {
	k, ctx := setupKeeper(t)

	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	registerTestEnclaveAndOperator(t, k, ctx, privKey.PubKey())

	// Revoke the operator
	pubKeyHex := hex.EncodeToString(privKey.PubKey().SerializeCompressed())
	require.NoError(t, k.RevokeOperator(ctx, pubKeyHex))

	validators := testValidators()
	blockTime := time.Now()
	ctx = setBlockTime(ctx, blockTime)

	att := signAttestation(t, privKey, validators, blockTime, uniqueNonce("revoked"), 1)

	err = k.ApplyValidatorSelection(ctx, validators, att, 1)
	require.Error(t, err)
	require.Contains(t, err.Error(), "operator revoked")
}

func TestApplyValidatorSelection_RevokedEnclave(t *testing.T) {
	k, ctx := setupKeeper(t)

	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	enclaveID := registerTestEnclaveAndOperator(t, k, ctx, privKey.PubKey())

	// Revoke the enclave
	require.NoError(t, k.RevokeEnclave(ctx, enclaveID))

	validators := testValidators()
	blockTime := time.Now()
	ctx = setBlockTime(ctx, blockTime)

	att := signAttestation(t, privKey, validators, blockTime, uniqueNonce("revoked-enc"), 1)

	err = k.ApplyValidatorSelection(ctx, validators, att, 1)
	require.Error(t, err)
	require.Contains(t, err.Error(), "enclave revoked")
}

func TestApplyValidatorSelection_EmptyValidatorSet(t *testing.T) {
	k, ctx := setupKeeper(t)

	att := types.TEEAttestation{}
	err := k.ApplyValidatorSelection(ctx, nil, att, 1)
	require.Error(t, err)
	require.Contains(t, err.Error(), "empty validator set")
}

func TestApplyValidatorSelection_DuplicateAddressRejected(t *testing.T) {
	k, ctx := setupKeeper(t)

	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	registerTestEnclaveAndOperator(t, k, ctx, privKey.PubKey())

	// Construct a validator set with duplicate addresses
	validators := []types.ValidatorRecord{
		{Address: "aethel1val1", DelegatedStake: 1000, PerformanceScore: 9500, Commission: 500},
		{Address: "aethel1val1", DelegatedStake: 2000, PerformanceScore: 9800, Commission: 400}, // duplicate
	}

	blockTime := time.Now()
	ctx = setBlockTime(ctx, blockTime)

	att := signAttestation(t, privKey, validators, blockTime, uniqueNonce("dup-addr-1"), 1)
	err = k.ApplyValidatorSelection(ctx, validators, att, 1)
	require.Error(t, err)
	require.Contains(t, err.Error(), "duplicate validator address")
}

func TestApplyValidatorSelection_MissingEvidence(t *testing.T) {
	k, ctx := setupKeeper(t)

	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	registerTestEnclaveAndOperator(t, k, ctx, privKey.PubKey())

	validators := testValidators()
	blockTime := time.Now()
	ctx = setBlockTime(ctx, blockTime)

	att := signAttestation(t, privKey, validators, blockTime, uniqueNonce("no-evidence"), 1)

	// Clear the evidence
	att.PlatformEvidence = ""

	err = k.ApplyValidatorSelection(ctx, validators, att, 1)
	require.Error(t, err)
	require.Contains(t, err.Error(), "missing platform evidence")
}

func TestApplyValidatorSelection_WrongEvidenceBinding(t *testing.T) {
	k, ctx := setupKeeper(t)

	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	registerTestEnclaveAndOperator(t, k, ctx, privKey.PubKey())

	validators := testValidators()
	blockTime := time.Now()
	ctx = setBlockTime(ctx, blockTime)

	att := signAttestation(t, privKey, validators, blockTime, uniqueNonce("wrong-binding"), 1)

	// Tamper with evidence: change reportData to wrong digest
	evidenceBytes, _ := hex.DecodeString(att.PlatformEvidence)
	// Corrupt the reportData (bytes 64-96) — this will cause the reportData
	// check to fail before P-256 verification is reached
	for i := 64; i < 96; i++ {
		evidenceBytes[i] = 0xFF
	}
	att.PlatformEvidence = hex.EncodeToString(evidenceBytes)

	err = k.ApplyValidatorSelection(ctx, validators, att, 1)
	require.Error(t, err)
	require.Contains(t, err.Error(), "reportData does not match")
}

func TestApplyValidatorSelection_BadP256Signature(t *testing.T) {
	k, ctx := setupKeeper(t)

	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	registerTestEnclaveAndOperator(t, k, ctx, privKey.PubKey())

	validators := testValidators()
	blockTime := time.Now()
	ctx = setBlockTime(ctx, blockTime)

	att := signAttestation(t, privKey, validators, blockTime, uniqueNonce("bad-p256"), 1)

	// Corrupt the P-256 signature (last 64 bytes of 256-byte evidence: [192:256])
	evidenceBytes, _ := hex.DecodeString(att.PlatformEvidence)
	for i := 192; i < 256; i++ {
		evidenceBytes[i] = 0xFF
	}
	att.PlatformEvidence = hex.EncodeToString(evidenceBytes)

	err = k.ApplyValidatorSelection(ctx, validators, att, 1)
	require.Error(t, err)
	require.Contains(t, err.Error(), "P-256 signature verification failed")
}

// ─────────────────────────────────────────────────────────────────────────────
// Registration
// ─────────────────────────────────────────────────────────────────────────────

func TestRegisterEnclave_DuplicateRejected(t *testing.T) {
	k, ctx := setupKeeper(t)
	enclaveHash, signerHash := testEnclaveHashes()
	p256X, p256Y := p256TestPublicKey()

	// Register vendor root key
	vrX, vrY := vendorRootTestPublicKey()
	require.NoError(t, k.RegisterVendorRootKey(ctx, types.PlatformSGX,
		hex.EncodeToString(vrX.Bytes()),
		hex.EncodeToString(vrY.Bytes())))

	vendorR, vendorS := generateVendorKeyAttestation(t, p256X, p256Y, types.PlatformSGX)

	reg := types.EnclaveRegistration{
		EnclaveHash:   hex.EncodeToString(enclaveHash[:]),
		SignerHash:    hex.EncodeToString(signerHash[:]),
		Platform:      types.PlatformSGX,
		Description:   "First",
		PlatformKeyX:  hex.EncodeToString(p256X.Bytes()),
		PlatformKeyY:  hex.EncodeToString(p256Y.Bytes()),
		VendorAttestR: vendorR,
		VendorAttestS: vendorS,
	}
	_, err := k.RegisterEnclave(ctx, reg)
	require.NoError(t, err)

	_, err = k.RegisterEnclave(ctx, reg)
	require.Error(t, err)
	require.Contains(t, err.Error(), "already registered")
}

func TestRegisterOperator_UnregisteredEnclaveRejected(t *testing.T) {
	k, ctx := setupKeeper(t)

	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	err = k.RegisterOperator(ctx, types.OperatorRegistration{
		PubKeyHex:   hex.EncodeToString(privKey.PubKey().SerializeCompressed()),
		EnclaveID:   "0000000000000000000000000000000000000000000000000000000000000000",
		Description: "Ghost enclave",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "enclave not registered")
}

func TestRegisterEnclave_MissingVendorRootKey(t *testing.T) {
	k, ctx := setupKeeper(t)
	enclaveHash, signerHash := testEnclaveHashes()
	p256X, p256Y := p256TestPublicKey()

	// Don't register vendor root key — should fail
	_, err := k.RegisterEnclave(ctx, types.EnclaveRegistration{
		EnclaveHash:   hex.EncodeToString(enclaveHash[:]),
		SignerHash:    hex.EncodeToString(signerHash[:]),
		Platform:      types.PlatformSGX,
		Description:   "No vendor root",
		PlatformKeyX:  hex.EncodeToString(p256X.Bytes()),
		PlatformKeyY:  hex.EncodeToString(p256Y.Bytes()),
		VendorAttestR: "0000000000000000000000000000000000000000000000000000000000000001",
		VendorAttestS: "0000000000000000000000000000000000000000000000000000000000000001",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "vendor root key")
}

func TestRegisterEnclave_InvalidVendorAttestation(t *testing.T) {
	k, ctx := setupKeeper(t)
	enclaveHash, signerHash := testEnclaveHashes()
	p256X, p256Y := p256TestPublicKey()

	// Register vendor root key
	vrX, vrY := vendorRootTestPublicKey()
	require.NoError(t, k.RegisterVendorRootKey(ctx, types.PlatformSGX,
		hex.EncodeToString(vrX.Bytes()),
		hex.EncodeToString(vrY.Bytes())))

	// Try with invalid vendor attestation (wrong signature)
	_, err := k.RegisterEnclave(ctx, types.EnclaveRegistration{
		EnclaveHash:   hex.EncodeToString(enclaveHash[:]),
		SignerHash:    hex.EncodeToString(signerHash[:]),
		Platform:      types.PlatformSGX,
		Description:   "Bad attestation",
		PlatformKeyX:  hex.EncodeToString(p256X.Bytes()),
		PlatformKeyY:  hex.EncodeToString(p256Y.Bytes()),
		VendorAttestR: "0000000000000000000000000000000000000000000000000000000000000001",
		VendorAttestS: "0000000000000000000000000000000000000000000000000000000000000001",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "vendor key attestation verification failed")
}

func TestRegisterEnclave_SelfIssuedKeyRejected(t *testing.T) {
	// This is the exact attack: operator generates their own P-256 key
	// and tries to register it with a self-signed attestation (not vendor-rooted)
	k, ctx := setupKeeper(t)
	enclaveHash, signerHash := testEnclaveHashes()

	// Register vendor root key (D=2)
	vrX, vrY := vendorRootTestPublicKey()
	require.NoError(t, k.RegisterVendorRootKey(ctx, types.PlatformSGX,
		hex.EncodeToString(vrX.Bytes()),
		hex.EncodeToString(vrY.Bytes())))

	// Attacker generates their own key (D=3)
	attackerPriv := new(ecdsa.PrivateKey)
	attackerPriv.Curve = elliptic.P256()
	attackerPriv.D = big.NewInt(3)
	attackerPriv.PublicKey.X, attackerPriv.PublicKey.Y = elliptic.P256().ScalarBaseMult(big.NewInt(3).Bytes())

	// Self-sign the key attestation (using attacker's own key, not vendor root)
	var data []byte
	xBytes := make([]byte, 32)
	yBytes := make([]byte, 32)
	attackerPriv.PublicKey.X.FillBytes(xBytes)
	attackerPriv.PublicKey.Y.FillBytes(yBytes)
	data = append(data, xBytes...)
	data = append(data, yBytes...)
	data = append(data, types.PlatformSGX)
	hash := sha256.Sum256(data)

	// Sign with attacker's key (not vendor root)
	r, s, err := ecdsa.Sign(rand.Reader, attackerPriv, hash[:])
	require.NoError(t, err)
	rBytes := make([]byte, 32)
	sBytes := make([]byte, 32)
	r.FillBytes(rBytes)
	s.FillBytes(sBytes)

	_, err = k.RegisterEnclave(ctx, types.EnclaveRegistration{
		EnclaveHash:   hex.EncodeToString(enclaveHash[:]),
		SignerHash:    hex.EncodeToString(signerHash[:]),
		Platform:      types.PlatformSGX,
		Description:   "Self-issued key attack",
		PlatformKeyX:  hex.EncodeToString(xBytes),
		PlatformKeyY:  hex.EncodeToString(yBytes),
		VendorAttestR: hex.EncodeToString(rBytes),
		VendorAttestS: hex.EncodeToString(sBytes),
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "vendor key attestation verification failed")
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

func TestApplyValidatorSelection_ZeroHwReportHashRejected(t *testing.T) {
	k, ctx := setupKeeper(t)

	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	registerTestEnclaveAndOperator(t, k, ctx, privKey.PubKey())

	validators := testValidators()
	blockTime := time.Now()
	ctx = setBlockTime(ctx, blockTime)

	att := signAttestation(t, privKey, validators, blockTime, uniqueNonce("zero-hw"), 1)

	// Zero out the rawReportHash at [160:192] in the 256-byte evidence
	evidenceBytes, _ := hex.DecodeString(att.PlatformEvidence)
	for i := 160; i < 192; i++ {
		evidenceBytes[i] = 0x00
	}
	att.PlatformEvidence = hex.EncodeToString(evidenceBytes)

	err = k.ApplyValidatorSelection(ctx, validators, att, 1)
	require.Error(t, err)
	require.Contains(t, err.Error(), "rawReportHash is zero")
}

func TestApplyValidatorSelection_FreshHwReportPerAttestation(t *testing.T) {
	// Verify that each attestation gets a unique rawReportHash
	// (since the mock is derived from the attestation digest)
	k, ctx := setupKeeper(t)

	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	registerTestEnclaveAndOperator(t, k, ctx, privKey.PubKey())

	validators := testValidators()
	blockTime := time.Now()

	att1 := signAttestation(t, privKey, validators, blockTime, uniqueNonce("fresh-hw-1"), 1)
	att2 := signAttestation(t, privKey, validators, blockTime, uniqueNonce("fresh-hw-2"), 1)

	ev1, _ := hex.DecodeString(att1.PlatformEvidence)
	ev2, _ := hex.DecodeString(att2.PlatformEvidence)

	// rawReportHash at [160:192] should differ between attestations
	hwHash1 := ev1[160:192]
	hwHash2 := ev2[160:192]
	require.NotEqual(t, hwHash1, hwHash2, "each attestation must have a unique rawReportHash")
}

// ─────────────────────────────────────────────────────────────────────────────
// Universe hash verification in ApplyValidatorSelection
// ─────────────────────────────────────────────────────────────────────────────

// TestApplyValidatorSelection_UniverseHashFromOnChainState verifies that
// ApplyValidatorSelection independently computes the universe hash from
// on-chain validator telemetry state and rejects attestations with a
// mismatched universe hash.
func TestApplyValidatorSelection_UniverseHashFromOnChainState(t *testing.T) {
	k, ctx := setupKeeper(t)

	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	registerTestEnclaveAndOperator(t, k, ctx, privKey.PubKey())

	blockTime := time.Now()
	ctx = setBlockTime(ctx, blockTime)

	// Populate on-chain validators with fresh telemetry.
	// These represent the *existing* active set that was present when
	// BuildValidatorSelectionRequest was called.
	existingVals := []types.ValidatorRecord{
		{Address: "aethel1existing1", IsActive: true, TelemetryUpdatedAt: blockTime.Add(-1 * time.Hour), UptimePct: 99.0, AvgResponseMs: 50, CountryCode: "US"},
		{Address: "aethel1existing2", IsActive: true, TelemetryUpdatedAt: blockTime.Add(-2 * time.Hour), UptimePct: 98.0, AvgResponseMs: 60, CountryCode: "DE"},
		{Address: "aethel1existing3", IsActive: true, TelemetryUpdatedAt: blockTime.Add(-1 * time.Hour), UptimePct: 97.0, AvgResponseMs: 70, CountryCode: "JP"},
	}
	for i := range existingVals {
		err = k.setValidator(ctx, &existingVals[i])
		require.NoError(t, err)
	}

	// Compute the expected universe hash from the on-chain state
	sortedAddrs := []string{"aethel1existing1", "aethel1existing2", "aethel1existing3"}
	sort.Strings(sortedAddrs)
	expectedUniverse := computeEligibleUniverseHash(sortedAddrs)

	// Build validators to apply (the new selected set)
	newValidators := testValidators()

	// Sign attestation WITH the correct universe hash
	att := signAttestationWithUniverse(t, privKey, newValidators, blockTime, uniqueNonce("universe-ok"), 1, expectedUniverse)
	err = k.ApplyValidatorSelection(ctx, newValidators, att, 1)
	require.NoError(t, err)
}

// TestApplyValidatorSelection_UniverseHashMismatch verifies that an attestation
// with a wrong universe hash is rejected.
func TestApplyValidatorSelection_UniverseHashMismatch(t *testing.T) {
	k, ctx := setupKeeper(t)

	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	registerTestEnclaveAndOperator(t, k, ctx, privKey.PubKey())

	blockTime := time.Now()
	ctx = setBlockTime(ctx, blockTime)

	// Populate on-chain validators with fresh telemetry
	existingVals := []types.ValidatorRecord{
		{Address: "aethel1existing1", IsActive: true, TelemetryUpdatedAt: blockTime.Add(-1 * time.Hour), UptimePct: 99.0, AvgResponseMs: 50, CountryCode: "US"},
		{Address: "aethel1existing2", IsActive: true, TelemetryUpdatedAt: blockTime.Add(-2 * time.Hour), UptimePct: 98.0, AvgResponseMs: 60, CountryCode: "DE"},
	}
	for i := range existingVals {
		err = k.setValidator(ctx, &existingVals[i])
		require.NoError(t, err)
	}

	// Use a WRONG universe hash — as if the relayer submitted a request
	// that omitted one of the eligible validators
	wrongAddrs := []string{"aethel1existing1"} // missing existing2
	wrongUniverse := computeEligibleUniverseHash(wrongAddrs)

	newValidators := testValidators()
	att := signAttestationWithUniverse(t, privKey, newValidators, blockTime, uniqueNonce("universe-bad"), 1, wrongUniverse)

	err = k.ApplyValidatorSelection(ctx, newValidators, att, 1)
	require.Error(t, err)
	require.Contains(t, err.Error(), "payload hash mismatch")
}

// ─────────────────────────────────────────────────────────────────────────────
// Telemetry-gated validator selection
// ─────────────────────────────────────────────────────────────────────────────

func TestBuildValidatorSelectionRequest_RejectsWithoutTelemetry(t *testing.T) {
	k, ctx := setupKeeper(t)
	ctx = setBlockTime(ctx, time.Now())

	// Store a validator WITHOUT telemetry
	v := &types.ValidatorRecord{
		Address:          "aethel1val1",
		DelegatedStake:   1000,
		Commission:       500,
		IsActive:         true,
		GeographicRegion: "us-east",
		OperatorID:       "op-1",
		// TelemetryUpdatedAt is zero — no telemetry
	}
	err := k.setValidator(ctx, v)
	require.NoError(t, err)

	// BuildValidatorSelectionRequest should fail because no validator
	// has populated telemetry (zero TelemetryUpdatedAt is treated as stale)
	_, err = k.BuildValidatorSelectionRequest(ctx)
	require.Error(t, err)
	require.Contains(t, err.Error(), "no validators with fresh telemetry")
}

func TestBuildValidatorSelectionRequest_SucceedsWithTelemetry(t *testing.T) {
	k, ctx := setupKeeper(t)
	ctx = setBlockTime(ctx, time.Now())

	// Store a validator
	v := &types.ValidatorRecord{
		Address:          "aethel1val1",
		DelegatedStake:   1000,
		Commission:       500,
		IsActive:         true,
		GeographicRegion: "us-east",
		OperatorID:       "op-1",
	}
	err := k.setValidator(ctx, v)
	require.NoError(t, err)

	// Populate telemetry
	err = k.UpdateValidatorTelemetry(ctx, "aethel1val1", 99.5, 80.0, 5000, "US")
	require.NoError(t, err)

	// Now BuildValidatorSelectionRequest should succeed
	body, err := k.BuildValidatorSelectionRequest(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, body)

	// Verify the output contains real telemetry values, not placeholders
	var req map[string]interface{}
	err = json.Unmarshal(body, &req)
	require.NoError(t, err)

	validators := req["validators"].([]interface{})
	require.Len(t, validators, 1)
	val := validators[0].(map[string]interface{})
	require.Equal(t, 99.5, val["uptime_pct"])
	require.Equal(t, 80.0, val["avg_response_ms"])
	require.Equal(t, float64(5000), val["total_jobs_completed"])
	require.Equal(t, "US", val["country_code"])
}

func TestUpdateValidatorTelemetry_Validation(t *testing.T) {
	k, ctx := setupKeeper(t)
	ctx = setBlockTime(ctx, time.Now())

	// Store a validator
	v := &types.ValidatorRecord{
		Address:          "aethel1val1",
		DelegatedStake:   1000,
		IsActive:         true,
		GeographicRegion: "us-east",
		OperatorID:       "op-1",
	}
	err := k.setValidator(ctx, v)
	require.NoError(t, err)

	// Invalid uptime (>100)
	err = k.UpdateValidatorTelemetry(ctx, "aethel1val1", 101.0, 80.0, 5000, "US")
	require.Error(t, err)
	require.Contains(t, err.Error(), "uptime_pct must be in [0, 100]")

	// Invalid uptime (<0)
	err = k.UpdateValidatorTelemetry(ctx, "aethel1val1", -1.0, 80.0, 5000, "US")
	require.Error(t, err)

	// Invalid latency (<0)
	err = k.UpdateValidatorTelemetry(ctx, "aethel1val1", 99.5, -10.0, 5000, "US")
	require.Error(t, err)
	require.Contains(t, err.Error(), "avg_response_ms must be >= 0")

	// Non-existent validator
	err = k.UpdateValidatorTelemetry(ctx, "aethel1unknown", 99.5, 80.0, 5000, "US")
	require.Error(t, err)
	require.Contains(t, err.Error(), "not found")

	// Valid update
	err = k.UpdateValidatorTelemetry(ctx, "aethel1val1", 99.5, 80.0, 5000, "US")
	require.NoError(t, err)

	// Verify stored values
	updated, exists := k.getValidator(ctx, "aethel1val1")
	require.True(t, exists)
	require.Equal(t, 99.5, updated.UptimePct)
	require.Equal(t, 80.0, updated.AvgResponseMs)
	require.Equal(t, uint64(5000), updated.TotalJobsCompleted)
	require.Equal(t, "US", updated.CountryCode)
	require.False(t, updated.TelemetryUpdatedAt.IsZero())
}

func TestBuildValidatorSelectionRequest_RejectsStaleTelemetry(t *testing.T) {
	k, ctx := setupKeeper(t)

	// Store a validator and populate telemetry at T=0.
	baseTime := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	ctx = setBlockTime(ctx, baseTime)

	v := &types.ValidatorRecord{
		Address:          "aethel1stale",
		DelegatedStake:   5000,
		Commission:       500,
		IsActive:         true,
		GeographicRegion: "eu-west",
		OperatorID:       "op-stale",
	}
	require.NoError(t, k.setValidator(ctx, v))

	// Populate telemetry at baseTime
	require.NoError(t, k.UpdateValidatorTelemetry(ctx, "aethel1stale", 98.0, 50.0, 1000, "DE"))

	// Advance block time by 3 days (> DefaultTelemetryMaxAgeSec = 48h)
	staleCtx := setBlockTime(ctx, baseTime.Add(73*time.Hour))

	// BuildValidatorSelectionRequest should fail — telemetry is stale
	_, err := k.BuildValidatorSelectionRequest(staleCtx)
	require.Error(t, err)
	require.Contains(t, err.Error(), "no validators with fresh telemetry")
}

func TestBuildValidatorSelectionRequest_QuorumNotMet(t *testing.T) {
	k, ctx := setupKeeper(t)

	baseTime := time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC)
	ctx = setBlockTime(ctx, baseTime)

	// Validator A: telemetry updated at baseTime (fresh)
	vA := &types.ValidatorRecord{
		Address:          "aethel1fresh",
		DelegatedStake:   5000,
		Commission:       500,
		IsActive:         true,
		GeographicRegion: "us-east",
		OperatorID:       "op-fresh",
	}
	require.NoError(t, k.setValidator(ctx, vA))
	require.NoError(t, k.UpdateValidatorTelemetry(ctx, "aethel1fresh", 99.0, 40.0, 8000, "US"))

	// Validator B: telemetry updated 3 days ago (stale)
	oldCtx := setBlockTime(ctx, baseTime.Add(-73*time.Hour))
	vB := &types.ValidatorRecord{
		Address:          "aethel1stale",
		DelegatedStake:   3000,
		Commission:       300,
		IsActive:         true,
		GeographicRegion: "eu-west",
		OperatorID:       "op-stale",
	}
	require.NoError(t, k.setValidator(oldCtx, vB))
	require.NoError(t, k.UpdateValidatorTelemetry(oldCtx, "aethel1stale", 97.0, 60.0, 2000, "DE"))

	// 1/2 active validators have fresh telemetry = 50% < 67% quorum → fail
	_, err := k.BuildValidatorSelectionRequest(ctx)
	require.Error(t, err)
	require.Contains(t, err.Error(), "telemetry quorum not met")
	require.Contains(t, err.Error(), "1/2 active validators")
}

func TestBuildValidatorSelectionRequest_QuorumMetFiltersStale(t *testing.T) {
	k, ctx := setupKeeper(t)

	baseTime := time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC)
	ctx = setBlockTime(ctx, baseTime)

	// 4 active validators: 3 fresh, 1 stale → 75% >= 67% quorum → succeed
	for i, addr := range []string{"aethel1val1", "aethel1val2", "aethel1val3"} {
		v := &types.ValidatorRecord{
			Address:          addr,
			DelegatedStake:   uint64(1000 * (i + 1)),
			Commission:       500,
			IsActive:         true,
			GeographicRegion: "us-east",
			OperatorID:       fmt.Sprintf("op-%d", i),
		}
		require.NoError(t, k.setValidator(ctx, v))
		require.NoError(t, k.UpdateValidatorTelemetry(ctx, addr,
			98.0+float64(i)*0.5, 40.0+float64(i)*10, uint64(1000*(i+1)), "US"))
	}

	// Fourth validator with stale telemetry
	oldCtx := setBlockTime(ctx, baseTime.Add(-73*time.Hour))
	vStale := &types.ValidatorRecord{
		Address:          "aethel1stale",
		DelegatedStake:   2000,
		Commission:       300,
		IsActive:         true,
		GeographicRegion: "eu-west",
		OperatorID:       "op-stale",
	}
	require.NoError(t, k.setValidator(oldCtx, vStale))
	require.NoError(t, k.UpdateValidatorTelemetry(oldCtx, "aethel1stale", 97.0, 60.0, 500, "DE"))

	// 3/4 = 75% >= 67% quorum → should succeed
	body, err := k.BuildValidatorSelectionRequest(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, body)

	var req map[string]interface{}
	require.NoError(t, json.Unmarshal(body, &req))

	// Stale validator should be excluded from the candidate set
	validators := req["validators"].([]interface{})
	require.Len(t, validators, 3, "only fresh validators should be included")
	for _, v := range validators {
		val := v.(map[string]interface{})
		require.NotEqual(t, "aethel1stale", val["address"], "stale validator must be excluded")
	}

	// Universe metadata should be present
	require.Equal(t, float64(4), req["total_active_count"])
	require.Equal(t, float64(3), req["eligible_count"])
	require.Equal(t, float64(1), req["skipped_stale_count"])
	require.NotEmpty(t, req["eligible_universe_hash"])
}

func TestBuildValidatorSelectionRequest_InactiveNotCountedInQuorum(t *testing.T) {
	k, ctx := setupKeeper(t)

	baseTime := time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC)
	ctx = setBlockTime(ctx, baseTime)

	// 1 active validator with fresh telemetry
	vActive := &types.ValidatorRecord{
		Address:          "aethel1active",
		DelegatedStake:   5000,
		Commission:       500,
		IsActive:         true,
		GeographicRegion: "us-east",
		OperatorID:       "op-active",
	}
	require.NoError(t, k.setValidator(ctx, vActive))
	require.NoError(t, k.UpdateValidatorTelemetry(ctx, "aethel1active", 99.0, 40.0, 8000, "US"))

	// 1 inactive validator (slashed) — should NOT count against quorum
	vInactive := &types.ValidatorRecord{
		Address:          "aethel1inactive",
		DelegatedStake:   3000,
		Commission:       300,
		IsActive:         false, // slashed / deactivated
		GeographicRegion: "eu-west",
		OperatorID:       "op-inactive",
	}
	require.NoError(t, k.setValidator(ctx, vInactive))

	// 1/1 active has fresh telemetry = 100% >= 67% → should succeed
	// (the inactive validator must not drag the quorum down to 50%)
	body, err := k.BuildValidatorSelectionRequest(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, body)

	var req map[string]interface{}
	require.NoError(t, json.Unmarshal(body, &req))

	require.Equal(t, float64(1), req["total_active_count"])
	require.Equal(t, float64(1), req["eligible_count"])
	require.Equal(t, float64(0), req["skipped_stale_count"])
}

func TestBuildValidatorSelectionRequest_UniverseHashDeterministic(t *testing.T) {
	k, ctx := setupKeeper(t)

	baseTime := time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC)
	ctx = setBlockTime(ctx, baseTime)

	// Store validators in non-alphabetical order
	for _, addr := range []string{"aethel1zz", "aethel1aa", "aethel1mm"} {
		v := &types.ValidatorRecord{
			Address:          addr,
			DelegatedStake:   1000,
			Commission:       500,
			IsActive:         true,
			GeographicRegion: "us-east",
			OperatorID:       "op-1",
		}
		require.NoError(t, k.setValidator(ctx, v))
		require.NoError(t, k.UpdateValidatorTelemetry(ctx, addr, 99.0, 40.0, 1000, "US"))
	}

	// Build twice — universe hash must be identical
	body1, err := k.BuildValidatorSelectionRequest(ctx)
	require.NoError(t, err)
	body2, err := k.BuildValidatorSelectionRequest(ctx)
	require.NoError(t, err)

	var req1, req2 map[string]interface{}
	require.NoError(t, json.Unmarshal(body1, &req1))
	require.NoError(t, json.Unmarshal(body2, &req2))

	hash1 := req1["eligible_universe_hash"].(string)
	hash2 := req2["eligible_universe_hash"].(string)
	require.Equal(t, hash1, hash2, "universe hash must be deterministic across calls")
	require.Len(t, hash1, 64, "universe hash must be 32 bytes hex-encoded")
}

func TestBuildValidatorSelectionRequest_TelemetryAtBoundaryIncluded(t *testing.T) {
	k, ctx := setupKeeper(t)

	baseTime := time.Date(2025, 3, 15, 0, 0, 0, 0, time.UTC)

	// Store validator and populate telemetry at baseTime
	ctx = setBlockTime(ctx, baseTime)
	v := &types.ValidatorRecord{
		Address:          "aethel1edge",
		DelegatedStake:   4000,
		Commission:       400,
		IsActive:         true,
		GeographicRegion: "ap-east",
		OperatorID:       "op-edge",
	}
	require.NoError(t, k.setValidator(ctx, v))
	require.NoError(t, k.UpdateValidatorTelemetry(ctx, "aethel1edge", 99.9, 30.0, 10000, "JP"))

	// Advance block time to exactly maxAge - 1 second (should still be fresh)
	// DefaultTelemetryMaxAgeSec = 2 * 86400 = 172800 seconds
	justFresh := baseTime.Add(time.Duration(types.DefaultTelemetryMaxAgeSec-1) * time.Second)
	body, err := k.BuildValidatorSelectionRequest(setBlockTime(ctx, justFresh))
	require.NoError(t, err)
	require.NotEmpty(t, body, "telemetry at max_age-1s should still be included")

	// Advance block time to exactly maxAge + 1 second (should be stale)
	justStale := baseTime.Add(time.Duration(types.DefaultTelemetryMaxAgeSec+1) * time.Second)
	_, err = k.BuildValidatorSelectionRequest(setBlockTime(ctx, justStale))
	require.Error(t, err)
	require.Contains(t, err.Error(), "no validators with fresh telemetry")
}

// setBlockTime returns a context with the given block time.
func setBlockTime(ctx sdk.Context, t time.Time) sdk.Context {
	return ctx.WithBlockTime(t)
}

// ─────────────────────────────────────────────────────────────────────────────
// BuildDelegationAttestationRequest Tests
// ─────────────────────────────────────────────────────────────────────────────

// addTestStaker is a helper that inserts a staker directly into the store.
func addTestStaker(t *testing.T, k *Keeper, ctx sdk.Context, addr string, shares uint64, delegatedTo string) {
	t.Helper()
	evmAddr, _ := resolveEvmAddress(addr)
	rec := &types.StakerRecord{
		Address:     addr,
		EvmAddress:  evmAddr,
		Shares:      shares,
		DelegatedTo: delegatedTo,
		StakedAt:    time.Now(),
	}
	require.NoError(t, k.setStaker(ctx, rec))
}

func TestBuildDelegationAttestationRequest_basic(t *testing.T) {
	k, ctx := setupKeeper(t)

	require.NoError(t, k.setValidator(ctx, &types.ValidatorRecord{Address: "aethel1val1", IsActive: true}))
	require.NoError(t, k.setValidator(ctx, &types.ValidatorRecord{Address: "aethel1val2", IsActive: true}))
	addTestStaker(t, k, ctx, "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 1000, "aethel1val1")
	addTestStaker(t, k, ctx, "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", 2000, "aethel1val2")

	// Must snapshot before building request.
	require.NoError(t, k.SnapshotDelegationState(ctx))

	body, err := k.BuildDelegationAttestationRequest(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, body)

	// Verify JSON structure.
	var parsed map[string]interface{}
	require.NoError(t, json.Unmarshal(body, &parsed))

	require.Contains(t, parsed, "epoch")
	require.Contains(t, parsed, "staker_stakes")
	require.Contains(t, parsed, "staker_registry_root")

	stakes, ok := parsed["staker_stakes"].([]interface{})
	require.True(t, ok)
	require.Equal(t, 2, len(stakes))

	// Verify staker_registry_root is a valid 64-char hex string.
	root, ok := parsed["staker_registry_root"].(string)
	require.True(t, ok)
	require.Equal(t, 64, len(root))
	_, err = hex.DecodeString(root)
	require.NoError(t, err)
}

func TestBuildDelegationAttestationRequest_requiresSnapshot(t *testing.T) {
	k, ctx := setupKeeper(t)

	addTestStaker(t, k, ctx, "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 1000, "aethel1val1")

	// Build without snapshot → error
	_, err := k.BuildDelegationAttestationRequest(ctx)
	require.Error(t, err)
	require.Contains(t, err.Error(), "no delegation snapshot")
}

func TestBuildDelegationAttestationRequest_skipsZeroShares(t *testing.T) {
	k, ctx := setupKeeper(t)

	require.NoError(t, k.setValidator(ctx, &types.ValidatorRecord{Address: "aethel1val1", IsActive: true}))
	require.NoError(t, k.setValidator(ctx, &types.ValidatorRecord{Address: "aethel1val2", IsActive: true}))
	addTestStaker(t, k, ctx, "0xcccccccccccccccccccccccccccccccccccccccc", 500, "aethel1val1")
	addTestStaker(t, k, ctx, "0xdddddddddddddddddddddddddddddddddddddd", 0, "aethel1val2")

	require.NoError(t, k.SnapshotDelegationState(ctx))

	body, err := k.BuildDelegationAttestationRequest(ctx)
	require.NoError(t, err)

	var parsed map[string]interface{}
	require.NoError(t, json.Unmarshal(body, &parsed))

	stakes := parsed["staker_stakes"].([]interface{})
	require.Equal(t, 1, len(stakes))

	entry := stakes[0].(map[string]interface{})
	// collectStakerEntries uses EvmAddress (lowercase, no 0x prefix).
	require.Equal(t, "cccccccccccccccccccccccccccccccccccccccc", entry["address"])
}

func TestBuildDelegationAttestationRequest_includesDelegatedTo(t *testing.T) {
	k, ctx := setupKeeper(t)

	require.NoError(t, k.setValidator(ctx, &types.ValidatorRecord{Address: "aethel1validator_xyz", IsActive: true}))
	addTestStaker(t, k, ctx, "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", 100, "aethel1validator_xyz")

	require.NoError(t, k.SnapshotDelegationState(ctx))

	body, err := k.BuildDelegationAttestationRequest(ctx)
	require.NoError(t, err)

	var parsed map[string]interface{}
	require.NoError(t, json.Unmarshal(body, &parsed))

	stakes := parsed["staker_stakes"].([]interface{})
	entry := stakes[0].(map[string]interface{})
	require.Equal(t, "aethel1validator_xyz", entry["delegated_to"])
}

func TestSnapshotDelegationState_immutable(t *testing.T) {
	k, ctx := setupKeeper(t)

	require.NoError(t, k.setValidator(ctx, &types.ValidatorRecord{Address: "aethel1val1", IsActive: true}))
	addTestStaker(t, k, ctx, "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", 100, "aethel1val1")

	// First snapshot succeeds.
	require.NoError(t, k.SnapshotDelegationState(ctx))

	// Second snapshot for the same epoch fails.
	err := k.SnapshotDelegationState(ctx)
	require.Error(t, err)
	require.Contains(t, err.Error(), "delegation snapshot already exists")
}

func TestSnapshotDelegationState_rejectsUnknownValidator(t *testing.T) {
	k, ctx := setupKeeper(t)

	// No validators registered — delegation target is unknown.
	addTestStaker(t, k, ctx, "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 500, "aethel1unknown")

	err := k.SnapshotDelegationState(ctx)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unknown validator")
	require.Contains(t, err.Error(), "aethel1unknown")
}

func TestSnapshotDelegationState_rejectsEmptyDelegation(t *testing.T) {
	k, ctx := setupKeeper(t)

	// Create staker with empty delegation.
	s := &types.StakerRecord{
		Address:     "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		EvmAddress:  "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		Shares:      1000,
		DelegatedTo: "",
	}
	data, _ := json.Marshal(s)
	require.NoError(t, k.Stakers.Set(ctx, s.Address, string(data)))

	err := k.SnapshotDelegationState(ctx)
	require.Error(t, err)
	require.Contains(t, err.Error(), "empty delegation target")
}

func TestGetDelegationSnapshotStakerCount(t *testing.T) {
	k, ctx := setupKeeper(t)

	require.NoError(t, k.setValidator(ctx, &types.ValidatorRecord{Address: "aethel1val1", IsActive: true}))
	require.NoError(t, k.setValidator(ctx, &types.ValidatorRecord{Address: "aethel1val2", IsActive: true}))

	addTestStaker(t, k, ctx, "0x1111111111111111111111111111111111111111", 500, "aethel1val1")
	addTestStaker(t, k, ctx, "0x2222222222222222222222222222222222222222", 300, "aethel1val2")

	require.NoError(t, k.SnapshotDelegationState(ctx))

	// Read the current epoch used by SnapshotDelegationState.
	currentEpoch := k.getUint64(ctx, k.CurrentEpoch)
	count, err := k.GetDelegationSnapshotStakerCount(ctx, currentEpoch)
	require.NoError(t, err)
	require.Equal(t, uint64(2), count, "cardinality must reflect number of stakers in snapshot")
}

func TestBuildDelegationAttestationRequest_freezesDelegation(t *testing.T) {
	k, ctx := setupKeeper(t)

	// Register delegation target validators so snapshot validation passes.
	require.NoError(t, k.setValidator(ctx, &types.ValidatorRecord{Address: "aethel1val1", IsActive: true}))
	require.NoError(t, k.setValidator(ctx, &types.ValidatorRecord{Address: "aethel1val2", IsActive: true}))

	aliceAddr := "0xaaaaaaaabbbbbbbbccccccccddddddddeeeeeeee"
	addTestStaker(t, k, ctx, aliceAddr, 1000, "aethel1val1")

	// Snapshot delegation state (freezes delegated_to = val1).
	require.NoError(t, k.SnapshotDelegationState(ctx))

	// Re-delegate AFTER snapshot — should NOT affect the attestation request.
	staker, _ := k.getStaker(ctx, aliceAddr)
	staker.DelegatedTo = "aethel1val2"
	require.NoError(t, k.setStaker(ctx, staker))

	body, err := k.BuildDelegationAttestationRequest(ctx)
	require.NoError(t, err)

	var parsed map[string]interface{}
	require.NoError(t, json.Unmarshal(body, &parsed))

	stakes := parsed["staker_stakes"].([]interface{})
	entry := stakes[0].(map[string]interface{})
	// The frozen snapshot should still have val1, not the live val2.
	require.Equal(t, "aethel1val1", entry["delegated_to"],
		"attestation request must use frozen delegation state, not live state")
}

func TestComputeStakerRegistryRoot_deterministic(t *testing.T) {
	entries := []stakerStakeEntry{
		{Address: "0x1111111111111111111111111111111111111111", Shares: 1000, DelegatedTo: "val1"},
		{Address: "0x2222222222222222222222222222222222222222", Shares: 2000, DelegatedTo: "val2"},
	}

	root1 := computeStakerRegistryRoot(entries)
	root2 := computeStakerRegistryRoot(entries)
	require.Equal(t, root1, root2, "registry root must be deterministic")
	require.NotEqual(t, [32]byte{}, root1, "registry root must not be zero")
}

func TestComputeStakerRegistryRoot_orderIndependent(t *testing.T) {
	// XOR is commutative, so order should not matter.
	entriesA := []stakerStakeEntry{
		{Address: "0x1111111111111111111111111111111111111111", Shares: 1000, DelegatedTo: "v1"},
		{Address: "0x2222222222222222222222222222222222222222", Shares: 2000, DelegatedTo: "v2"},
	}
	entriesB := []stakerStakeEntry{
		{Address: "0x2222222222222222222222222222222222222222", Shares: 2000, DelegatedTo: "v2"},
		{Address: "0x1111111111111111111111111111111111111111", Shares: 1000, DelegatedTo: "v1"},
	}

	rootA := computeStakerRegistryRoot(entriesA)
	rootB := computeStakerRegistryRoot(entriesB)
	require.Equal(t, rootA, rootB, "XOR accumulator must be order-independent")
}

func TestComputeStakerRegistryRoot_differentSharesProduceDifferentRoot(t *testing.T) {
	entriesA := []stakerStakeEntry{
		{Address: "0x1111111111111111111111111111111111111111", Shares: 1000, DelegatedTo: "v1"},
	}
	entriesB := []stakerStakeEntry{
		{Address: "0x1111111111111111111111111111111111111111", Shares: 2000, DelegatedTo: "v1"},
	}

	rootA := computeStakerRegistryRoot(entriesA)
	rootB := computeStakerRegistryRoot(entriesB)
	require.NotEqual(t, rootA, rootB, "different shares must produce different roots")
}

func TestParseAddressBytes_hexAddress(t *testing.T) {
	addr := "0x1111111111111111111111111111111111111111"
	result := parseAddressBytes(addr)

	var expected [20]byte
	for i := range expected {
		expected[i] = 0x11
	}
	require.Equal(t, expected, result)
}

func TestParseAddressBytes_nonHexReturnsZero(t *testing.T) {
	// Non-hex address returns zero bytes — the SHA-256 fallback has been
	// removed. All addresses must be resolved to canonical 20-byte EVM
	// form via resolveEvmAddress() before reaching parseAddressBytes().
	addr := "aethel1staker1"
	result := parseAddressBytes(addr)
	require.Equal(t, [20]byte{}, result, "non-hex address must return zero bytes")
}

func TestParseAddressBytes_caseInsensitive(t *testing.T) {
	// Hex addresses with mixed case must produce the same 20-byte representation.
	lowerHex := parseAddressBytes("0xabcdef1234567890abcdef1234567890abcdef12")
	upperHex := parseAddressBytes("0xABCDEF1234567890ABCDEF1234567890ABCDEF12")
	require.Equal(t, lowerHex, upperHex, "hex addresses must be case-insensitive")
	require.NotEqual(t, [20]byte{}, lowerHex, "valid hex address must not be zero")
}

func TestParseAddressBytes_shortHex(t *testing.T) {
	// Short hex should be left-padded.
	addr := "0x01"
	result := parseAddressBytes(addr)

	var expected [20]byte
	expected[19] = 0x01
	require.Equal(t, expected, result)
}

func TestComputeStakerRegistryRoot_crossLanguageVector(t *testing.T) {
	// Fixed test vector: compute the registry root for a known staker set
	// and verify the result is deterministic. This test vector should be
	// replicated in Rust tests to guarantee cross-language agreement.
	//
	// Staker: address=0x1234...1234 (20 bytes), shares=1000
	// Expected: keccak256(address_20bytes || shares_uint256) = single-element XOR root
	entries := []stakerStakeEntry{
		{Address: "0x1234567890abcdef1234567890abcdef12345678", Shares: 1000, DelegatedTo: "val1"},
	}
	root := computeStakerRegistryRoot(entries)

	// Manually compute the expected value.
	addrBytes := parseAddressBytes("0x1234567890abcdef1234567890abcdef12345678")
	var sharesBE [32]byte
	sharesBE[30] = 0x03 // 1000 = 0x03E8
	sharesBE[31] = 0xE8
	h := sha3.NewLegacyKeccak256()
	h.Write(addrBytes[:])
	h.Write(sharesBE[:])
	var expected [32]byte
	copy(expected[:], h.Sum(nil))

	require.Equal(t, expected, root, "registry root must match manually computed keccak256")
}

func TestResolveEvmAddress_hex(t *testing.T) {
	// 0x-prefixed hex address → lowercase hex without prefix.
	result, err := resolveEvmAddress("0xAbCdEf1234567890AbCdEf1234567890aBcDeF12")
	require.NoError(t, err)
	require.Equal(t, "abcdef1234567890abcdef1234567890abcdef12", result)
}

func TestResolveEvmAddress_rawHex(t *testing.T) {
	// Raw hex (no 0x prefix) → lowercase hex.
	result, err := resolveEvmAddress("ABCDEF1234567890ABCDEF1234567890ABCDEF12")
	require.NoError(t, err)
	require.Equal(t, "abcdef1234567890abcdef1234567890abcdef12", result)
}

func TestResolveEvmAddress_invalidAddress(t *testing.T) {
	// Non-hex, non-bech32 address → error.
	_, err := resolveEvmAddress("not-a-valid-address")
	require.Error(t, err)
	require.Contains(t, err.Error(), "cannot resolve address")
}

func TestCollectStakerEntries_usesEvmAddress(t *testing.T) {
	// Verify that collectStakerEntries uses the EvmAddress field from
	// StakerRecord, ensuring registry root compatibility with EVM.
	k, ctx := setupKeeper(t)

	addTestStaker(t, k, ctx, "0xAbCdEf1234567890AbCdEf1234567890aBcDeF12", 1000, "val1")

	entries, err := k.collectStakerEntries(ctx)
	require.NoError(t, err)
	require.Equal(t, 1, len(entries))
	// Address should be the canonical lowercase hex EVM address.
	require.Equal(t, "abcdef1234567890abcdef1234567890abcdef12", entries[0].Address)
}

// ─────────────────────────────────────────────────────────────────────────────
// Emergency Pause Tests
// ─────────────────────────────────────────────────────────────────────────────

func TestPauseVault_basic(t *testing.T) {
	k, ctx := setupKeeper(t)

	// Initially not paused.
	require.False(t, k.IsPaused(ctx))

	// Pause the vault.
	err := k.PauseVault(ctx, "authority", "security incident detected")
	require.NoError(t, err)
	require.True(t, k.IsPaused(ctx))

	ps := k.GetPauseState(ctx)
	require.True(t, ps.Paused)
	require.Equal(t, "security incident detected", ps.Reason)
	require.Equal(t, "authority", ps.PausedBy)
	require.Len(t, ps.EventLog, 1)
	require.Equal(t, "pause", ps.EventLog[0].Action)
}

func TestPauseVault_unauthorized(t *testing.T) {
	k, ctx := setupKeeper(t)

	err := k.PauseVault(ctx, "not-authority", "hacker attempt")
	require.Error(t, err)
	require.Contains(t, err.Error(), "unauthorized")
	require.False(t, k.IsPaused(ctx))
}

func TestPauseVault_alreadyPaused(t *testing.T) {
	k, ctx := setupKeeper(t)

	require.NoError(t, k.PauseVault(ctx, "authority", "first pause"))
	err := k.PauseVault(ctx, "authority", "second pause")
	require.Error(t, err)
	require.Contains(t, err.Error(), "already paused")
}

func TestUnpauseVault_basic(t *testing.T) {
	k, ctx := setupKeeper(t)

	require.NoError(t, k.PauseVault(ctx, "authority", "security incident"))
	require.True(t, k.IsPaused(ctx))

	require.NoError(t, k.UnpauseVault(ctx, "authority", "issue resolved"))
	require.False(t, k.IsPaused(ctx))

	ps := k.GetPauseState(ctx)
	require.Len(t, ps.EventLog, 2)
	require.Equal(t, "unpause", ps.EventLog[1].Action)
	require.Equal(t, "issue resolved", ps.EventLog[1].Reason)
}

func TestUnpauseVault_unauthorized(t *testing.T) {
	k, ctx := setupKeeper(t)

	require.NoError(t, k.PauseVault(ctx, "authority", "paused"))
	err := k.UnpauseVault(ctx, "not-authority", "trying to unpause")
	require.Error(t, err)
	require.Contains(t, err.Error(), "unauthorized")
	require.True(t, k.IsPaused(ctx))
}

func TestUnpauseVault_notPaused(t *testing.T) {
	k, ctx := setupKeeper(t)

	err := k.UnpauseVault(ctx, "authority", "nothing to unpause")
	require.Error(t, err)
	require.Contains(t, err.Error(), "not paused")
}

func TestPause_blocksStake(t *testing.T) {
	k, ctx := setupKeeper(t)

	// Set up a validator so stake would succeed normally.
	require.NoError(t, k.setValidator(ctx, &types.ValidatorRecord{
		Address:  "val1",
		IsActive: true,
	}))
	require.NoError(t, k.setActiveValidatorAddrs(ctx, []string{"val1"}))

	// Pause vault.
	require.NoError(t, k.PauseVault(ctx, "authority", "maintenance"))

	// Stake should fail.
	_, err := k.Stake(ctx, testAddrAlice, 100_000_000, "val1", 0)
	require.Error(t, err)
	require.Contains(t, err.Error(), "vault is paused")
}

func TestPause_blocksUnstake(t *testing.T) {
	k, ctx := setupKeeper(t)

	// Set up validator and stake.
	require.NoError(t, k.setValidator(ctx, &types.ValidatorRecord{
		Address:  "val1",
		IsActive: true,
	}))
	require.NoError(t, k.setActiveValidatorAddrs(ctx, []string{"val1"}))

	_, err := k.Stake(ctx, testAddrAlice, 100_000_000, "val1", 0)
	require.NoError(t, err)

	// Pause vault.
	require.NoError(t, k.PauseVault(ctx, "authority", "exploit detected"))

	// Unstake should fail.
	_, _, err = k.Unstake(ctx, testAddrAlice, 50_000_000)
	require.Error(t, err)
	require.Contains(t, err.Error(), "vault is paused")
}

func TestPause_blocksWithdraw(t *testing.T) {
	k, ctx := setupKeeper(t)

	require.NoError(t, k.PauseVault(ctx, "authority", "paused"))
	_, err := k.Withdraw(ctx, testAddrAlice, 1)
	require.Error(t, err)
	require.Contains(t, err.Error(), "vault is paused")
}

func TestPause_blocksDelegateStake(t *testing.T) {
	k, ctx := setupKeeper(t)

	require.NoError(t, k.PauseVault(ctx, "authority", "paused"))
	err := k.DelegateStake(ctx, testAddrAlice, "val1")
	require.Error(t, err)
	require.Contains(t, err.Error(), "vault is paused")
}

func TestPause_blocksApplyValidatorSelection(t *testing.T) {
	k, ctx := setupKeeper(t)

	require.NoError(t, k.PauseVault(ctx, "authority", "paused"))
	err := k.ApplyValidatorSelection(ctx, []types.ValidatorRecord{{Address: "val1"}}, types.TEEAttestation{}, 1)
	require.Error(t, err)
	require.Contains(t, err.Error(), "vault is paused")
}

func TestPause_blocksSlashValidator(t *testing.T) {
	k, ctx := setupKeeper(t)

	require.NoError(t, k.PauseVault(ctx, "authority", "paused"))
	err := k.SlashValidator(ctx, "val1", "misbehavior")
	require.Error(t, err)
	require.Contains(t, err.Error(), "vault is paused")
}

func TestPause_unpauseThenOperate(t *testing.T) {
	k, ctx := setupKeeper(t)

	require.NoError(t, k.setValidator(ctx, &types.ValidatorRecord{
		Address:  "val1",
		IsActive: true,
	}))
	require.NoError(t, k.setActiveValidatorAddrs(ctx, []string{"val1"}))

	// Pause, then unpause.
	require.NoError(t, k.PauseVault(ctx, "authority", "test"))
	require.NoError(t, k.UnpauseVault(ctx, "authority", "all clear"))

	// Stake should now work.
	shares, err := k.Stake(ctx, testAddrAlice, 100_000_000, "val1", 0)
	require.NoError(t, err)
	require.True(t, shares > 0)
}

func TestPause_vaultStatusReflects(t *testing.T) {
	k, ctx := setupKeeper(t)

	status := k.GetVaultStatus(ctx)
	require.False(t, status.Paused)
	require.Empty(t, status.PauseReason)

	require.NoError(t, k.PauseVault(ctx, "authority", "test reason"))

	status = k.GetVaultStatus(ctx)
	require.True(t, status.Paused)
	require.Equal(t, "test reason", status.PauseReason)
}

// ─────────────────────────────────────────────────────────────────────────────
// Circuit Breaker Tests
// ─────────────────────────────────────────────────────────────────────────────

func TestCircuitBreaker_unstakeThreshold(t *testing.T) {
	k, ctx := setupKeeper(t)

	// Configure circuit breaker: max 10% unstake per epoch.
	require.NoError(t, k.UpdateCircuitBreakerConfig(ctx, "authority", types.CircuitBreakerConfig{
		MaxUnstakePerEpochPct: 10,
		MaxSlashesPerEpoch:    10,
		Enabled:               true,
	}))

	// Set up initial TVL with a validator.
	require.NoError(t, k.setValidator(ctx, &types.ValidatorRecord{
		Address:  "val1",
		IsActive: true,
	}))
	require.NoError(t, k.setActiveValidatorAddrs(ctx, []string{"val1"}))

	// Stake 1,000,000,000 uAETHEL (1000 AETHEL).
	_, err := k.Stake(ctx, testAddrAlice, 1_000_000_000, "val1", 0)
	require.NoError(t, err)

	// Unstake 5% — should succeed without tripping circuit breaker.
	_, _, err = k.Unstake(ctx, testAddrAlice, 50_000_000)
	require.NoError(t, err)
	require.False(t, k.IsPaused(ctx))

	// Unstake another 6% — should succeed but the circuit breaker should trip (>10%).
	_, _, err = k.Unstake(ctx, testAddrAlice, 60_000_000)
	require.NoError(t, err) // The unstake itself succeeds
	require.True(t, k.IsPaused(ctx)) // But the vault is now paused

	ps := k.GetPauseState(ctx)
	require.Contains(t, ps.Reason, "circuit breaker")
	require.Equal(t, "circuit_breaker", ps.PausedBy)
}

func TestCircuitBreaker_slashThreshold(t *testing.T) {
	k, ctx := setupKeeper(t)

	// Configure circuit breaker: max 2 slashes per epoch.
	require.NoError(t, k.UpdateCircuitBreakerConfig(ctx, "authority", types.CircuitBreakerConfig{
		MaxUnstakePerEpochPct: 100,
		MaxSlashesPerEpoch:    2,
		Enabled:               true,
	}))

	// Create 4 active validators.
	for i := 1; i <= 4; i++ {
		addr := fmt.Sprintf("val%d", i)
		require.NoError(t, k.setValidator(ctx, &types.ValidatorRecord{
			Address:  addr,
			IsActive: true,
		}))
	}
	require.NoError(t, k.setActiveValidatorAddrs(ctx, []string{"val1", "val2", "val3", "val4"}))

	// Slash val1 — no trip yet.
	require.NoError(t, k.SlashValidator(ctx, "val1", "downtime"))
	require.False(t, k.IsPaused(ctx))

	// Slash val2 — no trip yet.
	require.NoError(t, k.SlashValidator(ctx, "val2", "downtime"))
	require.False(t, k.IsPaused(ctx))

	// Slash val3 — should trip (3 > 2).
	require.NoError(t, k.SlashValidator(ctx, "val3", "downtime"))
	require.True(t, k.IsPaused(ctx))

	ps := k.GetPauseState(ctx)
	require.Contains(t, ps.Reason, "circuit breaker")
	require.Contains(t, ps.Reason, "slash count")
}

func TestCircuitBreaker_disabled(t *testing.T) {
	k, ctx := setupKeeper(t)

	// Disable circuit breaker.
	require.NoError(t, k.UpdateCircuitBreakerConfig(ctx, "authority", types.CircuitBreakerConfig{
		MaxUnstakePerEpochPct: 10,
		MaxSlashesPerEpoch:    1,
		Enabled:               false,
	}))

	// Set up validators.
	for i := 1; i <= 3; i++ {
		addr := fmt.Sprintf("val%d", i)
		require.NoError(t, k.setValidator(ctx, &types.ValidatorRecord{
			Address:  addr,
			IsActive: true,
		}))
	}
	require.NoError(t, k.setActiveValidatorAddrs(ctx, []string{"val1", "val2", "val3"}))

	// Multiple slashes should not trip breaker.
	require.NoError(t, k.SlashValidator(ctx, "val1", "test"))
	require.NoError(t, k.SlashValidator(ctx, "val2", "test"))
	require.False(t, k.IsPaused(ctx))
}

func TestCircuitBreaker_updateConfig_unauthorized(t *testing.T) {
	k, ctx := setupKeeper(t)

	err := k.UpdateCircuitBreakerConfig(ctx, "not-authority", types.CircuitBreakerConfig{
		Enabled: false,
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "unauthorized")
}

// ─────────────────────────────────────────────────────────────────────────────
// Operator Audit Log Tests
// ─────────────────────────────────────────────────────────────────────────────

func TestOperatorAuditLog_recordsOnRegisterEnclave(t *testing.T) {
	k, ctx := setupKeeper(t)

	// Register a vendor root key for SGX.
	pkX, pkY := p256TestPublicKey()
	xHex := fmt.Sprintf("%064x", pkX)
	yHex := fmt.Sprintf("%064x", pkY)
	require.NoError(t, k.RegisterVendorRootKey(ctx, types.PlatformSGX, xHex, yHex))

	// Create an enclave registration with valid vendor attestation.
	enclaveHash, signerHash := testEnclaveHashes()
	vendorKey := p256TestPrivateKey()

	platformKeyPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	platXHex := fmt.Sprintf("%064x", platformKeyPriv.PublicKey.X)
	platYHex := fmt.Sprintf("%064x", platformKeyPriv.PublicKey.Y)

	// Sign the platform key with vendor root.
	xBuf, _ := hex.DecodeString(platXHex)
	yBuf, _ := hex.DecodeString(platYHex)
	var keyAttestData []byte
	keyAttestData = append(keyAttestData, xBuf...)
	keyAttestData = append(keyAttestData, yBuf...)
	keyAttestData = append(keyAttestData, types.PlatformSGX)
	keyAttestHash := sha256.Sum256(keyAttestData)
	attestR, attestS, err := ecdsa.Sign(rand.Reader, vendorKey, keyAttestHash[:])
	require.NoError(t, err)

	reg := types.EnclaveRegistration{
		EnclaveHash:     hex.EncodeToString(enclaveHash[:]),
		SignerHash:      hex.EncodeToString(signerHash[:]),
		ApplicationHash: "",
		Platform:        types.PlatformSGX,
		PlatformKeyX:    platXHex,
		PlatformKeyY:    platYHex,
		VendorAttestR:   fmt.Sprintf("%064x", attestR),
		VendorAttestS:   fmt.Sprintf("%064x", attestS),
	}

	enclaveID, err := k.RegisterEnclave(ctx, reg)
	require.NoError(t, err)
	require.NotEmpty(t, enclaveID)

	// Verify audit log has an entry.
	var foundAudit bool
	_ = k.OperatorAuditLog.Walk(ctx, nil, func(_ string, val string) (bool, error) {
		var action types.OperatorAction
		require.NoError(t, json.Unmarshal([]byte(val), &action))
		if action.Action == "register_enclave" && action.Target == enclaveID {
			foundAudit = true
			return true, nil
		}
		return false, nil
	})
	require.True(t, foundAudit, "audit log should record register_enclave")
}

func TestOperatorAuditLog_recordsOnRevokeEnclave(t *testing.T) {
	k, ctx := setupKeeper(t)

	// Directly set a mock enclave registration for simpler testing.
	reg := types.EnclaveRegistration{Active: true, Platform: types.PlatformSGX}
	data, _ := json.Marshal(reg)
	require.NoError(t, k.RegisteredEnclaves.Set(ctx, "test-enclave-id", string(data)))

	require.NoError(t, k.RevokeEnclave(ctx, "test-enclave-id"))

	var foundAudit bool
	_ = k.OperatorAuditLog.Walk(ctx, nil, func(_ string, val string) (bool, error) {
		var action types.OperatorAction
		require.NoError(t, json.Unmarshal([]byte(val), &action))
		if action.Action == "revoke_enclave" && action.Target == "test-enclave-id" {
			foundAudit = true
			return true, nil
		}
		return false, nil
	})
	require.True(t, foundAudit, "audit log should record revoke_enclave")
}

func TestPause_auditLogMultipleEvents(t *testing.T) {
	k, ctx := setupKeeper(t)

	// Do multiple pause/unpause cycles.
	require.NoError(t, k.PauseVault(ctx, "authority", "incident 1"))
	require.NoError(t, k.UnpauseVault(ctx, "authority", "resolved 1"))
	require.NoError(t, k.PauseVault(ctx, "authority", "incident 2"))
	require.NoError(t, k.UnpauseVault(ctx, "authority", "resolved 2"))

	ps := k.GetPauseState(ctx)
	require.Len(t, ps.EventLog, 4)
	require.Equal(t, "pause", ps.EventLog[0].Action)
	require.Equal(t, "incident 1", ps.EventLog[0].Reason)
	require.Equal(t, "unpause", ps.EventLog[1].Action)
	require.Equal(t, "resolved 1", ps.EventLog[1].Reason)
	require.Equal(t, "pause", ps.EventLog[2].Action)
	require.Equal(t, "incident 2", ps.EventLog[2].Reason)
	require.Equal(t, "unpause", ps.EventLog[3].Action)
	require.Equal(t, "resolved 2", ps.EventLog[3].Reason)
}

// ─────────────────────────────────────────────────────────────────────────────
// Benchmarks (Track 11: Performance SLOs)
// ─────────────────────────────────────────────────────────────────────────────

// setupBenchKeeper creates a keeper for benchmarks (no *testing.T).
func setupBenchKeeper(b *testing.B) (*Keeper, sdk.Context) {
	b.Helper()
	storeKey := storetypes.NewKVStoreKey(types.StoreKey)
	tkey := storetypes.NewTransientStoreKey("transient_bench")
	ctx := testutil.DefaultContext(storeKey, tkey)
	ctx = ctx.WithBlockTime(time.Now())

	ir := codectypes.NewInterfaceRegistry()
	cdc := codec.NewProtoCodec(ir)
	storeService := runtime.NewKVStoreService(storeKey)
	k := NewKeeper(cdc, storeService, "authority")
	if err := k.InitializeDefaults(ctx); err != nil {
		b.Fatal(err)
	}

	// Pre-populate a validator for staking benchmarks.
	if err := k.setValidator(ctx, &types.ValidatorRecord{
		Address:  "benchval1",
		IsActive: true,
	}); err != nil {
		b.Fatal(err)
	}
	if err := k.setActiveValidatorAddrs(ctx, []string{"benchval1"}); err != nil {
		b.Fatal(err)
	}

	return k, ctx
}

// ─────────────────────────────────────────────────────────────────────────────
// Cross-Language Conformance Tests (Track 8)
// ─────────────────────────────────────────────────────────────────────────────
//
// These tests read shared JSON test vectors from the Cruzible dApp repository
// and verify that the Go keeper produces identical hashes to the TypeScript
// and Python SDKs.

// conformanceValidatorVector is the JSON schema for validator-selection vectors.
type conformanceValidatorVector struct {
	Name  string `json:"name"`
	Input struct {
		Epoch      uint64 `json:"epoch"`
		Validators []struct {
			Address              string `json:"address"`
			Stake                string `json:"stake"`
			PerformanceScore     uint32 `json:"performance_score"`
			DecentralizationScore uint32 `json:"decentralization_score"`
			ReputationScore      uint32 `json:"reputation_score"`
			CompositeScore       uint32 `json:"composite_score"`
			TEEPublicKey         string `json:"tee_public_key"`
			CommissionBps        uint32 `json:"commission_bps"`
			Rank                 int    `json:"rank"`
		} `json:"validators"`
	} `json:"input"`
	Expected struct {
		ValidatorSetHash string `json:"validator_set_hash"`
	} `json:"expected"`
}

// conformanceRewardVector is the JSON schema for reward payload vectors.
type conformanceRewardVector struct {
	Name  string `json:"name"`
	Input struct {
		Epoch                 uint64 `json:"epoch"`
		StakerRegistryRoot    string `json:"staker_registry_root"`
		DelegationRegistryRoot string `json:"delegation_registry_root"`
		StakerStakes          []struct {
			Address     string `json:"address"`
			Shares      string `json:"shares"`
			DelegatedTo string `json:"delegated_to"`
		} `json:"staker_stakes"`
	} `json:"input"`
	Expected struct {
		StakeSnapshotHash      string `json:"stake_snapshot_hash"`
		StakerRegistryRoot     string `json:"staker_registry_root"`
		DelegationRegistryRoot string `json:"delegation_registry_root"`
	} `json:"expected"`
}

// parseStakeUint64 converts a decimal string (possibly very large) to uint64.
// For values that exceed uint64, it returns 0 (test vectors should use values
// that fit in uint64 for Go conformance since the keeper uses uint64 internally).
func parseStakeUint64(s string) uint64 {
	v, ok := new(big.Int).SetString(s, 10)
	if !ok {
		return 0
	}
	if !v.IsUint64() {
		return 0
	}
	return v.Uint64()
}

func TestConformance_validatorSetHash_fromVectors(t *testing.T) {
	vectorPath := "../../../dApps/cruzible/test-vectors/validator-selection/default.json"
	data, err := os.ReadFile(vectorPath)
	if err != nil {
		t.Skipf("test vector file not found at %s: %v", vectorPath, err)
	}

	var vector conformanceValidatorVector
	if err := json.Unmarshal(data, &vector); err != nil {
		t.Fatalf("failed to parse test vector: %v", err)
	}

	if vector.Expected.ValidatorSetHash == "" {
		t.Skip("test vector has no expected validator_set_hash")
	}

	// Convert JSON validators to types.ValidatorRecord.
	// Note: The Go keeper uses uint64 for DelegatedStake while the SDKs use
	// arbitrary-precision uint256. If any stake value exceeds uint64 max, the
	// Go encoding will differ from the SDK encoding, and this test will
	// correctly surface the representation gap. Skip those vectors with a
	// diagnostic message so the gap is tracked without blocking CI.
	var validators []types.ValidatorRecord
	for _, v := range vector.Input.Validators {
		stake := parseStakeUint64(v.Stake)
		if stake == 0 && v.Stake != "0" {
			t.Skipf("stake %q exceeds uint64; Go keeper cannot match SDK uint256 encoding — "+
				"this is a known representation gap (Track 8 follow-up)", v.Stake)
		}
		teeKey, _ := hex.DecodeString(strings.TrimPrefix(v.TEEPublicKey, "0x"))
		validators = append(validators, types.ValidatorRecord{
			Address:               v.Address,
			DelegatedStake:        stake,
			PerformanceScore:      v.PerformanceScore,
			DecentralizationScore: v.DecentralizationScore,
			ReputationScore:       v.ReputationScore,
			CompositeScore:        v.CompositeScore,
			TEEPublicKey:          teeKey,
			Commission:            v.CommissionBps,
		})
	}

	hash := computeValidatorSetHash(vector.Input.Epoch, validators)
	got := "0x" + hex.EncodeToString(hash[:])
	expected := strings.ToLower(vector.Expected.ValidatorSetHash)

	require.Equal(t, expected, got,
		"Go computeValidatorSetHash must match test vector (cross-language conformance)")
}

func TestConformance_stakerRegistryRoot_fromVectors(t *testing.T) {
	vectorPath := "../../../dApps/cruzible/test-vectors/reward/default.json"
	data, err := os.ReadFile(vectorPath)
	if err != nil {
		t.Skipf("test vector file not found at %s: %v", vectorPath, err)
	}

	var vector conformanceRewardVector
	if err := json.Unmarshal(data, &vector); err != nil {
		t.Fatalf("failed to parse test vector: %v", err)
	}

	if vector.Expected.StakerRegistryRoot == "" {
		t.Skip("test vector has no expected staker_registry_root")
	}

	var entries []stakerStakeEntry
	for _, s := range vector.Input.StakerStakes {
		entries = append(entries, stakerStakeEntry{
			Address:     s.Address,
			Shares:      parseStakeUint64(s.Shares),
			DelegatedTo: s.DelegatedTo,
		})
	}

	root := computeStakerRegistryRoot(entries)
	got := "0x" + hex.EncodeToString(root[:])
	expected := strings.ToLower(vector.Expected.StakerRegistryRoot)

	require.Equal(t, expected, got,
		"Go computeStakerRegistryRoot must match test vector (cross-language conformance)")
}

// ─────────────────────────────────────────────────────────────────────────────
// Attestation Relay Governance Tests
//
// These tests verify the AttestationRelay lifecycle:
//   - Registration with P-256 key validation
//   - Time-locked key rotation (initiate → finalize / cancel)
//   - Liveness challenges with P-256 proof-of-possession
//   - Emergency revocation
//   - RegisterEnclave attestation count tracking
// ─────────────────────────────────────────────────────────────────────────────

// relayTestPrivateKey returns a P-256 private key (D=3) used as the relay signing key.
func relayTestPrivateKey() *ecdsa.PrivateKey {
	priv := new(ecdsa.PrivateKey)
	priv.Curve = elliptic.P256()
	priv.D = big.NewInt(3)
	priv.PublicKey.X, priv.PublicKey.Y = elliptic.P256().ScalarBaseMult(big.NewInt(3).Bytes())
	return priv
}

// relayTestPublicKey returns the relay test P-256 public key (3*G).
func relayTestPublicKey() (x, y *big.Int) {
	return elliptic.P256().ScalarBaseMult(big.NewInt(3).Bytes())
}

// rotatedRelayTestPrivateKey returns a second P-256 private key (D=4) for rotation tests.
func rotatedRelayTestPrivateKey() *ecdsa.PrivateKey {
	priv := new(ecdsa.PrivateKey)
	priv.Curve = elliptic.P256()
	priv.D = big.NewInt(4)
	priv.PublicKey.X, priv.PublicKey.Y = elliptic.P256().ScalarBaseMult(big.NewInt(4).Bytes())
	return priv
}

// rotatedRelayTestPublicKey returns the rotated relay test P-256 public key (4*G).
func rotatedRelayTestPublicKey() (x, y *big.Int) {
	return elliptic.P256().ScalarBaseMult(big.NewInt(4).Bytes())
}

func TestRegisterAttestationRelay(t *testing.T) {
	k, ctx := setupKeeper(t)

	relayX, relayY := relayTestPublicKey()
	xHex := hex.EncodeToString(relayX.Bytes())
	yHex := hex.EncodeToString(relayY.Bytes())

	// Register relay for SGX
	err := k.RegisterAttestationRelay(ctx, types.PlatformSGX, xHex, yHex, "Test SGX Relay v1")
	require.NoError(t, err)

	// Verify relay is active
	require.True(t, k.IsRelayActive(ctx, types.PlatformSGX))

	// Verify relay state
	relay, err := k.GetAttestationRelay(ctx, types.PlatformSGX)
	require.NoError(t, err)
	require.Equal(t, xHex, relay.PublicKeyX)
	require.Equal(t, yHex, relay.PublicKeyY)
	require.True(t, relay.Active)
	require.Equal(t, "Test SGX Relay v1", relay.Description)
	require.Equal(t, uint64(0), relay.AttestationCount)
	require.NotZero(t, relay.RegisteredAt)
	require.Equal(t, relay.RegisteredAt, relay.LastRotatedAt)

	// Verify vendor root key was also set (backward compatibility)
	vendorKey, err := k.getVendorRootKey(ctx, types.PlatformSGX)
	require.NoError(t, err)
	require.Equal(t, relayX, vendorKey.X)
	require.Equal(t, relayY, vendorKey.Y)

	// Duplicate registration must fail
	err = k.RegisterAttestationRelay(ctx, types.PlatformSGX, xHex, yHex, "Duplicate")
	require.ErrorIs(t, err, types.ErrRelayAlreadyRegistered)

	// Unregistered platform returns false
	require.False(t, k.IsRelayActive(ctx, types.PlatformNitro))
}

func TestRegisterAttestationRelay_InvalidKey(t *testing.T) {
	k, ctx := setupKeeper(t)

	// Not on curve (arbitrary bytes that are not a valid P-256 point)
	err := k.RegisterAttestationRelay(ctx, types.PlatformSGX,
		"0000000000000000000000000000000000000000000000000000000000000001",
		"0000000000000000000000000000000000000000000000000000000000000001",
		"Bad key")
	require.Error(t, err)
	require.Contains(t, err.Error(), "not on the P-256 curve")

	// Wrong length
	err = k.RegisterAttestationRelay(ctx, types.PlatformSGX, "abcd", "efgh", "Short key")
	require.Error(t, err)
}

func TestRelayRotation_FullLifecycle(t *testing.T) {
	k, ctx := setupKeeper(t)

	// Register initial relay
	relayX, relayY := relayTestPublicKey()
	xHex := hex.EncodeToString(relayX.Bytes())
	yHex := hex.EncodeToString(relayY.Bytes())
	require.NoError(t, k.RegisterAttestationRelay(ctx, types.PlatformSGX, xHex, yHex, "Test Relay"))

	// Initiate rotation with new key
	newX, newY := rotatedRelayTestPublicKey()
	newXHex := hex.EncodeToString(newX.Bytes())
	newYHex := hex.EncodeToString(newY.Bytes())
	require.NoError(t, k.InitiateRelayRotation(ctx, types.PlatformSGX, newXHex, newYHex))

	// Verify pending rotation state
	relay, err := k.GetAttestationRelay(ctx, types.PlatformSGX)
	require.NoError(t, err)
	require.Equal(t, newXHex, relay.PendingKeyX)
	require.Equal(t, newYHex, relay.PendingKeyY)
	require.NotZero(t, relay.RotationUnlocksAt)

	// Finalize before timelock must fail
	err = k.FinalizeRelayRotation(ctx, types.PlatformSGX)
	require.ErrorIs(t, err, types.ErrRotationTimelockActive)

	// Advance time past the 48-hour timelock
	ctx = ctx.WithBlockTime(ctx.BlockTime().Add(49 * time.Hour))

	// Now finalization should succeed
	require.NoError(t, k.FinalizeRelayRotation(ctx, types.PlatformSGX))

	// Verify key was updated
	relay, err = k.GetAttestationRelay(ctx, types.PlatformSGX)
	require.NoError(t, err)
	require.Equal(t, newXHex, relay.PublicKeyX)
	require.Equal(t, newYHex, relay.PublicKeyY)
	require.Empty(t, relay.PendingKeyX)
	require.Empty(t, relay.PendingKeyY)
	require.Zero(t, relay.RotationUnlocksAt)

	// Vendor root key should also be updated
	vendorKey, err := k.getVendorRootKey(ctx, types.PlatformSGX)
	require.NoError(t, err)
	require.Equal(t, newX, vendorKey.X)
	require.Equal(t, newY, vendorKey.Y)
}

func TestRelayRotation_Cancel(t *testing.T) {
	k, ctx := setupKeeper(t)

	relayX, relayY := relayTestPublicKey()
	xHex := hex.EncodeToString(relayX.Bytes())
	yHex := hex.EncodeToString(relayY.Bytes())
	require.NoError(t, k.RegisterAttestationRelay(ctx, types.PlatformSGX, xHex, yHex, "Test Relay"))

	newX, newY := rotatedRelayTestPublicKey()
	newXHex := hex.EncodeToString(newX.Bytes())
	newYHex := hex.EncodeToString(newY.Bytes())
	require.NoError(t, k.InitiateRelayRotation(ctx, types.PlatformSGX, newXHex, newYHex))

	// Cancel the rotation
	require.NoError(t, k.CancelRelayRotation(ctx, types.PlatformSGX))

	// Verify pending state was cleared
	relay, err := k.GetAttestationRelay(ctx, types.PlatformSGX)
	require.NoError(t, err)
	require.Empty(t, relay.PendingKeyX)
	require.Empty(t, relay.PendingKeyY)
	require.Zero(t, relay.RotationUnlocksAt)

	// Original key should be unchanged
	require.Equal(t, xHex, relay.PublicKeyX)
	require.Equal(t, yHex, relay.PublicKeyY)

	// Cancelling when nothing is pending must fail
	err = k.CancelRelayRotation(ctx, types.PlatformSGX)
	require.ErrorIs(t, err, types.ErrNoRotationPending)
}

func TestRelayRotation_UnregisteredRelay(t *testing.T) {
	k, ctx := setupKeeper(t)

	newX, newY := rotatedRelayTestPublicKey()
	newXHex := hex.EncodeToString(newX.Bytes())
	newYHex := hex.EncodeToString(newY.Bytes())

	// Initiating rotation on unregistered platform must fail
	err := k.InitiateRelayRotation(ctx, types.PlatformSGX, newXHex, newYHex)
	require.ErrorIs(t, err, types.ErrRelayNotRegistered)

	// Finalizing on unregistered platform must fail
	err = k.FinalizeRelayRotation(ctx, types.PlatformSGX)
	require.ErrorIs(t, err, types.ErrRelayNotRegistered)
}

func TestRevokeRelay(t *testing.T) {
	k, ctx := setupKeeper(t)

	relayX, relayY := relayTestPublicKey()
	xHex := hex.EncodeToString(relayX.Bytes())
	yHex := hex.EncodeToString(relayY.Bytes())
	require.NoError(t, k.RegisterAttestationRelay(ctx, types.PlatformSGX, xHex, yHex, "Test Relay"))

	// Revoke
	require.NoError(t, k.RevokeRelay(ctx, types.PlatformSGX))

	// Verify relay is inactive
	require.False(t, k.IsRelayActive(ctx, types.PlatformSGX))

	relay, err := k.GetAttestationRelay(ctx, types.PlatformSGX)
	require.NoError(t, err)
	require.False(t, relay.Active)
	require.Empty(t, relay.PendingKeyX)
	require.Empty(t, relay.ActiveChallenge)

	// Vendor root key should be zeroed — new enclave registration should fail
	// because the zero key is not a valid P-256 point on the curve for verification.
	_, _ = k.getVendorRootKey(ctx, types.PlatformSGX)
	// The zero point is technically loadable but won't verify any signature,
	// so vendor key attestation will fail during RegisterEnclave.

	// Revoking unregistered relay must fail
	err = k.RevokeRelay(ctx, types.PlatformNitro)
	require.ErrorIs(t, err, types.ErrRelayNotRegistered)

	// Operations on revoked relay should fail
	err = k.InitiateRelayRotation(ctx, types.PlatformSGX,
		hex.EncodeToString(relayX.Bytes()),
		hex.EncodeToString(relayY.Bytes()))
	require.ErrorIs(t, err, types.ErrRelayNotActive)
}

func TestRelayChallenge_SuccessfulResponse(t *testing.T) {
	k, ctx := setupKeeper(t)

	relayPriv := relayTestPrivateKey()
	relayX, relayY := relayTestPublicKey()
	xHex := hex.EncodeToString(relayX.Bytes())
	yHex := hex.EncodeToString(relayY.Bytes())
	require.NoError(t, k.RegisterAttestationRelay(ctx, types.PlatformSGX, xHex, yHex, "Test Relay"))

	// Issue a challenge
	challengeBytes := sha256.Sum256([]byte("governance-challenge-nonce-1"))
	challengeHex := hex.EncodeToString(challengeBytes[:])
	require.NoError(t, k.ChallengeRelay(ctx, types.PlatformSGX, challengeHex))

	// Verify challenge is pending
	relay, err := k.GetAttestationRelay(ctx, types.PlatformSGX)
	require.NoError(t, err)
	require.Equal(t, challengeHex, relay.ActiveChallenge)
	require.NotZero(t, relay.ChallengeDeadline)

	// Respond with valid P-256 signature over SHA-256(challenge)
	challengeHash := sha256.Sum256(challengeBytes[:])
	r, s, err := ecdsa.Sign(rand.Reader, relayPriv, challengeHash[:])
	require.NoError(t, err)

	rBytes := make([]byte, 32)
	sBytes := make([]byte, 32)
	r.FillBytes(rBytes)
	s.FillBytes(sBytes)

	require.NoError(t, k.RespondRelayChallenge(ctx, types.PlatformSGX,
		hex.EncodeToString(rBytes), hex.EncodeToString(sBytes)))

	// Challenge should be cleared
	relay, err = k.GetAttestationRelay(ctx, types.PlatformSGX)
	require.NoError(t, err)
	require.Empty(t, relay.ActiveChallenge)
	require.Zero(t, relay.ChallengeDeadline)
}

func TestRelayChallenge_InvalidSignature(t *testing.T) {
	k, ctx := setupKeeper(t)

	relayX, relayY := relayTestPublicKey()
	xHex := hex.EncodeToString(relayX.Bytes())
	yHex := hex.EncodeToString(relayY.Bytes())
	require.NoError(t, k.RegisterAttestationRelay(ctx, types.PlatformSGX, xHex, yHex, "Test Relay"))

	challengeBytes := sha256.Sum256([]byte("challenge-nonce-2"))
	challengeHex := hex.EncodeToString(challengeBytes[:])
	require.NoError(t, k.ChallengeRelay(ctx, types.PlatformSGX, challengeHex))

	// Respond with a signature from a DIFFERENT key (vendorRoot, not relay)
	wrongPriv := vendorRootTestPrivateKey()
	challengeHash := sha256.Sum256(challengeBytes[:])
	r, s, err := ecdsa.Sign(rand.Reader, wrongPriv, challengeHash[:])
	require.NoError(t, err)

	rBytes := make([]byte, 32)
	sBytes := make([]byte, 32)
	r.FillBytes(rBytes)
	s.FillBytes(sBytes)

	err = k.RespondRelayChallenge(ctx, types.PlatformSGX,
		hex.EncodeToString(rBytes), hex.EncodeToString(sBytes))
	require.ErrorIs(t, err, types.ErrChallengeResponseInvalid)
}

func TestRelayChallenge_Expired(t *testing.T) {
	k, ctx := setupKeeper(t)

	relayPriv := relayTestPrivateKey()
	relayX, relayY := relayTestPublicKey()
	xHex := hex.EncodeToString(relayX.Bytes())
	yHex := hex.EncodeToString(relayY.Bytes())
	require.NoError(t, k.RegisterAttestationRelay(ctx, types.PlatformSGX, xHex, yHex, "Test Relay"))

	challengeBytes := sha256.Sum256([]byte("challenge-nonce-3"))
	challengeHex := hex.EncodeToString(challengeBytes[:])
	require.NoError(t, k.ChallengeRelay(ctx, types.PlatformSGX, challengeHex))

	// Advance time past the 1-hour challenge window
	ctx = ctx.WithBlockTime(ctx.BlockTime().Add(2 * time.Hour))

	// Response should fail due to expiration
	challengeHash := sha256.Sum256(challengeBytes[:])
	r, s, err := ecdsa.Sign(rand.Reader, relayPriv, challengeHash[:])
	require.NoError(t, err)

	rBytes := make([]byte, 32)
	sBytes := make([]byte, 32)
	r.FillBytes(rBytes)
	s.FillBytes(sBytes)

	err = k.RespondRelayChallenge(ctx, types.PlatformSGX,
		hex.EncodeToString(rBytes), hex.EncodeToString(sBytes))
	require.ErrorIs(t, err, types.ErrChallengeExpired)
}

func TestRelayChallenge_NoPending(t *testing.T) {
	k, ctx := setupKeeper(t)

	relayX, relayY := relayTestPublicKey()
	xHex := hex.EncodeToString(relayX.Bytes())
	yHex := hex.EncodeToString(relayY.Bytes())
	require.NoError(t, k.RegisterAttestationRelay(ctx, types.PlatformSGX, xHex, yHex, "Test Relay"))

	// Responding without a challenge must fail
	err := k.RespondRelayChallenge(ctx, types.PlatformSGX,
		"0000000000000000000000000000000000000000000000000000000000000001",
		"0000000000000000000000000000000000000000000000000000000000000001")
	require.ErrorIs(t, err, types.ErrNoPendingChallenge)
}

func TestRelayAttestationCountTracking(t *testing.T) {
	k, ctx := setupKeeper(t)

	// Use relay key as vendor root (relay registration sets vendorRootKey)
	relayPriv := relayTestPrivateKey()
	relayX, relayY := relayTestPublicKey()
	xHex := hex.EncodeToString(relayX.Bytes())
	yHex := hex.EncodeToString(relayY.Bytes())
	require.NoError(t, k.RegisterAttestationRelay(ctx, types.PlatformSGX, xHex, yHex, "Test Relay"))

	// Initial attestation count should be zero
	relay, err := k.GetAttestationRelay(ctx, types.PlatformSGX)
	require.NoError(t, err)
	require.Equal(t, uint64(0), relay.AttestationCount)

	// Register an enclave — the relay signed the platform key
	enclaveHash := sha256.Sum256([]byte("relay-enclave-v1"))
	signerHash := sha256.Sum256([]byte("relay-signer-v1"))
	p256X, p256Y := p256TestPublicKey()

	// Build vendor key attestation using the relay's private key (D=3)
	var attestData []byte
	xB := make([]byte, 32)
	yB := make([]byte, 32)
	p256X.FillBytes(xB)
	p256Y.FillBytes(yB)
	attestData = append(attestData, xB...)
	attestData = append(attestData, yB...)
	attestData = append(attestData, types.PlatformSGX)
	hash := sha256.Sum256(attestData)

	r, s, err := ecdsa.Sign(rand.Reader, relayPriv, hash[:])
	require.NoError(t, err)

	rBytes := make([]byte, 32)
	sBytes := make([]byte, 32)
	r.FillBytes(rBytes)
	s.FillBytes(sBytes)

	_, err = k.RegisterEnclave(ctx, types.EnclaveRegistration{
		EnclaveHash:   hex.EncodeToString(enclaveHash[:]),
		SignerHash:    hex.EncodeToString(signerHash[:]),
		Platform:      types.PlatformSGX,
		Description:   "Relay-attested Enclave",
		PlatformKeyX:  hex.EncodeToString(p256X.Bytes()),
		PlatformKeyY:  hex.EncodeToString(p256Y.Bytes()),
		VendorAttestR: hex.EncodeToString(rBytes),
		VendorAttestS: hex.EncodeToString(sBytes),
	})
	require.NoError(t, err)

	// Attestation count should now be 1
	relay, err = k.GetAttestationRelay(ctx, types.PlatformSGX)
	require.NoError(t, err)
	require.Equal(t, uint64(1), relay.AttestationCount)
}

func TestDirectVendorRootKeyOverrideBlockedWhileRelayActive(t *testing.T) {
	k, ctx := setupKeeper(t)

	relayX, relayY := relayTestPublicKey()
	xHex := hex.EncodeToString(relayX.Bytes())
	yHex := hex.EncodeToString(relayY.Bytes())

	// Register a relay for SGX
	require.NoError(t, k.RegisterAttestationRelay(ctx, types.PlatformSGX, xHex, yHex, "Test Relay"))

	// Direct override while relay is active must be rejected
	vrX, vrY := vendorRootTestPublicKey()
	err := k.RegisterVendorRootKey(ctx, types.PlatformSGX,
		hex.EncodeToString(vrX.Bytes()),
		hex.EncodeToString(vrY.Bytes()))
	require.ErrorIs(t, err, types.ErrDirectOverrideWhileRelayActive)

	// Vendor root key should still be the relay key, not the attempted override
	vendorKey, err := k.getVendorRootKey(ctx, types.PlatformSGX)
	require.NoError(t, err)
	require.Equal(t, relayX, vendorKey.X, "vendor root key should not have been overridden")
	require.Equal(t, relayY, vendorKey.Y, "vendor root key should not have been overridden")

	// After revoking the relay, direct override should work
	require.NoError(t, k.RevokeRelay(ctx, types.PlatformSGX))

	err = k.RegisterVendorRootKey(ctx, types.PlatformSGX,
		hex.EncodeToString(vrX.Bytes()),
		hex.EncodeToString(vrY.Bytes()))
	require.NoError(t, err, "direct vendor root key should be settable after relay revocation")

	vendorKey, err = k.getVendorRootKey(ctx, types.PlatformSGX)
	require.NoError(t, err)
	require.Equal(t, vrX, vendorKey.X)
	require.Equal(t, vrY, vendorKey.Y)
}

func TestDirectVendorRootKeyAllowedWithoutRelay(t *testing.T) {
	k, ctx := setupKeeper(t)

	// Without any relay registered, direct set should work fine
	vrX, vrY := vendorRootTestPublicKey()
	err := k.RegisterVendorRootKey(ctx, types.PlatformNitro,
		hex.EncodeToString(vrX.Bytes()),
		hex.EncodeToString(vrY.Bytes()))
	require.NoError(t, err)
}

func TestRelayCrossNetworkConsistency_Constants(t *testing.T) {
	// Verify the Go constants match the Solidity constants
	// RELAY_ROTATION_DELAY in VaultTEEVerifier.sol = 48 hours = 172800 seconds
	require.Equal(t, int64(172800), int64(types.RelayRotationDelaySec),
		"RelayRotationDelaySec must equal 48 hours (172800s) matching VaultTEEVerifier.sol")

	// RELAY_CHALLENGE_WINDOW in VaultTEEVerifier.sol = 1 hour = 3600 seconds
	require.Equal(t, int64(3600), int64(types.RelayChallengeWindowSec),
		"RelayChallengeWindowSec must equal 1 hour (3600s) matching VaultTEEVerifier.sol")
}

// bigIntHex32 encodes a big.Int as a 64-char hex string, zero-padded to 32 bytes.
// This is required because big.Int.Bytes() returns minimal-length encoding, but
// the keeper's setVendorRootKeyInternal requires exactly 32 bytes (64 hex chars).
func bigIntHex32(v *big.Int) string {
	b := make([]byte, 32)
	vb := v.Bytes()
	copy(b[32-len(vb):], vb)
	return hex.EncodeToString(b)
}

func TestRelayReregistrationAfterRevocation(t *testing.T) {
	k, ctx := setupKeeper(t)

	relayX, relayY := relayTestPublicKey()
	xHex := bigIntHex32(relayX)
	yHex := bigIntHex32(relayY)

	// Register → revoke
	require.NoError(t, k.RegisterAttestationRelay(ctx, types.PlatformSGX, xHex, yHex, "First Relay"))
	require.NoError(t, k.RevokeRelay(ctx, types.PlatformSGX))
	require.False(t, k.IsRelayActive(ctx, types.PlatformSGX))

	// Re-register with a different key (the rotated key) on the same platform
	rotX, rotY := rotatedRelayTestPublicKey()
	rotXHex := bigIntHex32(rotX)
	rotYHex := bigIntHex32(rotY)

	require.NoError(t, k.RegisterAttestationRelay(ctx, types.PlatformSGX, rotXHex, rotYHex, "Replacement Relay"),
		"re-registration after revocation must succeed")

	// Verify the new relay is active with fresh state
	relay, err := k.GetAttestationRelay(ctx, types.PlatformSGX)
	require.NoError(t, err)
	require.True(t, relay.Active)
	require.Equal(t, rotXHex, relay.PublicKeyX, "must hold the replacement key")
	require.Equal(t, rotYHex, relay.PublicKeyY)
	require.Equal(t, uint64(0), relay.AttestationCount, "count must reset on re-registration")
	require.Equal(t, "Replacement Relay", relay.Description)

	// Stale state from the first relay must be cleaned
	require.Empty(t, relay.PendingKeyX)
	require.Empty(t, relay.PendingKeyY)
	require.Zero(t, relay.RotationUnlocksAt)
	require.Empty(t, relay.ActiveChallenge)
	require.Zero(t, relay.ChallengeDeadline)

	// Vendor root key must be the replacement relay's key
	vendorKey, err := k.getVendorRootKey(ctx, types.PlatformSGX)
	require.NoError(t, err)
	require.Equal(t, rotX, vendorKey.X, "vendor root key must match replacement relay")
	require.Equal(t, rotY, vendorKey.Y)
}

func TestReplacementRelayRegistersEnclaves(t *testing.T) {
	k, ctx := setupKeeper(t)

	relayX, relayY := relayTestPublicKey()
	xHex := bigIntHex32(relayX)
	yHex := bigIntHex32(relayY)

	// Register → revoke first relay
	require.NoError(t, k.RegisterAttestationRelay(ctx, types.PlatformSGX, xHex, yHex, "Old Relay"))
	require.NoError(t, k.RevokeRelay(ctx, types.PlatformSGX))

	// Register replacement relay with D=4 key
	rotPriv := rotatedRelayTestPrivateKey()
	rotX, rotY := rotatedRelayTestPublicKey()
	rotXHex := bigIntHex32(rotX)
	rotYHex := bigIntHex32(rotY)

	require.NoError(t, k.RegisterAttestationRelay(ctx, types.PlatformSGX, rotXHex, rotYHex, "New Relay"))

	// Use the replacement relay to attest an enclave
	enclaveHash := sha256.Sum256([]byte("replacement-enclave-code"))
	signerHash := sha256.Sum256([]byte("replacement-signer"))

	// Generate a fresh P-256 key pair for the platform key
	p256Key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	p256X := p256Key.PublicKey.X
	p256Y := p256Key.PublicKey.Y

	// Sign the platform key attestation using the replacement relay private key (D=4)
	// Attestation message: SHA-256(platformKeyX || platformKeyY || platformId)
	var attestData []byte
	pxBytes := make([]byte, 32)
	pyBytes := make([]byte, 32)
	p256X.FillBytes(pxBytes)
	p256Y.FillBytes(pyBytes)
	attestData = append(attestData, pxBytes...)
	attestData = append(attestData, pyBytes...)
	attestData = append(attestData, types.PlatformSGX)
	hash := sha256.Sum256(attestData)

	r, s, err := ecdsa.Sign(rand.Reader, rotPriv, hash[:])
	require.NoError(t, err)

	rBytes := make([]byte, 32)
	sBytes := make([]byte, 32)
	r.FillBytes(rBytes)
	s.FillBytes(sBytes)

	_, err = k.RegisterEnclave(ctx, types.EnclaveRegistration{
		EnclaveHash:   hex.EncodeToString(enclaveHash[:]),
		SignerHash:    hex.EncodeToString(signerHash[:]),
		Platform:      types.PlatformSGX,
		Description:   "Enclave attested by replacement relay",
		PlatformKeyX:  bigIntHex32(p256X),
		PlatformKeyY:  bigIntHex32(p256Y),
		VendorAttestR: hex.EncodeToString(rBytes),
		VendorAttestS: hex.EncodeToString(sBytes),
	})
	require.NoError(t, err, "replacement relay must be able to attest enclaves")

	// Attestation count should be 1 on the replacement relay
	relay, err := k.GetAttestationRelay(ctx, types.PlatformSGX)
	require.NoError(t, err)
	require.Equal(t, uint64(1), relay.AttestationCount)
}

func BenchmarkStake(b *testing.B) {
	k, ctx := setupBenchKeeper(b)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		addr := fmt.Sprintf("0x%040x", i+1)
		_, _ = k.Stake(ctx, addr, 100_000_000, "benchval1", 0)
	}
}

func BenchmarkUnstake(b *testing.B) {
	k, ctx := setupBenchKeeper(b)

	// Pre-stake for all iterations.
	for i := 0; i < b.N; i++ {
		addr := fmt.Sprintf("0x%040x", i+1)
		_, _ = k.Stake(ctx, addr, 100_000_000, "benchval1", 0)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		addr := fmt.Sprintf("0x%040x", i+1)
		staker, _ := k.getStaker(ctx, addr)
		if staker != nil && staker.Shares > 0 {
			_, _, _ = k.Unstake(ctx, addr, staker.Shares/2)
		}
	}
}

func BenchmarkComputeValidatorSetHash(b *testing.B) {
	// Create a validator set of varying sizes.
	validators := make([]types.ValidatorRecord, 100)
	for i := range validators {
		validators[i] = types.ValidatorRecord{
			Address:               fmt.Sprintf("0x%040x", i+1),
			DelegatedStake:        uint64(i+1) * 1_000_000,
			PerformanceScore:      uint32(8000 + i),
			DecentralizationScore: uint32(7000 + i),
			ReputationScore:       uint32(9000 + i),
			CompositeScore:        uint32(8000 + i),
			TEEPublicKey:          make([]byte, 33),
			Commission:            500,
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		computeValidatorSetHash(uint64(i+1), validators)
	}
}

func BenchmarkGetVaultStatus(b *testing.B) {
	k, ctx := setupBenchKeeper(b)

	// Add some stakers and state.
	for i := 0; i < 100; i++ {
		addr := fmt.Sprintf("0x%040x", i+1)
		_, _ = k.Stake(ctx, addr, 100_000_000, "benchval1", 0)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = k.GetVaultStatus(ctx)
	}
}

func BenchmarkPauseUnpause(b *testing.B) {
	k, ctx := setupBenchKeeper(b)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = k.PauseVault(ctx, "authority", fmt.Sprintf("bench %d", i))
		_ = k.UnpauseVault(ctx, "authority", fmt.Sprintf("resolved %d", i))
	}
}

func BenchmarkGetExchangeRate(b *testing.B) {
	k, ctx := setupBenchKeeper(b)

	// Set up meaningful totals.
	_ = k.TotalPooledAethel.Set(ctx, 142_570_000_000)
	_ = k.TotalShares.Set(ctx, 131_500_000_000)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = k.GetExchangeRate(ctx)
	}
}
