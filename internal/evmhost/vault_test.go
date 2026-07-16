package evmhost_test

import (
	"encoding/hex"
	"os"
	"strings"
	"testing"

	gethabi "github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/holiman/uint256"
	"github.com/stretchr/testify/require"
)

// The vault test executes the COMMITTED artifacts (solc 0.8.20, optimizer 200,
// shanghai — see contracts/examples/build.sh), so the exact reviewed bytecode
// runs through the interpreter.
const artifactsDir = "../../contracts/examples/artifacts"

var beneficiary = common.HexToAddress("0x00000000000000000000000000000000000000BB")

func loadVaultArtifacts(t *testing.T) ([]byte, gethabi.ABI) {
	t.Helper()
	binHex, err := os.ReadFile(artifactsDir + "/AIGatedVault.bin")
	require.NoError(t, err, "run contracts/examples/build.sh to produce artifacts")
	bin, err := hex.DecodeString(strings.TrimSpace(string(binHex)))
	require.NoError(t, err)
	abiJSON, err := os.ReadFile(artifactsDir + "/AIGatedVault.abi")
	require.NoError(t, err)
	parsed, err := gethabi.JSON(strings.NewReader(string(abiJSON)))
	require.NoError(t, err)
	return bin, parsed
}

// TestAIGatedVault_EndToEnd is the ADR-0001 Phase 2 reference proof: REAL
// compiled Solidity (committed artifacts) escrows value and releases it only
// against a policy-compliant Digital Seal, entirely through the interpreter
// and the ISeal precompile.
func TestAIGatedVault_EndToEnd(t *testing.T) {
	host, _, ctx, seal := newStack(t)
	bin, vaultABI := loadVaultArtifacts(t)

	// Vault policy mirrors the harness seal: FHE backend, EU residency, no
	// vendor-root requirement (FHE has no silicon root).
	ctorArgs, err := vaultABI.Pack("",
		beneficiary,
		[32]byte(([32]byte)(seal.ModelCommitment)),
		[]string{"fhe"},
		"",
		[]string{},
		false,
		[]string{"EU"},
	)
	require.NoError(t, err)

	vaultAddr, err := host.Deploy(ctx, eoa, append(append([]byte{}, bin...), ctorArgs...), 3_000_000)
	require.NoError(t, err)

	// Fund the depositor and escrow 1000 wei via receive().
	host.FundAccount(eoa, uint256.NewInt(1_000_000))
	_, err = host.CallValue(ctx, eoa, vaultAddr, nil, 200_000, uint256.NewInt(1000))
	require.NoError(t, err)
	require.Equal(t, uint64(1000), host.Balance(vaultAddr).Uint64())

	// Release against the completed job: the vault walks job -> seal ->
	// confidentiality through ISeal and pays the beneficiary.
	calldata, err := vaultABI.Pack("release", "job-evm-1")
	require.NoError(t, err)
	_, err = host.Call(ctx, eoa, vaultAddr, calldata, 1_000_000)
	require.NoError(t, err)

	require.Equal(t, uint64(1000), host.Balance(beneficiary).Uint64(), "beneficiary must be paid")
	require.Zero(t, host.Balance(vaultAddr).Uint64(), "vault must be drained")

	// Double release reverts (AlreadyReleased).
	_, err = host.Call(ctx, eoa, vaultAddr, calldata, 1_000_000)
	require.Error(t, err)
}

// TestAIGatedVault_PolicyViolationsHoldFunds: the vault must NOT release when
// the seal cannot satisfy its policy or certifies the wrong model.
func TestAIGatedVault_PolicyViolationsHoldFunds(t *testing.T) {
	host, _, ctx, seal := newStack(t)
	bin, vaultABI := loadVaultArtifacts(t)
	host.FundAccount(eoa, uint256.NewInt(1_000_000))

	deploy := func(model [32]byte, backends []string, vendorRoot bool) common.Address {
		ctorArgs, err := vaultABI.Pack("", beneficiary, model, backends, "", []string{}, vendorRoot, []string{})
		require.NoError(t, err)
		addr, err := host.Deploy(ctx, eoa, append(append([]byte{}, bin...), ctorArgs...), 3_000_000)
		require.NoError(t, err)
		_, err = host.CallValue(ctx, eoa, addr, nil, 200_000, uint256.NewInt(500))
		require.NoError(t, err)
		return addr
	}
	release := func(addr common.Address) error {
		calldata, err := vaultABI.Pack("release", "job-evm-1")
		require.NoError(t, err)
		_, err = host.Call(ctx, eoa, addr, calldata, 1_000_000)
		return err
	}

	// Vendor-root demanded: the FHE seal has no silicon root -> revert, funds stay.
	vault := deploy([32]byte(([32]byte)(seal.ModelCommitment)), []string{"fhe"}, true)
	require.Error(t, release(vault), "vendor-root policy must hold funds")
	require.Equal(t, uint64(500), host.Balance(vault).Uint64())

	// TEE-only policy against an FHE seal -> revert.
	vault = deploy([32]byte(([32]byte)(seal.ModelCommitment)), []string{"tee"}, false)
	require.Error(t, release(vault), "tee-only policy must hold funds")

	// Wrong model commitment -> revert.
	var wrongModel [32]byte
	wrongModel[0] = 0xFF
	vault = deploy(wrongModel, []string{"fhe"}, false)
	require.Error(t, release(vault), "model mismatch must hold funds")

	// Unknown job -> revert (getSealIdByJob fails closed).
	vault = deploy([32]byte(([32]byte)(seal.ModelCommitment)), []string{"fhe"}, false)
	calldata, err := vaultABI.Pack("release", "no-such-job")
	require.NoError(t, err)
	_, err = host.Call(ctx, eoa, vault, calldata, 1_000_000)
	require.Error(t, err)

	require.Zero(t, host.Balance(beneficiary).Uint64(), "no violation path may pay out")
}
