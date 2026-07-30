package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"cosmossdk.io/core/store"
	"cosmossdk.io/log"
	storetypes "cosmossdk.io/store/types"
	abci "github.com/cometbft/cometbft/abci/types"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	dbm "github.com/cosmos/cosmos-db"
	"github.com/cosmos/cosmos-sdk/baseapp"
	"github.com/cosmos/cosmos-sdk/codec"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	sdked25519 "github.com/cosmos/cosmos-sdk/crypto/keys/ed25519"
	"github.com/cosmos/cosmos-sdk/runtime"
	sdk "github.com/cosmos/cosmos-sdk/types"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"
	"github.com/stretchr/testify/require"

	pouwkeeper "github.com/aethelred/aethelred/x/pouw/keeper"
	pouwtypes "github.com/aethelred/aethelred/x/pouw/types"
	sealkeeper "github.com/aethelred/aethelred/x/seal/keeper"
	verifykeeper "github.com/aethelred/aethelred/x/verify/keeper"
	verifytee "github.com/aethelred/aethelred/x/verify/tee"
)

type mockStakingKeeper struct {
	validators []stakingtypes.Validator
}

func (m mockStakingKeeper) GetAllValidators(_ context.Context) ([]stakingtypes.Validator, error) {
	return append([]stakingtypes.Validator(nil), m.validators...), nil
}
func (m mockStakingKeeper) GetValidator(_ context.Context, address sdk.ValAddress) (stakingtypes.Validator, error) {
	for _, validator := range m.validators {
		if validator.GetOperator() == address.String() {
			return validator, nil
		}
	}
	return stakingtypes.Validator{}, fmt.Errorf("validator not found")
}
func (m mockStakingKeeper) GetBondedValidatorsByPower(_ context.Context) ([]stakingtypes.Validator, error) {
	return append([]stakingtypes.Validator(nil), m.validators...), nil
}
func (m mockStakingKeeper) GetValidatorByConsAddr(
	_ context.Context,
	address sdk.ConsAddress,
) (stakingtypes.Validator, error) {
	for _, validator := range m.validators {
		publicKey, err := validator.ConsPubKey()
		if err == nil && bytes.Equal(publicKey.Address(), address) {
			return validator, nil
		}
	}
	return stakingtypes.Validator{}, fmt.Errorf("validator not found")
}
func (mockStakingKeeper) GetLastValidatorPower(_ context.Context, _ sdk.ValAddress) (int64, error) {
	return 1, nil
}

type mockBankKeeper struct{}

func (mockBankKeeper) SendCoinsFromModuleToAccount(_ context.Context, _ string, _ sdk.AccAddress, _ sdk.Coins) error {
	return nil
}
func (mockBankKeeper) SendCoinsFromAccountToModule(_ context.Context, _ sdk.AccAddress, _ string, _ sdk.Coins) error {
	return nil
}
func (mockBankKeeper) SendCoinsFromModuleToModule(_ context.Context, _ string, _ string, _ sdk.Coins) error {
	return nil
}
func (mockBankKeeper) BurnCoins(_ context.Context, _ string, _ sdk.Coins) error { return nil }
func (mockBankKeeper) SpendableCoins(_ context.Context, _ sdk.AccAddress) sdk.Coins {
	return sdk.NewCoins()
}

func newTestApp(t *testing.T) *AethelredApp {
	return newTestAppWithValidators(t, nil)
}

func newTestAppWithValidators(
	t *testing.T,
	validators []stakingtypes.Validator,
) *AethelredApp {
	t.Helper()

	logger := log.NewTestLogger(t)
	db := dbm.NewMemDB()
	txDecoder := func(_ []byte) (sdk.Tx, error) { return nil, nil }

	bapp := baseapp.NewBaseApp(Name, logger, db, txDecoder)
	storeKey := storetypes.NewKVStoreKey(pouwtypes.StoreKey)

	app := &AethelredApp{
		BaseApp:            bapp,
		keys:               map[string]*storetypes.KVStoreKey{pouwtypes.StoreKey: storeKey},
		voteExtensionCache: NewVoteExtensionCache(4, "aethelred-test-1"),
	}

	app.MountKVStores(map[string]*storetypes.KVStoreKey{
		pouwtypes.StoreKey: storeKey,
	})
	require.NoError(t, app.LoadLatestVersion())

	reg := codectypes.NewInterfaceRegistry()
	cdc := codec.NewProtoCodec(reg)
	var storeService store.KVStoreService = runtime.NewKVStoreService(storeKey)

	stakingKeeper := mockStakingKeeper{validators: validators}
	app.PouwKeeper = pouwkeeper.NewKeeper(
		cdc,
		storeService,
		stakingKeeper,
		mockBankKeeper{},
		sealkeeper.Keeper{},
		verifykeeper.Keeper{},
		"authority",
	)
	app.consensusHandler = pouwkeeper.NewConsensusHandler(logger, &app.PouwKeeper, nil)
	app.consensusValidatorResolver = stakingKeeper

	return app
}

type signedSealScenario struct {
	app           *AethelredApp
	ctx           sdk.Context
	job           pouwtypes.ComputeJob
	commit        abci.CommitInfo
	extendedVotes []abci.ExtendedVoteInfo
	sealTxs       [][]byte
	finalizedHash []byte
}

type testConsensusSigner struct {
	privateKey *sdked25519.PrivKey
	validator  stakingtypes.Validator
	account    string
	consensus  []byte
}

func newTestConsensusSigner(t *testing.T, operatorSeed byte) testConsensusSigner {
	t.Helper()
	privateKey := sdked25519.GenPrivKey()
	operator := sdk.ValAddress(bytes.Repeat([]byte{operatorSeed}, 20))
	validator, err := stakingtypes.NewValidator(
		operator.String(),
		privateKey.PubKey(),
		stakingtypes.Description{},
	)
	require.NoError(t, err)
	return testConsensusSigner{
		privateKey: privateKey,
		validator:  validator,
		account:    sdk.AccAddress(operator).String(),
		consensus:  append([]byte(nil), privateKey.PubKey().Address()...),
	}
}

func buildSignedSealScenario(t *testing.T, jobID string) signedSealScenario {
	t.Helper()
	voteBlockHash := sha256.Sum256([]byte("proposal-block-at-height-1"))
	return buildSignedSealScenarioWithBlockHashes(
		t,
		jobID,
		voteBlockHash[:],
		voteBlockHash[:],
	)
}

func buildSignedSealScenarioWithBlockHashes(
	t *testing.T,
	jobID string,
	signedVoteBlockHash []byte,
	finalizedBlockHash []byte,
) signedSealScenario {
	t.Helper()
	require.Len(t, signedVoteBlockHash, sha256.Size)
	require.Len(t, finalizedBlockHash, sha256.Size)

	signers := []testConsensusSigner{
		newTestConsensusSigner(t, 0x31),
		newTestConsensusSigner(t, 0x32),
	}
	validators := []stakingtypes.Validator{signers[0].validator, signers[1].validator}
	app := newTestAppWithValidators(t, validators)

	voteTime := time.Date(2026, 7, 25, 8, 0, 0, 0, time.UTC)
	ctx := app.BaseApp.NewContext(true).
		WithBlockHeight(2).
		WithBlockTime(voteTime.Add(30 * time.Minute)).
		WithChainID("aethelred-test-1")
	app.persistLastBlockTime(
		ctx.WithBlockHeight(1).WithBlockTime(voteTime),
	)
	require.NoError(t, app.PouwKeeper.SetParams(ctx, pouwtypes.DefaultParams()))

	modelHash := sha256.Sum256([]byte("signed-seal-model"))
	inputHash := sha256.Sum256([]byte("signed-seal-input"))
	outputHash := sha256.Sum256([]byte("signed-seal-output"))
	assigned := []string{signers[0].account, signers[1].account}
	assignmentJSON, err := json.Marshal(assigned)
	require.NoError(t, err)
	job := pouwtypes.ComputeJob{
		Id:          jobID,
		ModelHash:   modelHash[:],
		InputHash:   inputHash[:],
		RequestedBy: sdk.AccAddress(bytes.Repeat([]byte{0x44}, 20)).String(),
		ProofType:   pouwtypes.ProofTypeHybrid,
		Status:      pouwtypes.JobStatusProcessing,
		BlockHeight: 1,
		Metadata: map[string]string{
			"scheduler.assigned_to": string(assignmentJSON),
		},
	}
	require.NoError(t, app.PouwKeeper.Jobs.Set(ctx, job.Id, job))
	require.NoError(t, app.PouwKeeper.PendingJobs.Set(ctx, job.Id, job))

	require.NoError(t, app.persistFinalizedBlock(
		ctx.WithBlockHeight(1),
		1,
		finalizedBlockHash,
	))
	extendedVotes := make([]abci.ExtendedVoteInfo, 0, len(signers))
	commitVotes := make([]abci.VoteInfo, 0, len(signers))
	for index, signer := range signers {
		extensionNonce := bytes.Repeat([]byte{byte(index + 1)}, 32)
		verificationNonce := bytes.Repeat([]byte{byte(index + 11)}, 32)
		userData := verifytee.ComputeAttestationUserData(
			outputHash[:],
			1,
			ctx.ChainID(),
		)
		verification := ComputeVerification{
			JobID:           job.Id,
			ModelHash:       modelHash[:],
			InputHash:       inputHash[:],
			OutputHash:      outputHash[:],
			AttestationType: AttestationTypeHybrid,
			TEEAttestation: &TEEAttestationData{
				Platform:         "arm-trustzone",
				EnclaveID:        fmt.Sprintf("enclave-%d", index),
				Measurement:      bytes.Repeat([]byte{byte(0x80 + index)}, 32),
				Quote:            bytes.Repeat([]byte{byte(0x90 + index)}, 128),
				UserData:         userData,
				CertificateChain: [][]byte{bytes.Repeat([]byte{byte(0xA0 + index)}, 32)},
				Timestamp:        voteTime,
				Nonce:            verificationNonce,
				BlockHeight:      1,
				ChainID:          ctx.ChainID(),
			},
			ZKProof: &ZKProofData{
				ProofSystem:      "ezkl",
				Proof:            bytes.Repeat([]byte{byte(0xB0 + index)}, 256),
				PublicInputs:     append([]byte(nil), outputHash[:]...),
				VerifyingKeyHash: bytes.Repeat([]byte{0xC0}, 32),
				CircuitHash:      bytes.Repeat([]byte{0xD0}, 32),
				ProofSize:        256,
			},
			ExecutionTimeMs:           int64(index + 1),
			Success:                   true,
			Nonce:                     verificationNonce,
			ValidatorSignatureVersion: ComputeVerificationSignatureVersion,
			VoteBlockHash:             append([]byte(nil), signedVoteBlockHash...),
			ExtensionNonce:            extensionNonce,
		}
		require.NoError(t, signComputeVerification(
			&verification,
			1,
			ctx.ChainID(),
			signer.consensus,
			voteTime,
			ed25519.PrivateKey(signer.privateKey.Bytes()),
		))

		extension := NewVoteExtensionAtBlockTime(1, signer.consensus, voteTime)
		extension.ChainID = ctx.ChainID()
		extension.Nonce = extensionNonce
		extension.AddVerification(verification)
		require.NoError(t, SignVoteExtension(
			extension,
			ed25519.PrivateKey(signer.privateKey.Bytes()),
		))
		extensionBytes, err := extension.Marshal()
		require.NoError(t, err)
		extendedVotes = append(extendedVotes, abci.ExtendedVoteInfo{
			Validator:     abci.Validator{Address: signer.consensus, Power: 1},
			VoteExtension: extensionBytes,
			BlockIdFlag:   cmtproto.BlockIDFlagCommit,
		})
		commitVotes = append(commitVotes, abci.VoteInfo{
			Validator:   abci.Validator{Address: signer.consensus, Power: 1},
			BlockIdFlag: cmtproto.BlockIDFlagCommit,
		})
	}

	results := app.consensusHandler.AggregateVoteExtensions(ctx, extendedVotes)
	sealTxs := app.consensusHandler.CreateSealTransactions(ctx, results)
	require.Len(t, sealTxs, 1)
	return signedSealScenario{
		app:           app,
		ctx:           ctx,
		job:           job,
		commit:        abci.CommitInfo{Round: 0, Votes: commitVotes},
		extendedVotes: extendedVotes,
		sealTxs:       sealTxs,
		finalizedHash: append([]byte(nil), finalizedBlockHash...),
	}
}

func TestProcessProposal_FinalityAcceptsValidInjectedTx(t *testing.T) {
	scenario := buildSignedSealScenario(t, "job-finality-ok")
	resp, err := scenario.app.ProcessProposalHandler()(scenario.ctx, &abci.RequestProcessProposal{
		Height:             2,
		Txs:                scenario.sealTxs,
		ProposedLastCommit: scenario.commit,
	})
	require.NoError(t, err)
	require.Equal(t, abci.ResponseProcessProposal_ACCEPT, resp.Status)
}

func TestProcessProposal_AllowsOmittedOptionalSealCertificate(t *testing.T) {
	scenario := buildSignedSealScenario(t, "job-finality-optional")
	resp, err := scenario.app.ProcessProposalHandler()(scenario.ctx, &abci.RequestProcessProposal{
		Height:             2,
		Txs:                nil,
		ProposedLastCommit: scenario.commit,
	})
	require.NoError(t, err)
	require.Equal(t, abci.ResponseProcessProposal_ACCEPT, resp.Status)
}

func TestProcessProposal_FinalityRejectsTamperedConsensusPower(t *testing.T) {
	scenario := buildSignedSealScenario(t, "job-finality-tampered-power")

	// Tamper tx consensus-power fields so tx-level validation still passes
	// while app-level recomputation should reject it.
	var txMap map[string]interface{}
	require.NoError(t, json.Unmarshal(scenario.sealTxs[0], &txMap))
	txMap["total_power"] = float64(1)
	txMap["agreement_power"] = float64(1)
	txMap["total_votes"] = float64(1)
	txMap["validator_count"] = float64(1)
	tampered, err := json.Marshal(txMap)
	require.NoError(t, err)

	resp, err := scenario.app.ProcessProposalHandler()(scenario.ctx, &abci.RequestProcessProposal{
		Height:             2,
		Txs:                [][]byte{tampered},
		ProposedLastCommit: scenario.commit,
	})
	require.NoError(t, err)
	require.Equal(t, abci.ResponseProcessProposal_REJECT, resp.Status)
}

func TestProcessProposal_FinalityAcceptsNoInjectedTxWithEmptyCachedExtensions(t *testing.T) {
	app := newTestApp(t)
	ctx := app.BaseApp.NewContext(true).WithBlockHeight(2).WithBlockTime(time.Now().UTC())

	require.NoError(t, app.PouwKeeper.SetParams(ctx, pouwtypes.DefaultParams()))

	addr1 := []byte("validator-addr-1")
	addr2 := []byte("validator-addr-2")
	app.voteExtensionCache.Store(1, addr1, []byte{})
	app.voteExtensionCache.Store(1, addr2, []byte{})

	commit := abci.CommitInfo{
		Round: 0,
		Votes: []abci.VoteInfo{
			{Validator: abci.Validator{Address: addr1, Power: 1}, BlockIdFlag: cmtproto.BlockIDFlagCommit},
			{Validator: abci.Validator{Address: addr2, Power: 1}, BlockIdFlag: cmtproto.BlockIDFlagCommit},
		},
	}

	handler := app.ProcessProposalHandler()
	resp, err := handler(ctx, &abci.RequestProcessProposal{
		Height:             2,
		Txs:                nil,
		ProposedLastCommit: commit,
	})
	require.NoError(t, err)
	require.Equal(t, abci.ResponseProcessProposal_ACCEPT, resp.Status)
}

func TestProcessProposal_FinalityRejectsInjectedTxWhenCacheMissing(t *testing.T) {
	// PR-04/VC-01: When the vote extension cache is empty (e.g. after a node
	// restart), ProcessProposal degrades gracefully — it relies on the
	// deterministic on-chain consensus evidence audit and per-tx validation
	// rather than rejecting outright.  A valid seal transaction with a
	// matching on-chain job should therefore be ACCEPTED even when the cache
	// has no entries for the relevant height.
	scenario := buildSignedSealScenario(t, "job-cache-miss")
	scenario.app.voteExtensionCache = NewVoteExtensionCache(4, scenario.ctx.ChainID())
	resp, err := scenario.app.ProcessProposalHandler()(scenario.ctx, &abci.RequestProcessProposal{
		Height:             2,
		Txs:                scenario.sealTxs,
		ProposedLastCommit: scenario.commit,
	})
	require.NoError(t, err)
	// Cache is empty → graceful degradation accepts valid on-chain evidence.
	require.Equal(t, abci.ResponseProcessProposal_ACCEPT, resp.Status)
}

func TestSelfContainedSealEvidenceRejectsSignedFieldTampering(t *testing.T) {
	scenario := buildSignedSealScenario(t, "job-tamper-matrix")
	require.NoError(t, scenario.app.validateSelfContainedSealEvidence(
		scenario.ctx,
		scenario.sealTxs[0],
		scenario.commit,
		scenario.finalizedHash,
	))

	mutations := map[string]func(*pouwkeeper.SealCreationTx){
		"job": func(tx *pouwkeeper.SealCreationTx) {
			tx.JobID += "-tampered"
		},
		"model": func(tx *pouwkeeper.SealCreationTx) {
			tx.ModelHash[0] ^= 0xFF
		},
		"input": func(tx *pouwkeeper.SealCreationTx) {
			tx.InputHash[0] ^= 0xFF
		},
		"output": func(tx *pouwkeeper.SealCreationTx) {
			tx.OutputHash[0] ^= 0xFF
		},
		"tee": func(tx *pouwkeeper.SealCreationTx) {
			tx.ValidatorResults[0].TEEAttestation.Quote[0] ^= 0xFF
		},
		"zk": func(tx *pouwkeeper.SealCreationTx) {
			tx.ValidatorResults[0].ZKProof.Proof[0] ^= 0xFF
		},
		"nonce": func(tx *pouwkeeper.SealCreationTx) {
			tx.ValidatorResults[0].Nonce[0] ^= 0xFF
		},
		"execution_time": func(tx *pouwkeeper.SealCreationTx) {
			tx.ValidatorResults[0].ExecutionTimeMs++
		},
		"timestamp": func(tx *pouwkeeper.SealCreationTx) {
			tx.ValidatorResults[0].Timestamp =
				tx.ValidatorResults[0].Timestamp.Add(time.Second)
		},
		"height": func(tx *pouwkeeper.SealCreationTx) {
			tx.BlockHeight++
		},
		"chain": func(tx *pouwkeeper.SealCreationTx) {
			tx.ValidatorResults[0].TEEAttestation.ChainID = "other-chain"
		},
		"signer": func(tx *pouwkeeper.SealCreationTx) {
			tx.ValidatorResults[0].ValidatorConsensusAddress[0] ^= 0xFF
		},
		"account": func(tx *pouwkeeper.SealCreationTx) {
			tx.ValidatorResults[0].ValidatorAddress =
				sdk.AccAddress(bytes.Repeat([]byte{0xEE}, 20)).String()
		},
		"signature": func(tx *pouwkeeper.SealCreationTx) {
			tx.ValidatorResults[0].ValidatorSignature[0] ^= 0xFF
		},
		"signature_version": func(tx *pouwkeeper.SealCreationTx) {
			tx.ValidatorResults[0].ValidatorSignatureVersion++
		},
		"extension_nonce": func(tx *pouwkeeper.SealCreationTx) {
			tx.ValidatorResults[0].ExtensionNonce[0] ^= 0xFF
		},
		"vote_block_hash": func(tx *pouwkeeper.SealCreationTx) {
			tx.ValidatorResults[0].VoteBlockHash[0] ^= 0xFF
		},
	}

	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			var tx pouwkeeper.SealCreationTx
			require.NoError(t, json.Unmarshal(scenario.sealTxs[0], &tx))
			mutate(&tx)
			tampered, err := json.Marshal(tx)
			require.NoError(t, err)
			require.Error(t, scenario.app.validateSelfContainedSealEvidence(
				scenario.ctx,
				tampered,
				scenario.commit,
				scenario.finalizedHash,
			))
		})
	}
}

func TestSelfContainedSealEvidenceRejectsQuorumTampering(t *testing.T) {
	scenario := buildSignedSealScenario(t, "job-quorum-tamper")

	t.Run("duplicate signer", func(t *testing.T) {
		var tx pouwkeeper.SealCreationTx
		require.NoError(t, json.Unmarshal(scenario.sealTxs[0], &tx))
		tx.ValidatorResults = append(tx.ValidatorResults, tx.ValidatorResults[0])
		tx.ValidatorCount = len(tx.ValidatorResults)
		tampered, err := json.Marshal(tx)
		require.NoError(t, err)
		require.Error(t, scenario.app.validateSelfContainedSealEvidence(
			scenario.ctx,
			tampered,
			scenario.commit,
			scenario.finalizedHash,
		))
	})

	t.Run("non commit signer", func(t *testing.T) {
		commit := scenario.commit
		commit.Votes = append([]abci.VoteInfo(nil), scenario.commit.Votes...)
		commit.Votes[0].BlockIdFlag = cmtproto.BlockIDFlagAbsent
		require.Error(t, scenario.app.validateSelfContainedSealEvidence(
			scenario.ctx,
			scenario.sealTxs[0],
			commit,
			scenario.finalizedHash,
		))
	})

	t.Run("claimed agreement power", func(t *testing.T) {
		var tx pouwkeeper.SealCreationTx
		require.NoError(t, json.Unmarshal(scenario.sealTxs[0], &tx))
		tx.AgreementPower--
		tampered, err := json.Marshal(tx)
		require.NoError(t, err)
		require.Error(t, scenario.app.validateSelfContainedSealEvidence(
			scenario.ctx,
			tampered,
			scenario.commit,
			scenario.finalizedHash,
		))
	})
}

func TestProcessProposal_RejectsDuplicateInjectedConsensusTxForJob(t *testing.T) {
	app := newTestApp(t)
	ctx := app.BaseApp.NewContext(true).WithBlockHeight(2).WithBlockTime(time.Now().UTC())

	params := pouwtypes.DefaultParams()
	params.AllowSimulated = true // disable production finality path for this wiring test
	require.NoError(t, app.PouwKeeper.SetParams(ctx, params))

	modelHash := make32Bytes()
	inputHash := make32Bytes()
	outputHash := make32Bytes()

	job := pouwtypes.ComputeJob{
		Id:          "job-duplicate-injected",
		ModelHash:   modelHash,
		InputHash:   inputHash,
		RequestedBy: "requester",
		ProofType:   pouwtypes.ProofTypeTEE,
		Status:      pouwtypes.JobStatusPending,
		BlockHeight: ctx.BlockHeight(),
	}
	require.NoError(t, app.PouwKeeper.Jobs.Set(ctx, job.Id, job))

	commit := abci.CommitInfo{
		Round: 0,
		Votes: []abci.VoteInfo{
			{Validator: abci.Validator{Address: []byte("validator-addr-1"), Power: 1}, BlockIdFlag: cmtproto.BlockIDFlagCommit},
			{Validator: abci.Validator{Address: []byte("validator-addr-2"), Power: 1}, BlockIdFlag: cmtproto.BlockIDFlagCommit},
		},
	}

	tx1 := mustMarshalInjected(t, job.Id, outputHash, 2, 2, 2, 2)
	tx2 := mustMarshalInjected(t, job.Id, outputHash, 2, 2, 2, 2)

	handler := app.ProcessProposalHandler()
	resp, err := handler(ctx, &abci.RequestProcessProposal{
		Height:             2,
		Txs:                [][]byte{tx1, tx2},
		ProposedLastCommit: commit,
	})
	require.NoError(t, err)
	require.Equal(t, abci.ResponseProcessProposal_REJECT, resp.Status)
}
