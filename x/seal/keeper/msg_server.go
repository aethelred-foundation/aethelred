package keeper

import (
	"context"
	"fmt"

	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/aethelred/aethelred/x/seal/types"
)

type msgServer struct {
	types.UnimplementedMsgServer
	Keeper
}

// NewMsgServerImpl returns an implementation of the MsgServer interface
func NewMsgServerImpl(keeper Keeper) types.MsgServer {
	return &msgServer{Keeper: keeper}
}

var _ types.MsgServer = msgServer{}

// CreateSeal handles MsgCreateSeal
func (k msgServer) CreateSeal(goCtx context.Context, msg *types.MsgCreateSeal) (*types.MsgCreateSealResponse, error) {
	// Digital Seals are consensus-derived state. Accepting caller-supplied TEE
	// attestations or ZK proofs here would let an ordinary signed account mint
	// an apparently verified seal without passing the PoUW verification path.
	//
	// Keep the protobuf method for wire compatibility, but fail closed. The
	// PoUW keeper creates seals internally only after verified validator
	// results reach consensus.
	return nil, fmt.Errorf("direct seal creation is disabled; seals are created from verified PoUW consensus")
}

// RevokeSeal handles MsgRevokeSeal
func (k msgServer) RevokeSeal(goCtx context.Context, msg *types.MsgRevokeSeal) (*types.MsgRevokeSealResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	// Get the existing seal
	seal, err := k.Keeper.GetSeal(ctx, msg.SealId)
	if err != nil {
		return nil, fmt.Errorf("seal not found: %s", msg.SealId)
	}

	// Seal creators may self-revoke immediately. Module authority must use the
	// governed revocation workflow instead of bypassing dispute/approval controls.
	if msg.Authority == k.GetAuthority() {
		return nil, fmt.Errorf("module authority must use governed revocation workflow")
	}
	if msg.Authority != seal.RequestedBy {
		return nil, fmt.Errorf("unauthorized: only seal creator can revoke directly")
	}

	// Revoke the seal
	if err := k.Keeper.revokeSealDirect(ctx, msg.SealId, msg.Reason); err != nil {
		return nil, err
	}

	return &types.MsgRevokeSealResponse{}, nil
}
