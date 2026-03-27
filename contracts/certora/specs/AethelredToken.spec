// SPDX-License-Identifier: Apache-2.0
// Certora Verification Language (CVL) specification for AethelredToken
//
// SQ14 Formal Methods Execution - Tier 1 Target
// Contract: contracts/AethelredToken.sol
//
// Properties verified:
//   1. Supply cap invariant (totalSupply <= TOTAL_SUPPLY_CAP)
//   2. Blacklist transfer blocking
//   3. Mint supply cap enforcement
//   4. Burn accounting consistency (totalBurned tracks all burns)
//   5. Pause halts all transfers
//   6. Transfer restriction enforcement

// =============================================================================
// METHOD DECLARATIONS
// =============================================================================

methods {
    // ERC20 core
    function totalSupply() external returns (uint256) envfree;
    function balanceOf(address) external returns (uint256) envfree;
    function allowance(address, address) external returns (uint256) envfree;
    function transfer(address, uint256) external returns (bool);
    function transferFrom(address, address, uint256) external returns (bool);
    function approve(address, uint256) external returns (bool);

    // Token-specific constants
    function TOTAL_SUPPLY_CAP() external returns (uint256) envfree;
    function decimals() external returns (uint8) envfree;

    // Compliance state
    function blacklisted(address) external returns (bool) envfree;
    function whitelisted(address) external returns (bool) envfree;
    function transferRestrictionsEnabled() external returns (bool) envfree;
    function paused() external returns (bool) envfree;
    function authorizedBridges(address) external returns (bool) envfree;

    // Burn tracking
    function totalBurned() external returns (uint256) envfree;

    // Minting
    function mint(address, uint256) external;

    // Burning
    function burn(uint256) external;
    function burnFrom(address, uint256) external;
    function complianceBurn(address, uint256, bytes32) external;
    function adminBurn(address, uint256) external;

    // Bridge functions
    function bridgeMint(address, uint256) external;
    function bridgeBurn(address, uint256) external;

    // View functions
    function remainingMintable() external returns (uint256) envfree;
    function circulatingSupply() external returns (uint256) envfree;
    function canTransfer(address) external returns (bool) envfree;
}

// =============================================================================
// INVARIANTS
// =============================================================================

/// @title Total supply never exceeds the 10 billion cap
/// @notice This is the most critical safety property for the token economics
invariant totalSupplyBounded()
    totalSupply() <= TOTAL_SUPPLY_CAP();

/// @title Remaining mintable is consistent with supply cap
invariant remainingMintableConsistent()
    remainingMintable() == TOTAL_SUPPLY_CAP() - totalSupply();

/// @title Circulating supply equals total supply (by contract definition)
invariant circulatingSupplyConsistent()
    circulatingSupply() == totalSupply();

// =============================================================================
// SUPPLY CAP RULES
// =============================================================================

/// @title Minting increases total supply by exact amount
rule mintExactAmount(address to, uint256 amount) {
    env e;
    uint256 supplyBefore = totalSupply();
    uint256 balanceBefore = balanceOf(to);

    mint(e, to, amount);

    assert totalSupply() == supplyBefore + amount,
        "Total supply must increase by exact mint amount";
    assert balanceOf(to) == balanceBefore + amount,
        "Recipient balance must increase by exact mint amount";
}

/// @title Minting reverts when it would exceed supply cap
rule mintCannotExceedCap(address to, uint256 amount) {
    env e;

    require totalSupply() + amount > TOTAL_SUPPLY_CAP();

    mint@withrevert(e, to, amount);

    assert lastReverted,
        "Mint must revert when total supply would exceed cap";
}

/// @title Bridge minting also enforces supply cap
rule bridgeMintCannotExceedCap(address to, uint256 amount) {
    env e;

    require totalSupply() + amount > TOTAL_SUPPLY_CAP();

    bridgeMint@withrevert(e, to, amount);

    assert lastReverted,
        "Bridge mint must revert when total supply would exceed cap";
}

// =============================================================================
// BLACKLIST RULES
// =============================================================================

/// @title Blacklisted sender cannot transfer
rule blacklistedSenderCannotTransfer(address to, uint256 amount) {
    env e;

    require blacklisted(e.msg.sender);

    transfer@withrevert(e, to, amount);

    assert lastReverted,
        "Blacklisted sender must not be able to transfer";
}

/// @title Blacklisted recipient cannot receive transfers
rule blacklistedRecipientCannotReceive(address to, uint256 amount) {
    env e;

    require blacklisted(to);
    require !blacklisted(e.msg.sender);

    transfer@withrevert(e, to, amount);

    assert lastReverted,
        "Blacklisted recipient must not receive transfers";
}

/// @title Blacklisted sender cannot use transferFrom
rule blacklistedCannotTransferFrom(address from, address to, uint256 amount) {
    env e;

    require blacklisted(from);

    transferFrom@withrevert(e, from, to, amount);

    assert lastReverted,
        "Blacklisted address in from position must block transferFrom";
}

/// @title Minting to blacklisted address reverts
rule cannotMintToBlacklisted(address to, uint256 amount) {
    env e;

    require blacklisted(to);

    mint@withrevert(e, to, amount);

    assert lastReverted,
        "Cannot mint tokens to a blacklisted address";
}

/// @title Bridge mint to blacklisted address reverts
rule cannotBridgeMintToBlacklisted(address to, uint256 amount) {
    env e;

    require blacklisted(to);

    bridgeMint@withrevert(e, to, amount);

    assert lastReverted,
        "Cannot bridge-mint tokens to a blacklisted address";
}

// =============================================================================
// BURN ACCOUNTING RULES
// =============================================================================

/// @title Burn increases totalBurned by exact amount
rule burnTracksAmount(uint256 amount) {
    env e;
    uint256 burnedBefore = totalBurned();
    uint256 supplyBefore = totalSupply();

    burn(e, amount);

    assert totalBurned() == burnedBefore + amount,
        "totalBurned must increase by exact burn amount";
    assert totalSupply() == supplyBefore - amount,
        "totalSupply must decrease by exact burn amount";
}

/// @title BurnFrom increases totalBurned by exact amount
rule burnFromTracksAmount(address account, uint256 amount) {
    env e;
    uint256 burnedBefore = totalBurned();

    burnFrom(e, account, amount);

    assert totalBurned() == burnedBefore + amount,
        "totalBurned must increase by exact burnFrom amount";
}

/// @title ComplianceBurn increases totalBurned by exact amount
rule complianceBurnTracksAmount(address account, uint256 amount, bytes32 reason) {
    env e;
    uint256 burnedBefore = totalBurned();

    complianceBurn(e, account, amount, reason);

    assert totalBurned() == burnedBefore + amount,
        "totalBurned must increase by exact complianceBurn amount";
}

/// @title ComplianceBurn requires non-zero reason
rule complianceBurnRequiresReason(address account, uint256 amount) {
    env e;
    bytes32 zeroReason = to_bytes32(0);

    complianceBurn@withrevert(e, account, amount, zeroReason);

    assert lastReverted,
        "complianceBurn must revert with zero reason code";
}

// =============================================================================
// PAUSE RULES
// =============================================================================

/// @title When paused, transfers revert
rule pausedBlocksTransfer(address to, uint256 amount) {
    env e;

    require paused();

    transfer@withrevert(e, to, amount);

    assert lastReverted,
        "Transfers must revert when contract is paused";
}

/// @title When paused, transferFrom reverts
rule pausedBlocksTransferFrom(address from, address to, uint256 amount) {
    env e;

    require paused();

    transferFrom@withrevert(e, from, to, amount);

    assert lastReverted,
        "TransferFrom must revert when contract is paused";
}

// =============================================================================
// TRANSFER RESTRICTION RULES
// =============================================================================

/// @title Non-whitelisted cannot transfer when restrictions are enabled
rule transferRestrictionsEnforced(address to, uint256 amount) {
    env e;

    require transferRestrictionsEnabled();
    require !whitelisted(e.msg.sender);
    require !blacklisted(e.msg.sender);
    require !blacklisted(to);
    require !paused();

    transfer@withrevert(e, to, amount);

    assert lastReverted,
        "Non-whitelisted address must not transfer when restrictions enabled";
}

// =============================================================================
// CONSERVATION RULES
// =============================================================================

/// @title Transfer preserves total supply
rule transferPreservesTotalSupply(address to, uint256 amount) {
    env e;
    uint256 supplyBefore = totalSupply();

    transfer(e, to, amount);

    assert totalSupply() == supplyBefore,
        "Transfer must not change total supply";
}

/// @title Transfer is a zero-sum operation between sender and receiver
rule transferConservesBalance(address to, uint256 amount) {
    env e;

    require e.msg.sender != to; // distinct addresses

    uint256 senderBefore = balanceOf(e.msg.sender);
    uint256 recipientBefore = balanceOf(to);

    transfer(e, to, amount);

    assert balanceOf(e.msg.sender) == senderBefore - amount,
        "Sender balance must decrease by transfer amount";
    assert balanceOf(to) == recipientBefore + amount,
        "Recipient balance must increase by transfer amount";
}
