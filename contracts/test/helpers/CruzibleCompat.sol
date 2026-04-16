// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import "../../contracts/vault/Cruzible.sol";

library CruzibleCompat {
    function ORACLE_ROLE(Cruzible) internal pure returns (bytes32) {
        return keccak256("ORACLE_ROLE");
    }

    function GUARDIAN_ROLE(Cruzible) internal pure returns (bytes32) {
        return keccak256("GUARDIAN_ROLE");
    }

    function KEEPER_ROLE(Cruzible) internal pure returns (bytes32) {
        return keccak256("KEEPER_ROLE");
    }

    function UPGRADER_ROLE(Cruzible) internal pure returns (bytes32) {
        return keccak256("UPGRADER_ROLE");
    }

    function DELEGATION_ATTESTOR_ROLE(Cruzible) internal pure returns (bytes32) {
        return keccak256("DELEGATION_ATTESTOR_ROLE");
    }

    function KEEPER_BOND_MINIMUM(Cruzible) internal pure returns (uint256) {
        return 100_000 ether;
    }

    function CHALLENGE_BOND(Cruzible) internal pure returns (uint256) {
        return 10_000 ether;
    }

    function DELEGATION_CHALLENGE_PERIOD(Cruzible) internal pure returns (uint256) {
        return 1 hours;
    }

    function DELEGATION_MAX_AGE(Cruzible) internal pure returns (uint256) {
        return 6 hours;
    }

    function CHALLENGE_ADJUDICATION_PERIOD(Cruzible) internal pure returns (uint256) {
        return 24 hours;
    }

    function getTotalPooledAethel(Cruzible self) internal view returns (uint256) {
        return self.totalPooledAethel();
    }

    function getCurrentEpoch(Cruzible self) internal view returns (uint256) {
        return self.currentEpoch();
    }

    function getEpochSnapshot(
        Cruzible self,
        uint256 epoch
    )
        internal
        view
        returns (Cruzible.EpochSnapshot memory snap)
    {
        (
            snap.totalPooledAethel,
            snap.totalShares,
            snap.rewardsDistributed,
            snap.mevRedistributed,
            snap.protocolFee,
            snap.rewardsMerkleRoot,
            snap.validatorSetHash,
            snap.eligibleUniverseHash,
            snap.stakeSnapshotHash,
            snap.stakerRegistryRoot,
            snap.delegationRegistryRoot,
            snap.teeAttestationHash,
            snap.timestamp,
            snap.finalized
        ) = self.epochSnapshots(epoch);
    }

    function getValidator(
        Cruzible self,
        address validatorAddress
    )
        internal
        view
        returns (Cruzible.ValidatorInfo memory info)
    {
        (
            info.validatorAddress,
            info.delegatedStake,
            info.performanceScore,
            info.decentralizationScore,
            info.reputationScore,
            info.compositeScore,
            info.teePublicKey,
            info.commission,
            info.activeSince,
            info.slashCount,
            info.isActive
        ) = self.validators(validatorAddress);
    }

    function getActiveValidators(
        Cruzible self
    )
        internal
        view
        returns (address[] memory validators_)
    {
        uint256 count = self.getActiveValidatorCount();
        validators_ = new address[](count);
        for (uint256 i = 0; i < count; i++) {
            validators_[i] = self.activeValidators(i);
        }
    }

    function getUserWithdrawals(
        Cruzible self,
        address user
    )
        internal
        view
        returns (uint256[] memory withdrawalIds)
    {
        uint256 count = self.getUserWithdrawalCount(user);
        withdrawalIds = new uint256[](count);
        for (uint256 i = 0; i < count; i++) {
            withdrawalIds[i] = self.userWithdrawals(user, i);
        }
    }

    function getDelegationEpochAttestors(
        Cruzible self,
        uint256 epoch
    )
        internal
        view
        returns (address[] memory attestors)
    {
        uint256 count = self.getDelegationEpochAttestorCount(epoch);
        attestors = new address[](count);
        for (uint256 i = 0; i < count; i++) {
            attestors[i] = self.delegationEpochAttestors(epoch, i);
        }
    }

    function getAvailableBalance(Cruzible self) internal view returns (uint256) {
        uint256 balance = self.aethelToken().balanceOf(address(self));
        uint256 committed = self.totalPendingWithdrawals() + self.totalReservedForClaims();
        if (balance <= committed) {
            return 0;
        }
        return balance - committed;
    }

    function getEffectiveAPY(Cruzible self) internal view returns (uint256 apy) {
        if (self.currentEpoch() <= 1 || self.totalPooledAethel() == 0) {
            return 0;
        }

        Cruzible.EpochSnapshot memory lastEpoch = getEpochSnapshot(self, self.currentEpoch() - 1);
        if (!lastEpoch.finalized || lastEpoch.totalPooledAethel == 0) {
            return 0;
        }

        uint256 netRewards = lastEpoch.rewardsDistributed - lastEpoch.protocolFee;
        uint256 netMEV = (lastEpoch.mevRedistributed * 9000) / 10_000;
        uint256 epochYield = netRewards + netMEV;
        uint256 dailyRate = (epochYield * 1e18) / lastEpoch.totalPooledAethel;
        return (dailyRate * 365 * 10_000) / 1e18;
    }
}
