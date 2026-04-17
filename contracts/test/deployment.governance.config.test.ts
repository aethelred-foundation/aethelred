import { expect } from "chai";
import {
  isLocalDeploymentNetwork,
  resolveDeploymentAddress,
  resolveTimelockParticipants,
} from "../scripts/lib/deployment-governance";

describe("deployment governance config", function () {
  it("treats local names and chain ids as local deployment contexts", function () {
    expect(
      isLocalDeploymentNetwork({ networkName: "hardhat", chainId: 11155111 }),
    ).to.equal(true);
    expect(
      isLocalDeploymentNetwork({ networkName: "sepolia", chainId: 31337 }),
    ).to.equal(true);
    expect(
      isLocalDeploymentNetwork({ networkName: "sepolia", chainId: 11155111 }),
    ).to.equal(false);
  });

  it("allows deployer fallback only on local deployments", function () {
    expect(
      resolveDeploymentAddress({
        envName: "ADMIN_ADDRESS",
        envValue: undefined,
        deployerAddress: "0x000000000000000000000000000000000000dEaD",
        isLocal: true,
      }),
    ).to.equal("0x000000000000000000000000000000000000dEaD");

    expect(() =>
      resolveDeploymentAddress({
        envName: "ADMIN_ADDRESS",
        envValue: undefined,
        deployerAddress: "0x000000000000000000000000000000000000dEaD",
        isLocal: false,
      })
    ).to.throw("ADMIN_ADDRESS is required for non-local deployments");
  });

  it("preserves explicit governance addresses when provided", function () {
    expect(
      resolveDeploymentAddress({
        envName: "TREASURY_ADDRESS",
        envValue: "0x000000000000000000000000000000000000BEEF",
        deployerAddress: "0x000000000000000000000000000000000000dEaD",
        isLocal: false,
      }),
    ).to.equal("0x000000000000000000000000000000000000BEEF");
  });

  it("requires timelock participants on non-local deployments without a preexisting timelock", function () {
    expect(() =>
      resolveTimelockParticipants({
        explicitTimelockAddress: undefined,
        proposers: [],
        executors: [],
        fallbackAddress: "0x000000000000000000000000000000000000dEaD",
        isLocal: false,
      })
    ).to.throw(
      "TIMELOCK_PROPOSERS and TIMELOCK_EXECUTORS are required for non-local deployments when UPGRADER_TIMELOCK_ADDRESS is not provided",
    );
  });

  it("backfills local timelock participants with the fallback authority", function () {
    const resolved = resolveTimelockParticipants({
      explicitTimelockAddress: undefined,
      proposers: [],
      executors: [],
      fallbackAddress: "0x000000000000000000000000000000000000dEaD",
      isLocal: true,
    });

    expect(resolved.proposers).to.deep.equal([
      "0x000000000000000000000000000000000000dEaD",
    ]);
    expect(resolved.executors).to.deep.equal([
      "0x000000000000000000000000000000000000dEaD",
    ]);
  });

  it("does not require proposer or executor lists when a governance timelock is already configured", function () {
    const resolved = resolveTimelockParticipants({
      explicitTimelockAddress: "0x000000000000000000000000000000000000CAFE",
      proposers: [],
      executors: [],
      fallbackAddress: "0x000000000000000000000000000000000000dEaD",
      isLocal: false,
    });

    expect(resolved.timelockAddress).to.equal(
      "0x000000000000000000000000000000000000CAFE",
    );
    expect(resolved.proposers).to.deep.equal([]);
    expect(resolved.executors).to.deep.equal([]);
  });
});
