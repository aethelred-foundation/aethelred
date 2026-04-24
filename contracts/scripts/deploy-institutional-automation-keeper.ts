import { ethers, network } from "./lib/hardhat-runtime.js";
import {
  isLocalDeploymentNetwork,
  resolveDeploymentAddress,
} from "./lib/deployment-governance";

const DEFAULT_MAX_ASSETS_PER_RUN = 16n;

function parseAssetIds(raw: string | undefined): string[] {
  if (!raw) return [];
  return raw
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean)
    .map((id) =>
      id.startsWith("0x") && id.length === 66 ? id : ethers.id(id),
    );
}

async function main() {
  const bridgeAddress = process.env.INSTITUTIONAL_BRIDGE_ADDRESS;
  if (!bridgeAddress) {
    throw new Error("INSTITUTIONAL_BRIDGE_ADDRESS is required");
  }

  const ownerAddress = process.env.KEEPER_OWNER_ADDRESS;
  const assetIds = parseAssetIds(process.env.RESERVE_MONITOR_ASSET_IDS);
  const maxAssetsPerRun = process.env.MAX_ASSETS_PER_RUN
    ? BigInt(process.env.MAX_ASSETS_PER_RUN)
    : DEFAULT_MAX_ASSETS_PER_RUN;
  const grantPauserRole = process.env.GRANT_PAUSER_ROLE_TO_KEEPER !== "false";

  const [deployer] = await ethers.getSigners();
  const chainId = Number((await ethers.provider.getNetwork()).chainId);
  const isLocal = isLocalDeploymentNetwork({
    networkName: network.name,
    chainId,
  });
  const initialOwner = resolveDeploymentAddress({
    envName: "KEEPER_OWNER_ADDRESS",
    envValue: ownerAddress,
    deployerAddress: deployer.address,
    isLocal,
  });
  console.log("Deployer:", deployer.address);
  console.log("Institutional bridge:", bridgeAddress);
  console.log("Tracked assets:", assetIds.length);
  console.log("Keeper owner:", initialOwner);

  const Factory = await ethers.getContractFactory(
    "InstitutionalReserveAutomationKeeper",
  );
  const keeper = await Factory.deploy(bridgeAddress, assetIds, initialOwner);
  await keeper.waitForDeployment();

  const keeperAddress = await keeper.getAddress();
  console.log("Automation keeper deployed:", keeperAddress);

  if (maxAssetsPerRun !== DEFAULT_MAX_ASSETS_PER_RUN) {
    await (await keeper.setMaxAssetsPerRun(maxAssetsPerRun)).wait();
  }

  const bridge = await ethers.getContractAt(
    "InstitutionalStablecoinBridge",
    bridgeAddress,
  );
  if (grantPauserRole) {
    const pauserRole = await bridge.PAUSER_ROLE();
    const hasRole = await bridge.hasRole(pauserRole, keeperAddress);
    if (!hasRole) {
      const governanceTimelock = await bridge.governanceTimelock();
      if (governanceTimelock !== ethers.ZeroAddress) {
        const grantRoleCalldata = bridge.interface.encodeFunctionData(
          "grantRole",
          [pauserRole, keeperAddress],
        );
        console.log(
          "Governance timelock is active; queue this role grant through governance before enabling automation:",
        );
        console.log(`  Timelock: ${governanceTimelock}`);
        console.log(`  Target:   ${bridgeAddress}`);
        console.log(`  Calldata: ${grantRoleCalldata}`);
      } else {
        console.log("Granting PAUSER_ROLE to automation keeper...");
        await (await bridge.grantRole(pauserRole, keeperAddress)).wait();
      }
    }
  }

  console.log("Done.");
  console.log(
    JSON.stringify(
      {
        keeperAddress,
        bridgeAddress,
        trackedAssets: assetIds,
        owner: initialOwner,
        maxAssetsPerRun: maxAssetsPerRun.toString(),
      },
      null,
      2,
    ),
  );
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
