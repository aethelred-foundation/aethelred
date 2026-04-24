import { network as hardhatNetwork } from "hardhat";
import type { BaseContract, ContractFactory } from "ethers";

const connection = await hardhatNetwork.create();

export const ethers = connection.ethers;
export const networkHelpers = connection.networkHelpers;
export const time = networkHelpers.time;
export const mine = networkHelpers.mine;

const IMPLEMENTATION_SLOT =
  "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";

type DeployProxyOptions = {
  initializer?: string | false;
};

async function deployProxy(
  factory: ContractFactory,
  args: unknown[] = [],
  options: DeployProxyOptions = {},
): Promise<BaseContract> {
  const implementation = await factory.deploy();
  await implementation.waitForDeployment();

  const initializer = options.initializer ?? "initialize";
  const initData =
    initializer === false
      ? "0x"
      : factory.interface.encodeFunctionData(initializer, args);

  const proxyFactory = await ethers.getContractFactory("ERC1967Proxy");
  const proxy = await proxyFactory.deploy(
    await implementation.getAddress(),
    initData,
  );
  await proxy.waitForDeployment();

  return factory.attach(await proxy.getAddress());
}

async function getImplementationAddress(proxyAddress: string): Promise<string> {
  const slot = await ethers.provider.getStorage(proxyAddress, IMPLEMENTATION_SLOT);
  return ethers.getAddress(`0x${slot.slice(-40)}`);
}

export const upgrades = {
  deployProxy,
  erc1967: {
    getImplementationAddress,
  },
};
