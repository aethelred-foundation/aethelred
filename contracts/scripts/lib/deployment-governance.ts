export interface DeploymentNetworkContext {
  networkName: string;
  chainId: number;
}

interface ResolveDeploymentAddressOptions {
  envName: string;
  envValue?: string | null;
  deployerAddress: string;
  isLocal: boolean;
  localDefault?: string;
}

interface ResolveTimelockParticipantsOptions {
  explicitTimelockAddress?: string | null;
  proposers: string[];
  executors: string[];
  fallbackAddress: string;
  isLocal: boolean;
}

interface ResolvedTimelockParticipants {
  timelockAddress?: string;
  proposers: string[];
  executors: string[];
}

const LOCAL_NETWORK_NAMES = new Set(["hardhat", "devnet", "localhost"]);
const LOCAL_CHAIN_IDS = new Set([31337, 1337]);

function normalizeOptionalAddress(value?: string | null): string | undefined {
  const normalized = value?.trim();
  return normalized && normalized.length > 0 ? normalized : undefined;
}

export function isLocalDeploymentNetwork(
  context: DeploymentNetworkContext,
): boolean {
  return LOCAL_NETWORK_NAMES.has(context.networkName) ||
    LOCAL_CHAIN_IDS.has(context.chainId);
}

export function resolveDeploymentAddress(
  options: ResolveDeploymentAddressOptions,
): string {
  const explicitAddress = normalizeOptionalAddress(options.envValue);
  if (explicitAddress) {
    return explicitAddress;
  }

  if (options.isLocal) {
    return normalizeOptionalAddress(options.localDefault) ?? options.deployerAddress;
  }

  throw new Error(`${options.envName} is required for non-local deployments`);
}

export function resolveTimelockParticipants(
  options: ResolveTimelockParticipantsOptions,
): ResolvedTimelockParticipants {
  const timelockAddress = normalizeOptionalAddress(options.explicitTimelockAddress);
  if (timelockAddress) {
    return {
      timelockAddress,
      proposers: [...options.proposers],
      executors: [...options.executors],
    };
  }

  if (!options.isLocal &&
    (options.proposers.length === 0 || options.executors.length === 0)) {
    throw new Error(
      "TIMELOCK_PROPOSERS and TIMELOCK_EXECUTORS are required for non-local deployments when UPGRADER_TIMELOCK_ADDRESS is not provided",
    );
  }

  return {
    proposers: options.proposers.length > 0
      ? [...options.proposers]
      : [options.fallbackAddress],
    executors: options.executors.length > 0
      ? [...options.executors]
      : [options.fallbackAddress],
  };
}
