/**
 * Hardhat Configuration - Aethelred Bridge Contracts
 *
 * Enterprise-grade configuration for development, testing, and deployment
 * of the AethelredBridge smart contracts across multiple networks.
 *
 * Networks Supported:
 * - devnet: Local DevNet (Anvil/Ganache)
 * - sepolia: Ethereum Sepolia testnet
 * - mainnet: Ethereum Mainnet (production)
 *
 * @author Aethelred Team
 * @license Apache-2.0
 */

import { defineConfig } from "hardhat/config";
import hardhatEthers from "@nomicfoundation/hardhat-ethers";
import hardhatChaiMatchers from "@nomicfoundation/hardhat-ethers-chai-matchers";
import hardhatMocha from "@nomicfoundation/hardhat-mocha";
import hardhatNetworkHelpers from "@nomicfoundation/hardhat-network-helpers";
import hardhatTypechain from "@nomicfoundation/hardhat-typechain";
import * as dotenv from "dotenv";

dotenv.config();

// ============================================================================
// Environment Variables
// ============================================================================

// SECURITY FIX H-03: Only allow Anvil default key for local/dev networks.
// Non-local networks (sepolia, mainnet) MUST provide DEPLOYER_PRIVATE_KEY via env var.
const ANVIL_DEFAULT_KEY =
  "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

function getAccounts(networkName: string): string[] {
  const key = process.env.DEPLOYER_PRIVATE_KEY;
  if (key) return [key];
  // Only allow Anvil default key for local development networks
  if (
    networkName === "hardhat" ||
    networkName === "devnet" ||
    networkName === "localhost"
  ) {
    return [ANVIL_DEFAULT_KEY];
  }
  // Non-local networks: return empty array - deployment will fail with a clear error
  return [];
}

const SEPOLIA_RPC_URL = process.env.SEPOLIA_RPC_URL ||
  "https://eth-sepolia.g.alchemy.com/v2/demo";

const MAINNET_RPC_URL = process.env.MAINNET_RPC_URL ||
  "https://eth-mainnet.g.alchemy.com/v2/demo";

const ALLOW_UNLIMITED_CONTRACT_SIZE =
  process.env.ALLOW_UNLIMITED_CONTRACT_SIZE === "true";

// DevNet configuration (Docker network)
const DEVNET_RPC_URL = process.env.DEVNET_RPC_URL ||
  "http://localhost:8545";

const DEFAULT_SOLIDITY_COMPILER = {
  version: "0.8.20",
  settings: {
    optimizer: {
      enabled: true,
      runs: 200, // Optimized for frequent function calls
      details: {
        yul: true,
        yulDetails: {
          stackAllocation: true,
        },
      },
    },
    viaIR: true, // Preserve IR-based code generation in every build profile.
    evmVersion: "paris",
    metadata: {
      bytecodeHash: "ipfs",
      useLiteralContent: true,
    },
  },
};

const SIZE_OPTIMIZED_SOLIDITY_COMPILER = {
  version: "0.8.20",
  settings: {
    optimizer: {
      enabled: true,
      runs: 1,
      details: {
        yul: true,
        yulDetails: {
          stackAllocation: true,
        },
      },
    },
    viaIR: true,
    evmVersion: "paris",
    metadata: {
      bytecodeHash: "none",
      useLiteralContent: false,
      appendCBOR: false,
    },
  },
};

const SIZE_OPTIMIZED_SOLIDITY_OVERRIDES = {
  // Size-optimized override for the institutional bridge to stay under EIP-170
  // without altering runtime behavior or ABI.
  "contracts/InstitutionalStablecoinBridge.sol": SIZE_OPTIMIZED_SOLIDITY_COMPILER,
  // Size-optimized override for Cruzible to stay under EIP-170 without
  // changing runtime behavior or ABI. This contract concentrates multiple
  // staking and attestation flows, so we optimize deployment size rather
  // than risk a late-stage logic split.
  "contracts/vault/Cruzible.sol": SIZE_OPTIMIZED_SOLIDITY_COMPILER,
};

// ============================================================================
// Hardhat Configuration
// ============================================================================

const config = defineConfig({
  plugins: [
    hardhatEthers,
    hardhatChaiMatchers,
    hardhatMocha,
    hardhatNetworkHelpers,
    hardhatTypechain,
  ],

  // Solidity Compiler Configuration
  solidity: {
    npmFilesToBuild: [
      "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol",
      "@openzeppelin/contracts/governance/TimelockController.sol",
    ],
    profiles: {
      default: {
        compilers: [DEFAULT_SOLIDITY_COMPILER],
        overrides: SIZE_OPTIMIZED_SOLIDITY_OVERRIDES,
      },
      production: {
        compilers: [DEFAULT_SOLIDITY_COMPILER],
        overrides: SIZE_OPTIMIZED_SOLIDITY_OVERRIDES,
      },
    },
  },

  // Network Configuration
  networks: {
    // Local Hardhat Network
    hardhat: {
      type: "edr-simulated",
      chainType: "l1",
      chainId: 31337,
      forking: process.env.FORK_MAINNET === "true" ? {
        url: MAINNET_RPC_URL,
        blockNumber: 18800000, // Pin to specific block for deterministic tests
      } : undefined,
      allowUnlimitedContractSize: ALLOW_UNLIMITED_CONTRACT_SIZE,
      allowBlocksWithSameTimestamp: true,
      mining: {
        auto: true,
        interval: 0,
      },
    },

    // Local DevNet (Anvil in Docker)
    devnet: {
      type: "http",
      chainType: "l1",
      url: DEVNET_RPC_URL,
      chainId: 31337,
      accounts: getAccounts("devnet"),
      timeout: 60000,
      gas: "auto",
      gasPrice: "auto",
    },

    // Sepolia Testnet
    sepolia: {
      type: "http",
      chainType: "l1",
      url: SEPOLIA_RPC_URL,
      chainId: 11155111,
      accounts: getAccounts("sepolia"),
      timeout: 120000,
      gas: "auto",
      gasPrice: "auto",
      // Alchemy/Infura rate limiting settings
      httpHeaders: {},
    },

    // Ethereum Mainnet (Production)
    mainnet: {
      type: "http",
      chainType: "l1",
      url: MAINNET_RPC_URL,
      chainId: 1,
      accounts: getAccounts("mainnet"),
      timeout: 180000,
      gas: "auto",
      gasPrice: "auto",
    },
  },

  // TypeChain Configuration
  typechain: {
    outDir: "typechain-types",
    target: "ethers-v6",
    alwaysGenerateOverloads: true,
    externalArtifacts: ["node_modules/@openzeppelin/contracts/build/contracts/*.json"],
    dontOverrideCompile: false,
  },

  // Paths Configuration
  paths: {
    sources: "./contracts",
    tests: {
      mocha: "./test",
    },
    cache: "./cache",
    artifacts: "./artifacts",
  },

  // Mocha Test Configuration
  test: {
    mocha: {
      timeout: 120000, // 2 minutes for complex tests
      parallel: false, // Disable parallel for state-dependent tests
      retries: process.env.CI ? 2 : 0,
    },
  },
});

export default config;
