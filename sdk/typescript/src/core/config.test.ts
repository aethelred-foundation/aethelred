import { describe, expect, it } from "vitest";

import { DEFAULT_CONFIG, NETWORK_CONFIGS, Network, resolveConfig } from "./config";

describe("core/config", () => {
  it("uses mainnet defaults when config is empty", () => {
    const cfg = resolveConfig({});

    expect(cfg.network).toBe(Network.MAINNET);
    expect(cfg.rpcUrl).toBe(NETWORK_CONFIGS[Network.MAINNET].rpcUrl);
    expect(cfg.chainId).toBe(NETWORK_CONFIGS[Network.MAINNET].chainId);
    expect(cfg.timeout.read).toBe(DEFAULT_CONFIG.timeout.read);
  });

  it("uses network presets for local", () => {
    const cfg = resolveConfig({ network: Network.LOCAL });

    expect(cfg.rpcUrl).toBe("http://127.0.0.1:26657");
    expect(cfg.chainId).toBe("aethelred-local");
    expect(cfg.networkConfig.restUrl).toBe("http://127.0.0.1:1317");
  });

  it("allows explicit rpcUrl and chainId overrides", () => {
    const cfg = resolveConfig({
      network: Network.TESTNET,
      rpcUrl: "http://127.0.0.1:9999",
      chainId: "custom-chain-9",
    });

    expect(cfg.rpcUrl).toBe("http://127.0.0.1:9999");
    expect(cfg.chainId).toBe("custom-chain-9");
    expect(cfg.networkConfig.chainId).toBe(NETWORK_CONFIGS[Network.TESTNET].chainId);
  });

  it("preserves apiKey and privateKey fields", () => {
    const cfg = resolveConfig({
      apiKey: "k_test",
      privateKey: "priv_test",
    });

    expect(cfg.apiKey).toBe("k_test");
    expect(cfg.privateKey).toBe("priv_test");
  });

  it("merges timeout and retry partials over defaults", () => {
    const cfg = resolveConfig({
      timeout: { read: 1234 },
      retry: { maxRetries: 9 },
    });

    expect(cfg.timeout.read).toBe(1234);
    expect(cfg.timeout.connect).toBe(DEFAULT_CONFIG.timeout.connect);
    expect(cfg.retry.maxRetries).toBe(9);
    expect(cfg.retry.initialDelay).toBe(DEFAULT_CONFIG.retry.initialDelay);
  });

  it("preserves optional runtime flags", () => {
    const cfg = resolveConfig({
      wsEnabled: false,
      logRequests: true,
      logLevel: "debug",
      maxConnections: 42,
    });

    expect(cfg.wsEnabled).toBe(false);
    expect(cfg.logRequests).toBe(true);
    expect(cfg.logLevel).toBe("debug");
    expect(cfg.maxConnections).toBe(42);
  });

  it("attaches the resolved networkConfig object", () => {
    const cfg = resolveConfig({ network: Network.DEVNET });

    expect(cfg.networkConfig).toEqual(NETWORK_CONFIGS[Network.DEVNET]);
    expect(cfg.networkConfig.explorerUrl).toContain("devnet");
  });
});
