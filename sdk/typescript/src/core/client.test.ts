import { describe, expect, it, vi } from "vitest";

import { Network } from "./config";
import { AethelredClient } from "./client";
import { AethelredError, ConnectionError, RateLimitError, TimeoutError } from "./errors";

describe("AethelredClient (core)", () => {
  it("resolves network defaults and initializes module accessors", () => {
    const client = new AethelredClient({ network: Network.LOCAL });

    expect(client.getRpcUrl()).toBe("http://127.0.0.1:26657");
    expect(client.getChainId()).toBe("aethelred-local");
    expect(client.jobs).toBeDefined();
    expect(client.seals).toBeDefined();
    expect(client.models).toBeDefined();
    expect(client.validators).toBeDefined();
    expect(client.verification).toBeDefined();
  });

  it("maps getNodeInfo through the REST endpoint", async () => {
    const client = new AethelredClient({ network: Network.LOCAL });
    const http = (client as any).http;

    http.get = vi.fn().mockResolvedValue({
      data: {
        default_node_info: {
          defaultNodeId: "node-1",
          listenAddr: "tcp://0.0.0.0:26656",
          network: "aethelred-local",
          version: "1.0.0",
          moniker: "local",
        },
      },
    });

    const nodeInfo = await client.getNodeInfo();

    expect(nodeInfo.network).toBe("aethelred-local");
    expect(http.get).toHaveBeenCalledWith(
      "/cosmos/base/tendermint/v1beta1/node_info",
      { params: undefined }
    );
  });

  it("returns false from healthCheck on request failure", async () => {
    const client = new AethelredClient({ network: Network.LOCAL });
    vi.spyOn(client, "getNodeInfo").mockRejectedValueOnce(new Error("boom"));

    await expect(client.healthCheck()).resolves.toBe(false);
  });

  it("wraps post/put/delete HTTP helpers and returns response data", async () => {
    const client = new AethelredClient({ network: Network.LOCAL });
    const http = (client as any).http;

    http.post = vi.fn().mockResolvedValue({ data: { ok: "post" } });
    http.put = vi.fn().mockResolvedValue({ data: { ok: "put" } });
    http.delete = vi.fn().mockResolvedValue({ data: { ok: "delete" } });

    await expect(client.post("/p", { a: 1 })).resolves.toEqual({ ok: "post" });
    await expect(client.put("/u", { b: 2 })).resolves.toEqual({ ok: "put" });
    await expect(client.delete("/d", { q: 1 })).resolves.toEqual({ ok: "delete" });

    expect(http.post).toHaveBeenCalledWith("/p", { a: 1 });
    expect(http.put).toHaveBeenCalledWith("/u", { b: 2 });
    expect(http.delete).toHaveBeenCalledWith("/d", { params: { q: 1 } });
  });

  it("maps getLatestBlock() and getBlock() to tendermint endpoints", async () => {
    const client = new AethelredClient({ network: Network.LOCAL });
    const http = (client as any).http;

    http.get = vi
      .fn()
      .mockResolvedValueOnce({ data: { blockId: { hash: "0x1" }, header: { height: 10 } } })
      .mockResolvedValueOnce({ data: { blockId: { hash: "0x2" }, header: { height: 7 } } });

    const latest = await client.getLatestBlock();
    const atHeight = await client.getBlock(7);

    expect(latest.blockId.hash).toBe("0x1");
    expect(atHeight.blockId.hash).toBe("0x2");
    expect(http.get).toHaveBeenNthCalledWith(1, "/cosmos/base/tendermint/v1beta1/blocks/latest", {
      params: undefined,
    });
    expect(http.get).toHaveBeenNthCalledWith(2, "/cosmos/base/tendermint/v1beta1/blocks/7", {
      params: undefined,
    });
  });

  it("returns resolved network config", () => {
    const client = new AethelredClient({ network: Network.TESTNET });
    const networkConfig = client.getNetworkConfig();

    expect(networkConfig.chainId).toBe("aethelred-testnet-1");
    expect(networkConfig.rpcUrl).toContain("testnet");
  });

  it("interceptor maps HTTP 429 responses to RateLimitError", async () => {
    const client = new AethelredClient({ network: Network.LOCAL });
    const rejected = (client as any).http.interceptors.response.handlers[0].rejected as (err: any) => Promise<never>;

    await expect(
      rejected({
        response: {
          status: 429,
          headers: { "retry-after": "7" },
          data: { message: "ratelimited" },
        },
      })
    ).rejects.toMatchObject({
      name: "RateLimitError",
      retryAfter: 7,
    } satisfies Partial<RateLimitError>);
  });

  it("interceptor maps server errors to AethelredError with status code", async () => {
    const client = new AethelredClient({ network: Network.LOCAL });
    const rejected = (client as any).http.interceptors.response.handlers[0].rejected as (err: any) => Promise<never>;

    await expect(
      rejected({
        response: {
          status: 500,
          data: { message: "internal failure", trace: "x" },
        },
        message: "Request failed with status code 500",
      })
    ).rejects.toMatchObject({
      name: "AethelredError",
      code: 500,
      message: "internal failure",
    } satisfies Partial<AethelredError>);
  });

  it("interceptor maps connection failures to ConnectionError", async () => {
    const client = new AethelredClient({ network: Network.LOCAL });
    const rejected = (client as any).http.interceptors.response.handlers[0].rejected as (err: any) => Promise<never>;

    await expect(rejected({ code: "ECONNREFUSED", message: "connect refused" })).rejects.toMatchObject({
      name: "ConnectionError",
    } satisfies Partial<ConnectionError>);
  });

  it("interceptor maps timeout-like axios errors to TimeoutError", async () => {
    const client = new AethelredClient({ network: Network.LOCAL });
    const rejected = (client as any).http.interceptors.response.handlers[0].rejected as (err: any) => Promise<never>;

    await expect(rejected({ code: "ECONNABORTED", message: "timeout" })).rejects.toMatchObject({
      name: "TimeoutError",
    } satisfies Partial<TimeoutError>);
  });

  it("injects X-API-Key header when apiKey is configured", () => {
    const client = new AethelredClient({ network: Network.LOCAL, apiKey: "test-key" });
    const defaults = ((client as any).http.defaults.headers ?? {}) as Record<string, any>;
    const common = (defaults.common ?? {}) as Record<string, string>;

    expect(common["X-API-Key"] ?? defaults["X-API-Key"]).toBe("test-key");
  });

  it("accepts a string URL as the constructor argument", () => {
    const client = new AethelredClient("http://custom-node:26657");
    expect(client.getRpcUrl()).toBe("http://custom-node:26657");
    expect(client.jobs).toBeDefined();
    expect(client.seals).toBeDefined();
  });

  it("returns true from healthCheck on success", async () => {
    const client = new AethelredClient({ network: Network.LOCAL });
    vi.spyOn(client, "getNodeInfo").mockResolvedValueOnce({
      defaultNodeId: "node-1",
      listenAddr: "tcp://0.0.0.0:26656",
      network: "aethelred-local",
      version: "1.0.0",
      moniker: "local",
    } as any);

    await expect(client.healthCheck()).resolves.toBe(true);
  });
});
