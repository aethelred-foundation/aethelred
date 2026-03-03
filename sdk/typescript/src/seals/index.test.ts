import { describe, expect, it, vi } from "vitest";

import { SealStatus, type DigitalSeal } from "../core/types";
import { SealsModule } from "./index";

function makeSeal(): DigitalSeal {
  return {
    id: "seal-1",
    jobId: "job-1",
    modelHash: "0xmodel",
    inputCommitment: "0xinput",
    outputCommitment: "0xoutput",
    modelCommitment: "0xmodelcommit",
    status: SealStatus.ACTIVE,
    requester: "aethelred1requester",
    validators: [],
    createdAt: new Date("2026-02-22T00:00:00Z"),
  };
}

describe("SealsModule", () => {
  it("creates seals via the expected endpoint", async () => {
    const client = {
      get: vi.fn(),
      post: vi.fn().mockResolvedValue({ sealId: "seal-1", txHash: "0xtx" }),
    } as any;

    const seals = new SealsModule(client);
    const resp = await seals.create({
      jobId: "job-1",
      expiresInBlocks: 100,
    });

    expect(client.post).toHaveBeenCalledWith("/aethelred/seal/v1/seals", {
      jobId: "job-1",
      expiresInBlocks: 100,
    });
    expect(resp.sealId).toBe("seal-1");
  });

  it("unwraps get() responses", async () => {
    const client = {
      get: vi.fn().mockResolvedValue({ seal: makeSeal() }),
      post: vi.fn(),
    } as any;

    const seals = new SealsModule(client);
    const seal = await seals.get("seal-1");

    expect(client.get).toHaveBeenCalledWith("/aethelred/seal/v1/seals/seal-1");
    expect(seal.id).toBe("seal-1");
  });

  it("list() forwards filters", async () => {
    const client = {
      get: vi.fn().mockResolvedValue({ seals: [makeSeal()] }),
      post: vi.fn(),
    } as any;

    const seals = new SealsModule(client);
    const result = await seals.list({
      requester: "aethelred1requester",
      modelHash: "0xmodel",
      status: SealStatus.ACTIVE,
      pagination: { limit: 20, offset: 5 },
    });

    expect(client.get).toHaveBeenCalledWith("/aethelred/seal/v1/seals", {
      requester: "aethelred1requester",
      modelHash: "0xmodel",
      status: SealStatus.ACTIVE,
      pagination: { limit: 20, offset: 5 },
    });
    expect(result).toHaveLength(1);
  });

  it("list() returns empty array when seals key is missing", async () => {
    const client = {
      get: vi.fn().mockResolvedValue({}),
      post: vi.fn(),
    } as any;

    const seals = new SealsModule(client);
    await expect(seals.list()).resolves.toEqual([]);
  });

  it("queries listByModel with the expected route and query params", async () => {
    const client = {
      get: vi.fn().mockResolvedValue({ seals: [makeSeal()] }),
      post: vi.fn(),
    } as any;

    const seals = new SealsModule(client);
    const results = await seals.listByModel("0xmodel", { limit: 10, offset: 2 });

    expect(client.get).toHaveBeenCalledWith("/aethelred/seal/v1/seals/by_model", {
      model_hash: "0xmodel",
      limit: 10,
      offset: 2,
    });
    expect(results).toHaveLength(1);
    expect(results[0].id).toBe("seal-1");
  });

  it("revokes a seal with auditable reason payload", async () => {
    const client = {
      get: vi.fn(),
      post: vi.fn().mockResolvedValue({}),
    } as any;

    const seals = new SealsModule(client);
    const ok = await seals.revoke("seal-1", "policy_violation");

    expect(ok).toBe(true);
    expect(client.post).toHaveBeenCalledWith("/aethelred/seal/v1/seals/seal-1/revoke", {
      reason: "policy_violation",
    });
  });

  it("verify() queries the verification route", async () => {
    const client = {
      get: vi.fn().mockResolvedValue({
        valid: true,
        verificationDetails: { signature: true },
        errors: [],
      }),
      post: vi.fn(),
    } as any;

    const seals = new SealsModule(client);
    const resp = await seals.verify("seal-1");

    expect(client.get).toHaveBeenCalledWith("/aethelred/seal/v1/seals/seal-1/verify");
    expect(resp.valid).toBe(true);
  });

  it("export() uses json format by default", async () => {
    const client = {
      get: vi.fn().mockResolvedValue({ data: "{\"seal\":\"ok\"}" }),
      post: vi.fn(),
    } as any;

    const seals = new SealsModule(client);
    const data = await seals.export("seal-1");

    expect(client.get).toHaveBeenCalledWith("/aethelred/seal/v1/seals/seal-1/export", {
      format: "json",
    });
    expect(data).toBe("{\"seal\":\"ok\"}");
  });

  it("export() supports alternate formats", async () => {
    const client = {
      get: vi.fn().mockResolvedValue({ data: "BASE64CBOR" }),
      post: vi.fn(),
    } as any;

    const seals = new SealsModule(client);
    const data = await seals.export("seal-1", "cbor");

    expect(client.get).toHaveBeenCalledWith("/aethelred/seal/v1/seals/seal-1/export", {
      format: "cbor",
    });
    expect(data).toBe("BASE64CBOR");
  });
});
