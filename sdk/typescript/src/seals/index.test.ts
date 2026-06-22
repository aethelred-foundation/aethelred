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
  const enterpriseBundle = () => ({
    schema_version: "1.0.0",
    bundle_id: "f47ac10b-58cc-4372-a567-0e02b2c3d479",
    job_id: "a".repeat(64),
    chain_id: "aethelred-m42-pilot-1",
    seal_id: "m42-seal-test",
    timestamp: "2026-06-11T00:00:00Z",
    model_hash: "1".repeat(64),
    circuit_hash: "2".repeat(64),
    verifying_key_hash: "3".repeat(64),
    validator_signature: "dmFsaWRhdG9yLXNpZ25hdHVyZQ==",
    confidence_score: 1,
    tee_evidence: {
      platform: "nitro",
      enclave_id: "m42-enclave",
      measurement: "abcd",
      quote: "cXVvdGU=",
      nonce: "4".repeat(64),
    },
    zkml_evidence: {
      proof_system: "halo2",
      proof_bytes: "cHJvb2Y=",
      public_inputs: "aW5wdXRz",
      output_commitment: "5".repeat(64),
    },
    region: "me-central-1",
    operator: "aethel1qypqxpq9qcrsszg2pvxq6rs0zqg3yyc5lzv7xu",
    policy_decision: {
      mode: "hybrid",
      require_both: true,
      fallback_allowed: false,
    },
    archive_pointer: {
      archive_type: "opensearch",
      index: "aethelred-m42-pilot-evidence",
      document_id: "a".repeat(64),
      uri: "opensearch://m42/doc",
      retention_days: 30,
      write_status: "pending_live_archive_write",
    },
    verification: {
      schema_verified: true,
      policy_verified: true,
      tee_attestation_verified: false,
      zkml_proof_verified: false,
      digital_seal_verified: false,
      live_verification_required: true,
      verifier_version: "test",
    },
  });

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
    const modelHash = `0x${"11".repeat(32)}`;
    const results = await seals.listByModel(modelHash, { limit: 10, offset: 2 });

    expect(client.get).toHaveBeenCalledWith("/aethelred/seal/v1/seals/by_model", {
      model_hash: Buffer.from("11".repeat(32), "hex").toString("base64"),
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
    expect(client.post).toHaveBeenCalledWith("/aethelred/seal/v1/seals/seal-1:revoke", {
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
    const exported = { version: "1.0", format: "json", seal: {}, metadata: {} };
    const client = {
      get: vi.fn().mockResolvedValue({ export: exported }),
      post: vi.fn(),
    } as any;

    const seals = new SealsModule(client);
    const data = await seals.export("seal-1");

    expect(client.get).toHaveBeenCalledWith("/aethelred/seal/v1/seals/seal-1/export", {
      format: "json",
    });
    expect(data).toBe(exported);
  });

  it("export() supports alternate formats", async () => {
    const exported = { version: "1.0", format: "portable", seal: {}, metadata: {} };
    const client = {
      get: vi.fn().mockResolvedValue({ export: exported }),
      post: vi.fn(),
    } as any;

    const seals = new SealsModule(client);
    const data = await seals.export("seal-1", "portable");

    expect(client.get).toHaveBeenCalledWith("/aethelred/seal/v1/seals/seal-1/export", {
      format: "portable",
    });
    expect(data).toBe(exported);
  });

  it("exportEvidenceBundle() requires the enterprise evidence contract", async () => {
    const bundle = enterpriseBundle();
    const client = {
      get: vi.fn().mockResolvedValue({ evidence_bundle: bundle }),
      post: vi.fn(),
    } as any;

    const seals = new SealsModule(client);
    await expect(seals.exportEvidenceBundle("job-1")).resolves.toBe(bundle);
  });

  it("exportEvidenceBundle() rejects incomplete evidence", async () => {
    const client = {
      get: vi.fn().mockResolvedValue({ evidence_bundle: { schema_version: "1.0.0" } }),
      post: vi.fn(),
    } as any;

    const seals = new SealsModule(client);
    await expect(seals.exportEvidenceBundle("job-1")).rejects.toThrow("evidence bundle missing required string");
  });

  it("exportEvidenceBundle() rejects null nested evidence objects", async () => {
    const bundle = enterpriseBundle();
    (bundle as any).archive_pointer = null;
    const client = {
      get: vi.fn().mockResolvedValue({ evidence_bundle: bundle }),
      post: vi.fn(),
    } as any;

    const seals = new SealsModule(client);
    await expect(seals.exportEvidenceBundle("job-1")).rejects.toThrow("evidence bundle missing required object: archive_pointer");
  });

  it("exportEvidenceBundle() rejects missing required false-valued booleans", async () => {
    const bundle = enterpriseBundle();
    delete (bundle.verification as any).live_verification_required;
    const client = {
      get: vi.fn().mockResolvedValue({ evidence_bundle: bundle }),
      post: vi.fn(),
    } as any;

    const seals = new SealsModule(client);
    await expect(seals.exportEvidenceBundle("job-1")).rejects.toThrow("evidence bundle missing required boolean: verification.live_verification_required");
  });
});
