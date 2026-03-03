import { describe, expect, it, vi } from "vitest";

import { TimeoutError } from "../core/errors";
import { JobStatus, ProofType, type ComputeJob, type SubmitJobResponse } from "../core/types";
import { JobsModule } from "./index";

function makeJob(status: JobStatus): ComputeJob {
  return {
    id: "job-1",
    creator: "aethelred1creator",
    modelHash: "0xmodel",
    inputHash: "0xinput",
    status,
    proofType: ProofType.TEE,
    priority: 1,
    maxGas: "100000",
    timeoutBlocks: 100,
    createdAt: new Date("2026-02-22T00:00:00Z"),
    metadata: {},
  };
}

describe("JobsModule", () => {
  it("submits jobs to the expected endpoint", async () => {
    const client = {
      post: vi.fn<(...args: any[]) => Promise<SubmitJobResponse>>().mockResolvedValue({
        jobId: "job-1",
        txHash: "0xtx",
        estimatedBlocks: 3,
      }),
      get: vi.fn(),
    } as any;

    const jobs = new JobsModule(client);
    const resp = await jobs.submit({
      modelHash: "0xmodel",
      inputHash: "0xinput",
      proofType: ProofType.TEE,
    });

    expect(client.post).toHaveBeenCalledWith("/aethelred/pouw/v1/jobs", {
      modelHash: "0xmodel",
      inputHash: "0xinput",
      proofType: ProofType.TEE,
    });
    expect(resp.jobId).toBe("job-1");
  });

  it("waits until terminal status is reached", async () => {
    const client = {
      get: vi
        .fn()
        .mockResolvedValueOnce({ job: makeJob(JobStatus.PENDING) })
        .mockResolvedValueOnce({ job: makeJob(JobStatus.COMPLETED) }),
      post: vi.fn(),
    } as any;

    const jobs = new JobsModule(client);
    const job = await jobs.waitForCompletion("job-1", { pollInterval: 0, timeout: 100 });

    expect(job.status).toBe(JobStatus.COMPLETED);
    expect(client.get).toHaveBeenCalledTimes(2);
    expect(client.get).toHaveBeenNthCalledWith(1, "/aethelred/pouw/v1/jobs/job-1");
  });

  it("throws TimeoutError when timeout is exhausted", async () => {
    const client = {
      get: vi.fn(),
      post: vi.fn(),
    } as any;

    const jobs = new JobsModule(client);

    await expect(jobs.waitForCompletion("job-timeout", { timeout: 0 })).rejects.toMatchObject({
      name: "TimeoutError",
    } satisfies Partial<TimeoutError>);
  });

  it("unwraps get() responses", async () => {
    const client = {
      get: vi.fn().mockResolvedValue({ job: makeJob(JobStatus.ASSIGNED) }),
      post: vi.fn(),
    } as any;
    const jobs = new JobsModule(client);

    const job = await jobs.get("job-xyz");

    expect(client.get).toHaveBeenCalledWith("/aethelred/pouw/v1/jobs/job-xyz");
    expect(job.status).toBe(JobStatus.ASSIGNED);
  });

  it("list() forwards filter options and returns jobs", async () => {
    const client = {
      get: vi.fn().mockResolvedValue({ jobs: [makeJob(JobStatus.PENDING)] }),
      post: vi.fn(),
    } as any;
    const jobs = new JobsModule(client);

    const results = await jobs.list({
      status: JobStatus.PENDING,
      creator: "aethelred1creator",
      pagination: { limit: 10, offset: 3 },
    });

    expect(client.get).toHaveBeenCalledWith("/aethelred/pouw/v1/jobs", {
      status: JobStatus.PENDING,
      creator: "aethelred1creator",
      pagination: { limit: 10, offset: 3 },
    });
    expect(results).toHaveLength(1);
  });

  it("list() returns empty array when jobs key is missing", async () => {
    const client = {
      get: vi.fn().mockResolvedValue({}),
      post: vi.fn(),
    } as any;
    const jobs = new JobsModule(client);

    await expect(jobs.list()).resolves.toEqual([]);
  });

  it("listPending() uses the pending route and pagination query", async () => {
    const client = {
      get: vi.fn().mockResolvedValue({ jobs: [makeJob(JobStatus.PENDING)] }),
      post: vi.fn(),
    } as any;
    const jobs = new JobsModule(client);

    await jobs.listPending({ limit: 5 });

    expect(client.get).toHaveBeenCalledWith("/aethelred/pouw/v1/jobs/pending", { limit: 5 });
  });

  it("cancel() posts to the cancel route and returns true", async () => {
    const client = {
      get: vi.fn(),
      post: vi.fn().mockResolvedValue({}),
    } as any;
    const jobs = new JobsModule(client);

    await expect(jobs.cancel("job-1")).resolves.toBe(true);
    expect(client.post).toHaveBeenCalledWith("/aethelred/pouw/v1/jobs/job-1/cancel");
  });

  it("waitForCompletion() returns FAILED terminal jobs", async () => {
    const client = {
      get: vi.fn().mockResolvedValue({ job: makeJob(JobStatus.FAILED) }),
      post: vi.fn(),
    } as any;
    const jobs = new JobsModule(client);

    const job = await jobs.waitForCompletion("job-failed", { timeout: 50, pollInterval: 0 });
    expect(job.status).toBe(JobStatus.FAILED);
  });

  it("waitForCompletion() propagates underlying get() errors", async () => {
    const client = {
      get: vi.fn().mockRejectedValue(new Error("rpc unavailable")),
      post: vi.fn(),
    } as any;
    const jobs = new JobsModule(client);

    await expect(jobs.waitForCompletion("job-err", { timeout: 50, pollInterval: 0 })).rejects.toThrow(
      "rpc unavailable"
    );
  });
});
