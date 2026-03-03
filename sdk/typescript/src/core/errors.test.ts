import { describe, expect, it } from "vitest";

import {
  AethelredError,
  AuthenticationError,
  ConnectionError,
  ErrorCode,
  JobError,
  RateLimitError,
  SealError,
  TimeoutError,
  TransactionError,
  ValidationError,
} from "./errors";

describe("core/errors", () => {
  it("serializes AethelredError to JSON with code name", () => {
    const err = new AethelredError("boom", ErrorCode.NOT_FOUND, { resource: "job" });

    expect(err.toJSON()).toEqual({
      name: "AethelredError",
      message: "boom",
      code: ErrorCode.NOT_FOUND,
      codeName: "NOT_FOUND",
      details: { resource: "job" },
    });
  });

  it("preserves optional cause on AethelredError", () => {
    const cause = new Error("root");
    const err = new AethelredError("wrapped", ErrorCode.INTERNAL, {}, cause);

    expect(err.cause).toBe(cause);
  });

  it("creates ConnectionError with default code and name", () => {
    const err = new ConnectionError();
    expect(err.name).toBe("ConnectionError");
    expect(err.code).toBe(ErrorCode.CONNECTION_FAILED);
  });

  it("creates RateLimitError with retryAfter details", () => {
    const err = new RateLimitError("slow down", 12);
    expect(err.name).toBe("RateLimitError");
    expect(err.code).toBe(ErrorCode.RATE_LIMITED);
    expect(err.retryAfter).toBe(12);
    expect(err.details).toEqual({ retryAfter: 12 });
  });

  it("creates TransactionError with tx hash details", () => {
    const err = new TransactionError("tx failed", "0xabc");
    expect(err.name).toBe("TransactionError");
    expect(err.txHash).toBe("0xabc");
    expect(err.details).toEqual({ txHash: "0xabc" });
  });

  it("creates JobError and SealError with IDs in details", () => {
    const jobErr = new JobError("job failed", "job-1");
    const sealErr = new SealError("seal failed", "seal-1");

    expect(jobErr.jobId).toBe("job-1");
    expect(jobErr.details).toEqual({ jobId: "job-1" });
    expect(sealErr.sealId).toBe("seal-1");
    expect(sealErr.details).toEqual({ sealId: "seal-1" });
  });

  it("creates ValidationError with field context", () => {
    const err = new ValidationError("invalid", "modelHash");
    expect(err.name).toBe("ValidationError");
    expect(err.code).toBe(ErrorCode.VALIDATION_FAILED);
    expect(err.details).toEqual({ field: "modelHash" });
  });

  it("creates AuthenticationError and TimeoutError with expected codes", () => {
    const auth = new AuthenticationError();
    const timeout = new TimeoutError("waited too long", 5000);

    expect(auth.code).toBe(ErrorCode.AUTHENTICATION_REQUIRED);
    expect(timeout.code).toBe(ErrorCode.CONNECTION_TIMEOUT);
    expect(timeout.details).toEqual({ timeoutMs: 5000 });
  });
});
