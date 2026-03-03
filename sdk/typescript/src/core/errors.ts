/**
 * Error types for Aethelred SDK.
 */

export enum ErrorCode {
  UNKNOWN = 1000,
  INTERNAL = 1001,
  INVALID_ARGUMENT = 1002,
  NOT_FOUND = 1003,
  ALREADY_EXISTS = 1004,
  PERMISSION_DENIED = 1005,
  CONNECTION_FAILED = 1100,
  CONNECTION_TIMEOUT = 1101,
  AUTHENTICATION_REQUIRED = 1200,
  INVALID_API_KEY = 1201,
  RATE_LIMITED = 1300,
  TRANSACTION_FAILED = 1400,
  INSUFFICIENT_FUNDS = 1401,
  JOB_NOT_FOUND = 1500,
  JOB_FAILED = 1504,
  SEAL_NOT_FOUND = 1600,
  SEAL_VERIFICATION_FAILED = 1604,
  MODEL_NOT_FOUND = 1700,
  VERIFICATION_FAILED = 1800,
  VALIDATION_FAILED = 1900,
}

export class AethelredError extends Error {
  public readonly code: ErrorCode;
  public readonly details: Record<string, unknown>;
  public readonly cause?: Error;

  constructor(
    message: string,
    code: ErrorCode = ErrorCode.UNKNOWN,
    details: Record<string, unknown> = {},
    cause?: Error
  ) {
    super(message);
    this.name = 'AethelredError';
    this.code = code;
    this.details = details;
    this.cause = cause;
    Object.setPrototypeOf(this, AethelredError.prototype);
  }

  toJSON(): Record<string, unknown> {
    return {
      name: this.name,
      message: this.message,
      code: this.code,
      codeName: ErrorCode[this.code],
      details: this.details,
    };
  }
}

export class ConnectionError extends AethelredError {
  constructor(message = 'Failed to connect', cause?: Error) {
    super(message, ErrorCode.CONNECTION_FAILED, {}, cause);
    this.name = 'ConnectionError';
  }
}

export class AuthenticationError extends AethelredError {
  constructor(message = 'Authentication failed') {
    super(message, ErrorCode.AUTHENTICATION_REQUIRED);
    this.name = 'AuthenticationError';
  }
}

export class RateLimitError extends AethelredError {
  public readonly retryAfter?: number;

  constructor(message = 'Rate limit exceeded', retryAfter?: number) {
    super(message, ErrorCode.RATE_LIMITED, { retryAfter });
    this.name = 'RateLimitError';
    this.retryAfter = retryAfter;
  }
}

export class TransactionError extends AethelredError {
  public readonly txHash?: string;

  constructor(message = 'Transaction failed', txHash?: string, code = ErrorCode.TRANSACTION_FAILED) {
    super(message, code, { txHash });
    this.name = 'TransactionError';
    this.txHash = txHash;
  }
}

export class JobError extends AethelredError {
  public readonly jobId?: string;

  constructor(message = 'Job operation failed', jobId?: string, code = ErrorCode.JOB_FAILED) {
    super(message, code, { jobId });
    this.name = 'JobError';
    this.jobId = jobId;
  }
}

export class SealError extends AethelredError {
  public readonly sealId?: string;

  constructor(message = 'Seal operation failed', sealId?: string, code = ErrorCode.SEAL_NOT_FOUND) {
    super(message, code, { sealId });
    this.name = 'SealError';
    this.sealId = sealId;
  }
}

export class ValidationError extends AethelredError {
  public readonly field?: string;

  constructor(message = 'Validation failed', field?: string) {
    super(message, ErrorCode.VALIDATION_FAILED, { field });
    this.name = 'ValidationError';
    this.field = field;
  }
}

export class TimeoutError extends AethelredError {
  constructor(message = 'Operation timed out', timeoutMs?: number) {
    super(message, ErrorCode.CONNECTION_TIMEOUT, { timeoutMs });
    this.name = 'TimeoutError';
  }
}
