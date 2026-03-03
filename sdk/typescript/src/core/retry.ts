/**
 * Aethelred SDK Retry System
 *
 * Sophisticated retry logic with exponential backoff, jitter,
 * circuit breaker, and customizable strategies.
 */

import { AethelredError, isAethelredError } from './errors';
import { getLogger } from './logger';

const logger = getLogger('retry');

/**
 * Retry strategy type
 */
export type RetryStrategy = 'exponential' | 'linear' | 'constant' | 'fibonacci';

/**
 * Retry configuration
 */
export interface RetryConfig {
  /** Maximum number of retry attempts */
  maxRetries: number;
  /** Base delay in milliseconds */
  baseDelayMs: number;
  /** Maximum delay in milliseconds */
  maxDelayMs: number;
  /** Retry strategy */
  strategy: RetryStrategy;
  /** Jitter factor (0-1) to randomize delays */
  jitter: number;
  /** Timeout for each attempt in milliseconds */
  timeoutMs?: number;
  /** Function to determine if error is retryable */
  isRetryable?: (error: Error, attempt: number) => boolean;
  /** Callback on each retry attempt */
  onRetry?: (error: Error, attempt: number, delayMs: number) => void;
  /** Abort signal for cancellation */
  signal?: AbortSignal;
}

/**
 * Default retry configuration
 */
export const DEFAULT_RETRY_CONFIG: RetryConfig = {
  maxRetries: 3,
  baseDelayMs: 1000,
  maxDelayMs: 30000,
  strategy: 'exponential',
  jitter: 0.2,
  isRetryable: defaultIsRetryable,
};

/**
 * Default function to determine if error is retryable
 */
function defaultIsRetryable(error: Error): boolean {
  if (isAethelredError(error)) {
    return error.isRetryable;
  }

  // Network errors are usually retryable
  const message = error.message.toLowerCase();
  const retryablePatterns = [
    'network',
    'timeout',
    'econnrefused',
    'econnreset',
    'enotfound',
    'socket hang up',
    'request failed',
    '429', // Rate limited
    '502', // Bad gateway
    '503', // Service unavailable
    '504', // Gateway timeout
  ];

  return retryablePatterns.some((pattern) => message.includes(pattern));
}

/**
 * Calculate delay for a given attempt
 */
function calculateDelay(
  attempt: number,
  config: RetryConfig
): number {
  let delay: number;

  switch (config.strategy) {
    case 'exponential':
      delay = config.baseDelayMs * Math.pow(2, attempt);
      break;
    case 'linear':
      delay = config.baseDelayMs * (attempt + 1);
      break;
    case 'constant':
      delay = config.baseDelayMs;
      break;
    case 'fibonacci':
      delay = config.baseDelayMs * fibonacci(attempt + 1);
      break;
    default:
      delay = config.baseDelayMs;
  }

  // Apply jitter
  if (config.jitter > 0) {
    const jitterRange = delay * config.jitter;
    delay += Math.random() * jitterRange * 2 - jitterRange;
  }

  // Ensure within bounds
  return Math.min(Math.max(delay, 0), config.maxDelayMs);
}

/**
 * Calculate fibonacci number
 */
function fibonacci(n: number): number {
  if (n <= 1) return n;
  let a = 0,
    b = 1;
  for (let i = 2; i <= n; i++) {
    [a, b] = [b, a + b];
  }
  return b;
}

/**
 * Sleep for a given duration
 */
async function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(resolve, ms);

    if (signal) {
      signal.addEventListener('abort', () => {
        clearTimeout(timeout);
        reject(new Error('Retry aborted'));
      });
    }
  });
}

/**
 * Wrap a promise with a timeout
 */
async function withTimeout<T>(
  promise: Promise<T>,
  timeoutMs: number,
  signal?: AbortSignal
): Promise<T> {
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      reject(new Error(`Operation timed out after ${timeoutMs}ms`));
    }, timeoutMs);

    if (signal) {
      signal.addEventListener('abort', () => {
        clearTimeout(timeout);
        reject(new Error('Operation aborted'));
      });
    }

    promise
      .then((result) => {
        clearTimeout(timeout);
        resolve(result);
      })
      .catch((error) => {
        clearTimeout(timeout);
        reject(error);
      });
  });
}

/**
 * Retry result with metadata
 */
export interface RetryResult<T> {
  success: boolean;
  result?: T;
  error?: Error;
  attempts: number;
  totalTimeMs: number;
  finalDelayMs?: number;
}

/**
 * Execute a function with retry logic
 */
export async function retry<T>(
  fn: () => Promise<T>,
  config: Partial<RetryConfig> = {}
): Promise<T> {
  const fullConfig: RetryConfig = { ...DEFAULT_RETRY_CONFIG, ...config };
  const startTime = Date.now();
  let lastError: Error | undefined;

  for (let attempt = 0; attempt <= fullConfig.maxRetries; attempt++) {
    // Check for abort
    if (fullConfig.signal?.aborted) {
      throw new Error('Retry aborted');
    }

    try {
      // Execute with optional timeout
      let result: T;
      if (fullConfig.timeoutMs) {
        result = await withTimeout(fn(), fullConfig.timeoutMs, fullConfig.signal);
      } else {
        result = await fn();
      }

      if (attempt > 0) {
        logger.debug(`Retry succeeded on attempt ${attempt + 1}`, {
          totalTimeMs: Date.now() - startTime,
        });
      }

      return result;
    } catch (error) {
      lastError = error as Error;

      // Check if we should retry
      const shouldRetry =
        attempt < fullConfig.maxRetries &&
        (fullConfig.isRetryable?.(lastError, attempt) ?? defaultIsRetryable(lastError));

      if (!shouldRetry) {
        logger.debug(`Not retrying: ${lastError.message}`, {
          attempt: attempt + 1,
          retryable: false,
        });
        break;
      }

      // Calculate delay
      const delay = calculateDelay(attempt, fullConfig);

      logger.debug(`Retrying after ${delay}ms`, {
        attempt: attempt + 1,
        maxRetries: fullConfig.maxRetries,
        error: lastError.message,
      });

      // Call retry callback
      fullConfig.onRetry?.(lastError, attempt + 1, delay);

      // Wait before retry
      await sleep(delay, fullConfig.signal);
    }
  }

  throw lastError;
}

/**
 * Execute a function with retry and return detailed result
 */
export async function retryWithResult<T>(
  fn: () => Promise<T>,
  config: Partial<RetryConfig> = {}
): Promise<RetryResult<T>> {
  const fullConfig: RetryConfig = { ...DEFAULT_RETRY_CONFIG, ...config };
  const startTime = Date.now();
  let attempts = 0;
  let finalDelayMs: number | undefined;

  for (let attempt = 0; attempt <= fullConfig.maxRetries; attempt++) {
    attempts = attempt + 1;

    if (fullConfig.signal?.aborted) {
      return {
        success: false,
        error: new Error('Retry aborted'),
        attempts,
        totalTimeMs: Date.now() - startTime,
      };
    }

    try {
      let result: T;
      if (fullConfig.timeoutMs) {
        result = await withTimeout(fn(), fullConfig.timeoutMs, fullConfig.signal);
      } else {
        result = await fn();
      }

      return {
        success: true,
        result,
        attempts,
        totalTimeMs: Date.now() - startTime,
        finalDelayMs,
      };
    } catch (error) {
      const err = error as Error;

      const shouldRetry =
        attempt < fullConfig.maxRetries &&
        (fullConfig.isRetryable?.(err, attempt) ?? defaultIsRetryable(err));

      if (!shouldRetry) {
        return {
          success: false,
          error: err,
          attempts,
          totalTimeMs: Date.now() - startTime,
          finalDelayMs,
        };
      }

      finalDelayMs = calculateDelay(attempt, fullConfig);
      fullConfig.onRetry?.(err, attempt + 1, finalDelayMs);
      await sleep(finalDelayMs, fullConfig.signal);
    }
  }

  return {
    success: false,
    error: new Error('Max retries exceeded'),
    attempts,
    totalTimeMs: Date.now() - startTime,
    finalDelayMs,
  };
}

/**
 * Circuit breaker state
 */
export enum CircuitState {
  CLOSED = 'CLOSED',
  OPEN = 'OPEN',
  HALF_OPEN = 'HALF_OPEN',
}

/**
 * Circuit breaker configuration
 */
export interface CircuitBreakerConfig {
  /** Failure threshold to open circuit */
  failureThreshold: number;
  /** Success threshold to close circuit */
  successThreshold: number;
  /** Time to wait before half-open in milliseconds */
  resetTimeoutMs: number;
  /** Optional retry config when circuit is closed */
  retryConfig?: Partial<RetryConfig>;
}

/**
 * Default circuit breaker configuration
 */
export const DEFAULT_CIRCUIT_BREAKER_CONFIG: CircuitBreakerConfig = {
  failureThreshold: 5,
  successThreshold: 2,
  resetTimeoutMs: 30000,
};

/**
 * Circuit breaker for protecting against cascading failures
 */
export class CircuitBreaker {
  private state: CircuitState = CircuitState.CLOSED;
  private failures = 0;
  private successes = 0;
  private lastFailureTime?: number;
  private readonly config: CircuitBreakerConfig;
  private readonly logger = getLogger('circuit-breaker');

  constructor(
    private readonly name: string,
    config: Partial<CircuitBreakerConfig> = {}
  ) {
    this.config = { ...DEFAULT_CIRCUIT_BREAKER_CONFIG, ...config };
  }

  /**
   * Get current circuit state
   */
  getState(): CircuitState {
    this.checkHalfOpen();
    return this.state;
  }

  /**
   * Execute a function through the circuit breaker
   */
  async execute<T>(fn: () => Promise<T>): Promise<T> {
    this.checkHalfOpen();

    if (this.state === CircuitState.OPEN) {
      throw new Error(`Circuit breaker ${this.name} is OPEN`);
    }

    try {
      let result: T;

      if (this.config.retryConfig) {
        result = await retry(fn, this.config.retryConfig);
      } else {
        result = await fn();
      }

      this.onSuccess();
      return result;
    } catch (error) {
      this.onFailure(error as Error);
      throw error;
    }
  }

  /**
   * Reset the circuit breaker
   */
  reset(): void {
    this.state = CircuitState.CLOSED;
    this.failures = 0;
    this.successes = 0;
    this.lastFailureTime = undefined;
    this.logger.info(`Circuit breaker ${this.name} reset`);
  }

  /**
   * Force open the circuit
   */
  open(): void {
    this.state = CircuitState.OPEN;
    this.lastFailureTime = Date.now();
    this.logger.warn(`Circuit breaker ${this.name} forced OPEN`);
  }

  /**
   * Check if circuit should transition to half-open
   */
  private checkHalfOpen(): void {
    if (
      this.state === CircuitState.OPEN &&
      this.lastFailureTime &&
      Date.now() - this.lastFailureTime >= this.config.resetTimeoutMs
    ) {
      this.state = CircuitState.HALF_OPEN;
      this.successes = 0;
      this.logger.info(`Circuit breaker ${this.name} is HALF_OPEN`);
    }
  }

  /**
   * Handle successful execution
   */
  private onSuccess(): void {
    this.failures = 0;

    if (this.state === CircuitState.HALF_OPEN) {
      this.successes++;

      if (this.successes >= this.config.successThreshold) {
        this.state = CircuitState.CLOSED;
        this.logger.info(`Circuit breaker ${this.name} is CLOSED`);
      }
    }
  }

  /**
   * Handle failed execution
   */
  private onFailure(error: Error): void {
    this.failures++;
    this.lastFailureTime = Date.now();

    if (this.state === CircuitState.HALF_OPEN) {
      this.state = CircuitState.OPEN;
      this.logger.warn(`Circuit breaker ${this.name} is OPEN (half-open failure)`, {
        error: error.message,
      });
    } else if (this.failures >= this.config.failureThreshold) {
      this.state = CircuitState.OPEN;
      this.logger.warn(`Circuit breaker ${this.name} is OPEN (threshold reached)`, {
        failures: this.failures,
        threshold: this.config.failureThreshold,
      });
    }
  }
}

/**
 * Create a retryable function
 */
export function withRetry<T extends (...args: any[]) => Promise<any>>(
  fn: T,
  config: Partial<RetryConfig> = {}
): T {
  return (async (...args: Parameters<T>) => {
    return retry(() => fn(...args), config);
  }) as T;
}

/**
 * Create a function protected by circuit breaker
 */
export function withCircuitBreaker<T extends (...args: any[]) => Promise<any>>(
  fn: T,
  breaker: CircuitBreaker
): T {
  return (async (...args: Parameters<T>) => {
    return breaker.execute(() => fn(...args));
  }) as T;
}
