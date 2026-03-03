/**
 * Aethelred SDK Core - Main Export
 */

// Error system
export {
  AethelredError,
  AethelredErrorCode,
  ConnectionError,
  TransactionError,
  SealError,
  ComputeError,
  ValidationError,
  RateLimitError,
  isAethelredError,
  wrapError,
  Errors,
  ErrorMetadata,
} from './errors';

// Logger
export {
  Logger,
  LogLevel,
  LogEntry,
  LogTransport,
  LoggerConfig,
  ConsoleTransport,
  JSONTransport,
  MemoryTransport,
  configureLogger,
  getLogLevel,
  setLogLevel,
  addTransport,
  removeTransport,
  createLogger,
  getLogger,
  logger,
} from './logger';

// Retry and circuit breaker
export {
  retry,
  retryWithResult,
  RetryConfig,
  RetryResult,
  RetryStrategy,
  DEFAULT_RETRY_CONFIG,
  CircuitBreaker,
  CircuitBreakerConfig,
  CircuitState,
  DEFAULT_CIRCUIT_BREAKER_CONFIG,
  withRetry,
  withCircuitBreaker,
} from './retry';

// Event system
export {
  EventEmitter,
  AethelredEventType,
  EventPayloads,
  EventHandler,
  EventSubscription,
  EventFilter,
  EventListenerOptions,
  EventObservable,
  globalEmitter,
  observe,
} from './events';

// Cache system
export {
  Cache,
  CacheConfig,
  CacheOptions,
  CacheStats,
  DEFAULT_CACHE_CONFIG,
  cached,
  memoize,
  createNamespacedCache,
  globalCache,
} from './cache';

// Connection pool
export {
  ConnectionPool,
  PoolConfig,
  PoolStats,
  PooledConnection,
  ConnectionHealth,
  ConnectionMetrics,
  LoadBalancingStrategy,
  DEFAULT_POOL_CONFIG,
} from './pool';
