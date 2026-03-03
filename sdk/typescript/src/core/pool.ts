/**
 * Aethelred SDK Connection Pool
 *
 * Connection pooling for RPC clients with health checks,
 * load balancing, and automatic failover.
 */

import { getLogger } from './logger';
import { CircuitBreaker, CircuitState } from './retry';

const logger = getLogger('pool');

/**
 * Connection health status
 */
export enum ConnectionHealth {
  HEALTHY = 'healthy',
  DEGRADED = 'degraded',
  UNHEALTHY = 'unhealthy',
  UNKNOWN = 'unknown',
}

/**
 * Connection metrics
 */
export interface ConnectionMetrics {
  totalRequests: number;
  successfulRequests: number;
  failedRequests: number;
  averageLatencyMs: number;
  lastLatencyMs: number;
  lastSuccessAt?: Date;
  lastFailureAt?: Date;
  consecutiveFailures: number;
  uptime: number;
}

/**
 * Connection entry
 */
export interface PooledConnection<T> {
  id: string;
  endpoint: string;
  client: T;
  health: ConnectionHealth;
  metrics: ConnectionMetrics;
  circuitBreaker: CircuitBreaker;
  weight: number;
  priority: number;
  lastHealthCheck?: Date;
}

/**
 * Load balancing strategy
 */
export type LoadBalancingStrategy =
  | 'round-robin'
  | 'least-connections'
  | 'weighted'
  | 'latency-based'
  | 'random';

/**
 * Pool configuration
 */
export interface PoolConfig<T> {
  /** Endpoints to connect to */
  endpoints: string[];
  /** Factory function to create connections */
  createConnection: (endpoint: string) => Promise<T>;
  /** Health check function */
  healthCheck?: (client: T) => Promise<boolean>;
  /** Load balancing strategy */
  strategy: LoadBalancingStrategy;
  /** Health check interval in milliseconds */
  healthCheckIntervalMs: number;
  /** Connection timeout in milliseconds */
  connectionTimeoutMs: number;
  /** Maximum retries per request */
  maxRetries: number;
  /** Minimum healthy connections */
  minHealthyConnections: number;
  /** Enable automatic reconnection */
  autoReconnect: boolean;
  /** Weights for endpoints (for weighted strategy) */
  weights?: Record<string, number>;
  /** Priorities for endpoints */
  priorities?: Record<string, number>;
}

/**
 * Default pool configuration
 */
export const DEFAULT_POOL_CONFIG: Omit<PoolConfig<any>, 'endpoints' | 'createConnection'> = {
  strategy: 'round-robin',
  healthCheckIntervalMs: 30000,
  connectionTimeoutMs: 10000,
  maxRetries: 3,
  minHealthyConnections: 1,
  autoReconnect: true,
};

/**
 * Connection pool implementation
 */
export class ConnectionPool<T> {
  private connections: Map<string, PooledConnection<T>> = new Map();
  private config: PoolConfig<T>;
  private roundRobinIndex = 0;
  private healthCheckTimer?: NodeJS.Timer;
  private isDestroyed = false;

  constructor(config: PoolConfig<T>) {
    this.config = { ...DEFAULT_POOL_CONFIG, ...config };
  }

  /**
   * Initialize the pool
   */
  async initialize(): Promise<void> {
    logger.info('Initializing connection pool', {
      endpoints: this.config.endpoints,
      strategy: this.config.strategy,
    });

    // Create connections for all endpoints
    await Promise.all(
      this.config.endpoints.map((endpoint) => this.addConnection(endpoint))
    );

    // Verify minimum healthy connections
    const healthyCount = this.getHealthyConnections().length;
    if (healthyCount < this.config.minHealthyConnections) {
      throw new Error(
        `Insufficient healthy connections: ${healthyCount}/${this.config.minHealthyConnections}`
      );
    }

    // Start health checks
    this.startHealthChecks();

    logger.info('Connection pool initialized', {
      total: this.connections.size,
      healthy: healthyCount,
    });
  }

  /**
   * Add a new connection to the pool
   */
  async addConnection(endpoint: string): Promise<PooledConnection<T> | null> {
    const id = this.generateConnectionId(endpoint);

    try {
      logger.debug(`Creating connection: ${endpoint}`);

      const client = await Promise.race([
        this.config.createConnection(endpoint),
        new Promise<never>((_, reject) =>
          setTimeout(
            () => reject(new Error('Connection timeout')),
            this.config.connectionTimeoutMs
          )
        ),
      ]);

      const connection: PooledConnection<T> = {
        id,
        endpoint,
        client,
        health: ConnectionHealth.UNKNOWN,
        metrics: this.createInitialMetrics(),
        circuitBreaker: new CircuitBreaker(endpoint),
        weight: this.config.weights?.[endpoint] ?? 1,
        priority: this.config.priorities?.[endpoint] ?? 0,
      };

      // Perform initial health check
      await this.checkConnectionHealth(connection);

      this.connections.set(id, connection);
      logger.info(`Connection added: ${endpoint}`, { health: connection.health });

      return connection;
    } catch (error) {
      logger.error(`Failed to create connection: ${endpoint}`, error as Error);
      return null;
    }
  }

  /**
   * Remove a connection from the pool
   */
  removeConnection(id: string): boolean {
    const connection = this.connections.get(id);
    if (connection) {
      this.connections.delete(id);
      logger.info(`Connection removed: ${connection.endpoint}`);
      return true;
    }
    return false;
  }

  /**
   * Get a connection using the configured strategy
   */
  getConnection(): PooledConnection<T> | undefined {
    const healthy = this.getHealthyConnections();

    if (healthy.length === 0) {
      // Try degraded connections as fallback
      const degraded = this.getConnectionsByHealth(ConnectionHealth.DEGRADED);
      if (degraded.length > 0) {
        logger.warn('Using degraded connection - no healthy connections available');
        return this.selectByStrategy(degraded);
      }
      return undefined;
    }

    return this.selectByStrategy(healthy);
  }

  /**
   * Execute a request through the pool with automatic failover
   */
  async execute<R>(
    fn: (client: T) => Promise<R>,
    options: { maxRetries?: number } = {}
  ): Promise<R> {
    const maxRetries = options.maxRetries ?? this.config.maxRetries;
    const triedConnections = new Set<string>();
    let lastError: Error | undefined;

    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      const connection = this.getAvailableConnection(triedConnections);

      if (!connection) {
        throw lastError || new Error('No available connections');
      }

      triedConnections.add(connection.id);

      try {
        const startTime = Date.now();

        const result = await connection.circuitBreaker.execute(() =>
          fn(connection.client)
        );

        // Update metrics on success
        this.recordSuccess(connection, Date.now() - startTime);

        return result;
      } catch (error) {
        lastError = error as Error;
        this.recordFailure(connection, error as Error);

        logger.warn(`Request failed on ${connection.endpoint}`, {
          attempt: attempt + 1,
          maxRetries,
          error: (error as Error).message,
        });
      }
    }

    throw lastError || new Error('All retry attempts failed');
  }

  /**
   * Get all connections
   */
  getAllConnections(): PooledConnection<T>[] {
    return Array.from(this.connections.values());
  }

  /**
   * Get healthy connections
   */
  getHealthyConnections(): PooledConnection<T>[] {
    return this.getConnectionsByHealth(ConnectionHealth.HEALTHY);
  }

  /**
   * Get connections by health status
   */
  getConnectionsByHealth(health: ConnectionHealth): PooledConnection<T>[] {
    return Array.from(this.connections.values()).filter(
      (c) =>
        c.health === health &&
        c.circuitBreaker.getState() !== CircuitState.OPEN
    );
  }

  /**
   * Get pool statistics
   */
  getStats(): PoolStats {
    const connections = Array.from(this.connections.values());

    const byHealth = {
      healthy: connections.filter((c) => c.health === ConnectionHealth.HEALTHY).length,
      degraded: connections.filter((c) => c.health === ConnectionHealth.DEGRADED).length,
      unhealthy: connections.filter((c) => c.health === ConnectionHealth.UNHEALTHY).length,
      unknown: connections.filter((c) => c.health === ConnectionHealth.UNKNOWN).length,
    };

    const totalRequests = connections.reduce(
      (sum, c) => sum + c.metrics.totalRequests,
      0
    );
    const successfulRequests = connections.reduce(
      (sum, c) => sum + c.metrics.successfulRequests,
      0
    );

    return {
      totalConnections: connections.length,
      byHealth,
      totalRequests,
      successRate: totalRequests > 0 ? successfulRequests / totalRequests : 0,
      averageLatencyMs:
        connections.reduce((sum, c) => sum + c.metrics.averageLatencyMs, 0) /
        (connections.length || 1),
    };
  }

  /**
   * Force health check on all connections
   */
  async checkAllHealth(): Promise<void> {
    await Promise.all(
      Array.from(this.connections.values()).map((c) =>
        this.checkConnectionHealth(c)
      )
    );
  }

  /**
   * Destroy the pool
   */
  destroy(): void {
    this.isDestroyed = true;

    if (this.healthCheckTimer) {
      clearInterval(this.healthCheckTimer);
      this.healthCheckTimer = undefined;
    }

    this.connections.clear();
    logger.info('Connection pool destroyed');
  }

  /**
   * Select connection by strategy
   */
  private selectByStrategy(connections: PooledConnection<T>[]): PooledConnection<T> {
    if (connections.length === 0) {
      throw new Error('No connections available');
    }

    if (connections.length === 1) {
      return connections[0];
    }

    switch (this.config.strategy) {
      case 'round-robin':
        return this.selectRoundRobin(connections);

      case 'least-connections':
        return this.selectLeastConnections(connections);

      case 'weighted':
        return this.selectWeighted(connections);

      case 'latency-based':
        return this.selectLatencyBased(connections);

      case 'random':
        return connections[Math.floor(Math.random() * connections.length)];

      default:
        return connections[0];
    }
  }

  /**
   * Round-robin selection
   */
  private selectRoundRobin(connections: PooledConnection<T>[]): PooledConnection<T> {
    this.roundRobinIndex = (this.roundRobinIndex + 1) % connections.length;
    return connections[this.roundRobinIndex];
  }

  /**
   * Least connections selection (by total requests)
   */
  private selectLeastConnections(
    connections: PooledConnection<T>[]
  ): PooledConnection<T> {
    return connections.reduce((min, c) =>
      c.metrics.totalRequests < min.metrics.totalRequests ? c : min
    );
  }

  /**
   * Weighted random selection
   */
  private selectWeighted(connections: PooledConnection<T>[]): PooledConnection<T> {
    const totalWeight = connections.reduce((sum, c) => sum + c.weight, 0);
    let random = Math.random() * totalWeight;

    for (const connection of connections) {
      random -= connection.weight;
      if (random <= 0) {
        return connection;
      }
    }

    return connections[connections.length - 1];
  }

  /**
   * Latency-based selection
   */
  private selectLatencyBased(connections: PooledConnection<T>[]): PooledConnection<T> {
    return connections.reduce((best, c) =>
      c.metrics.averageLatencyMs < best.metrics.averageLatencyMs ? c : best
    );
  }

  /**
   * Get available connection excluding tried ones
   */
  private getAvailableConnection(
    excluded: Set<string>
  ): PooledConnection<T> | undefined {
    const available = Array.from(this.connections.values())
      .filter(
        (c) =>
          !excluded.has(c.id) &&
          c.health !== ConnectionHealth.UNHEALTHY &&
          c.circuitBreaker.getState() !== CircuitState.OPEN
      )
      .sort((a, b) => {
        // Prioritize healthy over degraded
        if (a.health !== b.health) {
          return a.health === ConnectionHealth.HEALTHY ? -1 : 1;
        }
        // Then by priority
        return b.priority - a.priority;
      });

    if (available.length === 0) {
      return undefined;
    }

    return this.selectByStrategy(available);
  }

  /**
   * Check health of a single connection
   */
  private async checkConnectionHealth(
    connection: PooledConnection<T>
  ): Promise<void> {
    if (!this.config.healthCheck) {
      connection.health = ConnectionHealth.HEALTHY;
      return;
    }

    try {
      const startTime = Date.now();
      const healthy = await this.config.healthCheck(connection.client);
      const latency = Date.now() - startTime;

      connection.lastHealthCheck = new Date();

      if (healthy) {
        connection.health =
          latency > 1000 ? ConnectionHealth.DEGRADED : ConnectionHealth.HEALTHY;
        connection.metrics.consecutiveFailures = 0;
      } else {
        connection.health = ConnectionHealth.UNHEALTHY;
      }
    } catch (error) {
      connection.health = ConnectionHealth.UNHEALTHY;
      connection.metrics.consecutiveFailures++;

      logger.warn(`Health check failed: ${connection.endpoint}`, {
        error: (error as Error).message,
      });

      // Auto-reconnect if enabled
      if (
        this.config.autoReconnect &&
        connection.metrics.consecutiveFailures >= 3
      ) {
        this.reconnect(connection);
      }
    }
  }

  /**
   * Attempt to reconnect a connection
   */
  private async reconnect(connection: PooledConnection<T>): Promise<void> {
    logger.info(`Attempting reconnect: ${connection.endpoint}`);

    try {
      const newClient = await this.config.createConnection(connection.endpoint);
      connection.client = newClient;
      connection.metrics.consecutiveFailures = 0;
      connection.circuitBreaker.reset();

      await this.checkConnectionHealth(connection);
      logger.info(`Reconnected: ${connection.endpoint}`);
    } catch (error) {
      logger.error(`Reconnect failed: ${connection.endpoint}`, error as Error);
    }
  }

  /**
   * Record successful request
   */
  private recordSuccess(connection: PooledConnection<T>, latencyMs: number): void {
    const metrics = connection.metrics;
    metrics.totalRequests++;
    metrics.successfulRequests++;
    metrics.lastLatencyMs = latencyMs;
    metrics.lastSuccessAt = new Date();
    metrics.consecutiveFailures = 0;

    // Update rolling average
    const alpha = 0.1;
    metrics.averageLatencyMs =
      metrics.averageLatencyMs * (1 - alpha) + latencyMs * alpha;

    // Update health based on latency
    if (latencyMs > 2000 && connection.health === ConnectionHealth.HEALTHY) {
      connection.health = ConnectionHealth.DEGRADED;
    } else if (latencyMs < 500 && connection.health === ConnectionHealth.DEGRADED) {
      connection.health = ConnectionHealth.HEALTHY;
    }
  }

  /**
   * Record failed request
   */
  private recordFailure(connection: PooledConnection<T>, error: Error): void {
    const metrics = connection.metrics;
    metrics.totalRequests++;
    metrics.failedRequests++;
    metrics.lastFailureAt = new Date();
    metrics.consecutiveFailures++;

    if (metrics.consecutiveFailures >= 3) {
      connection.health = ConnectionHealth.UNHEALTHY;
    } else if (metrics.consecutiveFailures >= 1) {
      connection.health = ConnectionHealth.DEGRADED;
    }
  }

  /**
   * Start periodic health checks
   */
  private startHealthChecks(): void {
    this.healthCheckTimer = setInterval(async () => {
      if (this.isDestroyed) return;

      await this.checkAllHealth();
    }, this.config.healthCheckIntervalMs);

    // Don't prevent process exit
    if (this.healthCheckTimer.unref) {
      this.healthCheckTimer.unref();
    }
  }

  /**
   * Create initial metrics object
   */
  private createInitialMetrics(): ConnectionMetrics {
    return {
      totalRequests: 0,
      successfulRequests: 0,
      failedRequests: 0,
      averageLatencyMs: 0,
      lastLatencyMs: 0,
      consecutiveFailures: 0,
      uptime: Date.now(),
    };
  }

  /**
   * Generate unique connection ID
   */
  private generateConnectionId(endpoint: string): string {
    return `${endpoint}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  }
}

/**
 * Pool statistics
 */
export interface PoolStats {
  totalConnections: number;
  byHealth: {
    healthy: number;
    degraded: number;
    unhealthy: number;
    unknown: number;
  };
  totalRequests: number;
  successRate: number;
  averageLatencyMs: number;
}
