/**
 * Aethelred SDK Cache System
 *
 * Multi-level caching with TTL, LRU eviction, and cache invalidation.
 */

import { getLogger } from './logger';

const logger = getLogger('cache');

/**
 * Cache entry with metadata
 */
interface CacheEntry<T> {
  value: T;
  createdAt: number;
  expiresAt: number;
  accessCount: number;
  lastAccessedAt: number;
  size: number;
  tags: string[];
}

/**
 * Cache statistics
 */
export interface CacheStats {
  hits: number;
  misses: number;
  entries: number;
  size: number;
  hitRate: number;
  oldestEntryAge: number;
  averageAccessCount: number;
}

/**
 * Cache configuration
 */
export interface CacheConfig {
  /** Maximum number of entries */
  maxEntries: number;
  /** Maximum cache size in bytes */
  maxSize: number;
  /** Default TTL in milliseconds */
  defaultTTLMs: number;
  /** Enable automatic cleanup */
  autoCleanup: boolean;
  /** Cleanup interval in milliseconds */
  cleanupIntervalMs: number;
  /** Eviction strategy */
  evictionStrategy: 'lru' | 'lfu' | 'fifo';
}

/**
 * Default cache configuration
 */
export const DEFAULT_CACHE_CONFIG: CacheConfig = {
  maxEntries: 1000,
  maxSize: 50 * 1024 * 1024, // 50MB
  defaultTTLMs: 5 * 60 * 1000, // 5 minutes
  autoCleanup: true,
  cleanupIntervalMs: 60 * 1000, // 1 minute
  evictionStrategy: 'lru',
};

/**
 * Cache options for individual entries
 */
export interface CacheOptions {
  /** TTL in milliseconds */
  ttlMs?: number;
  /** Tags for grouped invalidation */
  tags?: string[];
  /** Skip size calculation (for performance) */
  skipSizeCalc?: boolean;
}

/**
 * Estimate size of a value in bytes
 */
function estimateSize(value: unknown): number {
  const str = JSON.stringify(value);
  return str ? str.length * 2 : 0; // UTF-16 chars are 2 bytes
}

/**
 * In-memory cache implementation
 */
export class Cache {
  private entries: Map<string, CacheEntry<any>> = new Map();
  private config: CacheConfig;
  private stats = { hits: 0, misses: 0 };
  private cleanupTimer?: NodeJS.Timer;
  private currentSize = 0;

  constructor(config: Partial<CacheConfig> = {}) {
    this.config = { ...DEFAULT_CACHE_CONFIG, ...config };

    if (this.config.autoCleanup) {
      this.startCleanup();
    }
  }

  /**
   * Get a value from cache
   */
  get<T>(key: string): T | undefined {
    const entry = this.entries.get(key);

    if (!entry) {
      this.stats.misses++;
      return undefined;
    }

    // Check expiration
    if (Date.now() > entry.expiresAt) {
      this.delete(key);
      this.stats.misses++;
      return undefined;
    }

    // Update access metadata
    entry.accessCount++;
    entry.lastAccessedAt = Date.now();

    this.stats.hits++;
    return entry.value as T;
  }

  /**
   * Set a value in cache
   */
  set<T>(key: string, value: T, options: CacheOptions = {}): void {
    const ttlMs = options.ttlMs ?? this.config.defaultTTLMs;
    const size = options.skipSizeCalc ? 0 : estimateSize(value);
    const now = Date.now();

    // Check if we need to evict
    this.ensureCapacity(size);

    // Remove existing entry if present
    const existing = this.entries.get(key);
    if (existing) {
      this.currentSize -= existing.size;
    }

    const entry: CacheEntry<T> = {
      value,
      createdAt: now,
      expiresAt: now + ttlMs,
      accessCount: 0,
      lastAccessedAt: now,
      size,
      tags: options.tags || [],
    };

    this.entries.set(key, entry);
    this.currentSize += size;

    logger.trace(`Cache set: ${key}`, { ttlMs, size, tags: options.tags });
  }

  /**
   * Check if key exists and is valid
   */
  has(key: string): boolean {
    const entry = this.entries.get(key);
    if (!entry) return false;

    if (Date.now() > entry.expiresAt) {
      this.delete(key);
      return false;
    }

    return true;
  }

  /**
   * Delete a key from cache
   */
  delete(key: string): boolean {
    const entry = this.entries.get(key);
    if (entry) {
      this.currentSize -= entry.size;
      this.entries.delete(key);
      logger.trace(`Cache delete: ${key}`);
      return true;
    }
    return false;
  }

  /**
   * Clear all entries
   */
  clear(): void {
    this.entries.clear();
    this.currentSize = 0;
    this.stats = { hits: 0, misses: 0 };
    logger.debug('Cache cleared');
  }

  /**
   * Invalidate entries by tag
   */
  invalidateByTag(tag: string): number {
    let count = 0;
    for (const [key, entry] of this.entries) {
      if (entry.tags.includes(tag)) {
        this.delete(key);
        count++;
      }
    }
    logger.debug(`Cache invalidated by tag: ${tag}`, { count });
    return count;
  }

  /**
   * Invalidate entries matching a predicate
   */
  invalidateWhere(predicate: (key: string, value: any) => boolean): number {
    let count = 0;
    for (const [key, entry] of this.entries) {
      if (predicate(key, entry.value)) {
        this.delete(key);
        count++;
      }
    }
    return count;
  }

  /**
   * Get or set with a factory function
   */
  async getOrSet<T>(
    key: string,
    factory: () => T | Promise<T>,
    options: CacheOptions = {}
  ): Promise<T> {
    const existing = this.get<T>(key);
    if (existing !== undefined) {
      return existing;
    }

    const value = await factory();
    this.set(key, value, options);
    return value;
  }

  /**
   * Get cache statistics
   */
  getStats(): CacheStats {
    const total = this.stats.hits + this.stats.misses;
    let oldestAge = 0;
    let totalAccessCount = 0;

    const now = Date.now();
    for (const entry of this.entries.values()) {
      const age = now - entry.createdAt;
      if (age > oldestAge) oldestAge = age;
      totalAccessCount += entry.accessCount;
    }

    return {
      hits: this.stats.hits,
      misses: this.stats.misses,
      entries: this.entries.size,
      size: this.currentSize,
      hitRate: total > 0 ? this.stats.hits / total : 0,
      oldestEntryAge: oldestAge,
      averageAccessCount:
        this.entries.size > 0 ? totalAccessCount / this.entries.size : 0,
    };
  }

  /**
   * Get all keys
   */
  keys(): string[] {
    return Array.from(this.entries.keys());
  }

  /**
   * Get all values
   */
  values<T>(): T[] {
    return Array.from(this.entries.values())
      .filter((entry) => Date.now() <= entry.expiresAt)
      .map((entry) => entry.value as T);
  }

  /**
   * Get entries by tag
   */
  getByTag<T>(tag: string): Map<string, T> {
    const result = new Map<string, T>();
    const now = Date.now();

    for (const [key, entry] of this.entries) {
      if (entry.tags.includes(tag) && now <= entry.expiresAt) {
        result.set(key, entry.value as T);
      }
    }

    return result;
  }

  /**
   * Refresh TTL for a key
   */
  touch(key: string, ttlMs?: number): boolean {
    const entry = this.entries.get(key);
    if (!entry) return false;

    const effectiveTTL = ttlMs ?? this.config.defaultTTLMs;
    entry.expiresAt = Date.now() + effectiveTTL;
    entry.lastAccessedAt = Date.now();
    return true;
  }

  /**
   * Stop automatic cleanup
   */
  destroy(): void {
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer);
      this.cleanupTimer = undefined;
    }
    this.clear();
  }

  /**
   * Ensure capacity for new entry
   */
  private ensureCapacity(newSize: number): void {
    // Check entry count
    while (this.entries.size >= this.config.maxEntries) {
      this.evictOne();
    }

    // Check size
    while (this.currentSize + newSize > this.config.maxSize && this.entries.size > 0) {
      this.evictOne();
    }
  }

  /**
   * Evict one entry based on strategy
   */
  private evictOne(): void {
    if (this.entries.size === 0) return;

    let victimKey: string | undefined;
    let victimScore = Infinity;

    for (const [key, entry] of this.entries) {
      let score: number;

      switch (this.config.evictionStrategy) {
        case 'lru':
          score = entry.lastAccessedAt;
          break;
        case 'lfu':
          score = entry.accessCount;
          break;
        case 'fifo':
          score = entry.createdAt;
          break;
        default:
          score = entry.lastAccessedAt;
      }

      if (score < victimScore) {
        victimScore = score;
        victimKey = key;
      }
    }

    if (victimKey) {
      this.delete(victimKey);
      logger.trace(`Cache evicted: ${victimKey}`, {
        strategy: this.config.evictionStrategy,
      });
    }
  }

  /**
   * Start automatic cleanup
   */
  private startCleanup(): void {
    this.cleanupTimer = setInterval(() => {
      this.cleanup();
    }, this.config.cleanupIntervalMs);

    // Don't prevent process exit
    if (this.cleanupTimer.unref) {
      this.cleanupTimer.unref();
    }
  }

  /**
   * Clean up expired entries
   */
  private cleanup(): void {
    const now = Date.now();
    let cleaned = 0;

    for (const [key, entry] of this.entries) {
      if (now > entry.expiresAt) {
        this.delete(key);
        cleaned++;
      }
    }

    if (cleaned > 0) {
      logger.trace(`Cache cleanup: removed ${cleaned} expired entries`);
    }
  }
}

/**
 * Cache decorator for methods
 */
export function cached(options: CacheOptions & { keyGenerator?: (...args: any[]) => string } = {}) {
  const cache = new Cache();

  return function (
    target: any,
    propertyKey: string,
    descriptor: PropertyDescriptor
  ) {
    const originalMethod = descriptor.value;

    descriptor.value = async function (...args: any[]) {
      const key = options.keyGenerator
        ? options.keyGenerator(...args)
        : `${propertyKey}:${JSON.stringify(args)}`;

      return cache.getOrSet(key, () => originalMethod.apply(this, args), options);
    };

    return descriptor;
  };
}

/**
 * Memoization with cache
 */
export function memoize<T extends (...args: any[]) => any>(
  fn: T,
  options: CacheOptions & { keyGenerator?: (...args: Parameters<T>) => string } = {}
): T {
  const cache = new Cache();

  return ((...args: Parameters<T>) => {
    const key = options.keyGenerator
      ? options.keyGenerator(...args)
      : JSON.stringify(args);

    const existing = cache.get<ReturnType<T>>(key);
    if (existing !== undefined) {
      return existing;
    }

    const result = fn(...args);

    // Handle promises
    if (result instanceof Promise) {
      return result.then((value) => {
        cache.set(key, value, options);
        return value;
      });
    }

    cache.set(key, result, options);
    return result;
  }) as T;
}

/**
 * Create a namespaced cache
 */
export function createNamespacedCache(
  namespace: string,
  config: Partial<CacheConfig> = {}
): Cache {
  const cache = new Cache(config);
  const originalSet = cache.set.bind(cache);
  const originalGet = cache.get.bind(cache);
  const originalDelete = cache.delete.bind(cache);
  const originalHas = cache.has.bind(cache);

  cache.set = (key: string, value: any, options?: CacheOptions) => {
    return originalSet(`${namespace}:${key}`, value, options);
  };

  cache.get = <T>(key: string) => {
    return originalGet<T>(`${namespace}:${key}`);
  };

  cache.delete = (key: string) => {
    return originalDelete(`${namespace}:${key}`);
  };

  cache.has = (key: string) => {
    return originalHas(`${namespace}:${key}`);
  };

  return cache;
}

/**
 * Global SDK cache instance
 */
export const globalCache = new Cache({
  maxEntries: 5000,
  maxSize: 100 * 1024 * 1024, // 100MB
  defaultTTLMs: 5 * 60 * 1000, // 5 minutes
});
