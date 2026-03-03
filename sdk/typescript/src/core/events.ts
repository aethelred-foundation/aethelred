/**
 * Aethelred SDK Event System
 *
 * Type-safe event emitter with namespaces, filtering, and observables.
 */

import { getLogger } from './logger';

const logger = getLogger('events');

/**
 * Event types for the SDK
 */
export enum AethelredEventType {
  // Connection events
  CONNECTED = 'connected',
  DISCONNECTED = 'disconnected',
  RECONNECTING = 'reconnecting',
  RECONNECTED = 'reconnected',

  // Block events
  NEW_BLOCK = 'newBlock',
  BLOCK_FINALIZED = 'blockFinalized',

  // Transaction events
  TX_SUBMITTED = 'txSubmitted',
  TX_CONFIRMED = 'txConfirmed',
  TX_FAILED = 'txFailed',

  // Seal events
  SEAL_CREATED = 'sealCreated',
  SEAL_VERIFIED = 'sealVerified',
  SEAL_REVOKED = 'sealRevoked',

  // Compute events
  JOB_SUBMITTED = 'jobSubmitted',
  JOB_ASSIGNED = 'jobAssigned',
  JOB_EXECUTING = 'jobExecuting',
  JOB_COMPLETED = 'jobCompleted',
  JOB_FAILED = 'jobFailed',

  // General
  ERROR = 'error',
}

/**
 * Event payload types
 */
export interface EventPayloads {
  [AethelredEventType.CONNECTED]: {
    chainId: string;
    blockHeight: number;
  };
  [AethelredEventType.DISCONNECTED]: {
    reason?: string;
  };
  [AethelredEventType.RECONNECTING]: {
    attempt: number;
    maxAttempts: number;
  };
  [AethelredEventType.RECONNECTED]: {
    chainId: string;
    attempts: number;
  };
  [AethelredEventType.NEW_BLOCK]: {
    height: number;
    hash: string;
    time: Date;
    txCount: number;
  };
  [AethelredEventType.BLOCK_FINALIZED]: {
    height: number;
    hash: string;
  };
  [AethelredEventType.TX_SUBMITTED]: {
    txHash: string;
    type: string;
  };
  [AethelredEventType.TX_CONFIRMED]: {
    txHash: string;
    height: number;
    gasUsed: number;
  };
  [AethelredEventType.TX_FAILED]: {
    txHash: string;
    error: string;
    code: number;
  };
  [AethelredEventType.SEAL_CREATED]: {
    sealId: string;
    modelHash: string;
    blockHeight: number;
  };
  [AethelredEventType.SEAL_VERIFIED]: {
    sealId: string;
    valid: boolean;
  };
  [AethelredEventType.SEAL_REVOKED]: {
    sealId: string;
    reason: string;
  };
  [AethelredEventType.JOB_SUBMITTED]: {
    jobId: string;
    modelHash: string;
  };
  [AethelredEventType.JOB_ASSIGNED]: {
    jobId: string;
    validators: string[];
  };
  [AethelredEventType.JOB_EXECUTING]: {
    jobId: string;
    validator: string;
  };
  [AethelredEventType.JOB_COMPLETED]: {
    jobId: string;
    outputHash: string;
    sealId?: string;
    executionTimeMs: number;
  };
  [AethelredEventType.JOB_FAILED]: {
    jobId: string;
    error: string;
  };
  [AethelredEventType.ERROR]: {
    error: Error;
    context?: string;
  };
}

/**
 * Event handler type
 */
export type EventHandler<T extends AethelredEventType> = (
  payload: EventPayloads[T]
) => void | Promise<void>;

/**
 * Event subscription
 */
export interface EventSubscription {
  /** Unique subscription ID */
  id: string;
  /** Event type */
  type: AethelredEventType;
  /** Unsubscribe function */
  unsubscribe: () => void;
}

/**
 * Event filter function
 */
export type EventFilter<T extends AethelredEventType> = (
  payload: EventPayloads[T]
) => boolean;

/**
 * Event listener options
 */
export interface EventListenerOptions<T extends AethelredEventType> {
  /** Only trigger once */
  once?: boolean;
  /** Filter function */
  filter?: EventFilter<T>;
  /** Priority (higher runs first) */
  priority?: number;
}

/**
 * Internal listener entry
 */
interface ListenerEntry<T extends AethelredEventType> {
  id: string;
  handler: EventHandler<T>;
  options: EventListenerOptions<T>;
}

/**
 * Generate unique ID
 */
function generateId(): string {
  return Math.random().toString(36).substring(2) + Date.now().toString(36);
}

/**
 * Type-safe event emitter
 */
export class EventEmitter {
  private listeners: Map<AethelredEventType, ListenerEntry<any>[]> = new Map();
  private allListeners: ListenerEntry<any>[] = [];
  private eventHistory: Map<AethelredEventType, any[]> = new Map();
  private historySize = 100;

  /**
   * Subscribe to an event
   */
  on<T extends AethelredEventType>(
    type: T,
    handler: EventHandler<T>,
    options: EventListenerOptions<T> = {}
  ): EventSubscription {
    const id = generateId();
    const entry: ListenerEntry<T> = {
      id,
      handler,
      options: { priority: 0, ...options },
    };

    const listeners = this.listeners.get(type) || [];
    listeners.push(entry);

    // Sort by priority (descending)
    listeners.sort((a, b) => (b.options.priority || 0) - (a.options.priority || 0));

    this.listeners.set(type, listeners);

    return {
      id,
      type,
      unsubscribe: () => this.off(type, id),
    };
  }

  /**
   * Subscribe to an event (fires only once)
   */
  once<T extends AethelredEventType>(
    type: T,
    handler: EventHandler<T>,
    options: Omit<EventListenerOptions<T>, 'once'> = {}
  ): EventSubscription {
    return this.on(type, handler, { ...options, once: true });
  }

  /**
   * Subscribe to all events
   */
  onAny(
    handler: (type: AethelredEventType, payload: any) => void | Promise<void>
  ): EventSubscription {
    const id = generateId();
    const entry: ListenerEntry<any> = {
      id,
      handler: (payload: any) => handler(payload.__type, payload),
      options: {},
    };

    this.allListeners.push(entry);

    return {
      id,
      type: AethelredEventType.ERROR, // Placeholder
      unsubscribe: () => {
        this.allListeners = this.allListeners.filter((l) => l.id !== id);
      },
    };
  }

  /**
   * Unsubscribe from an event
   */
  off<T extends AethelredEventType>(type: T, id: string): void {
    const listeners = this.listeners.get(type);
    if (listeners) {
      this.listeners.set(
        type,
        listeners.filter((l) => l.id !== id)
      );
    }
  }

  /**
   * Remove all listeners for an event type
   */
  removeAllListeners(type?: AethelredEventType): void {
    if (type) {
      this.listeners.delete(type);
    } else {
      this.listeners.clear();
      this.allListeners = [];
    }
  }

  /**
   * Emit an event
   */
  async emit<T extends AethelredEventType>(
    type: T,
    payload: EventPayloads[T]
  ): Promise<void> {
    logger.trace(`Event emitted: ${type}`, { payload });

    // Store in history
    this.addToHistory(type, payload);

    const listeners = this.listeners.get(type) || [];
    const toRemove: string[] = [];

    // Execute type-specific listeners
    for (const listener of listeners) {
      // Apply filter
      if (listener.options.filter && !listener.options.filter(payload)) {
        continue;
      }

      try {
        await listener.handler(payload);
      } catch (error) {
        logger.error(`Event handler error for ${type}`, error as Error);
      }

      // Mark for removal if once
      if (listener.options.once) {
        toRemove.push(listener.id);
      }
    }

    // Remove once listeners
    if (toRemove.length > 0) {
      this.listeners.set(
        type,
        listeners.filter((l) => !toRemove.includes(l.id))
      );
    }

    // Execute all-event listeners
    for (const listener of this.allListeners) {
      try {
        await listener.handler({ ...payload, __type: type });
      } catch (error) {
        logger.error(`All-event handler error`, error as Error);
      }
    }
  }

  /**
   * Emit an event synchronously
   */
  emitSync<T extends AethelredEventType>(
    type: T,
    payload: EventPayloads[T]
  ): void {
    this.emit(type, payload).catch((error) => {
      logger.error(`Event emission error for ${type}`, error);
    });
  }

  /**
   * Get listener count for an event type
   */
  listenerCount(type?: AethelredEventType): number {
    if (type) {
      return (this.listeners.get(type) || []).length;
    }

    let count = this.allListeners.length;
    for (const listeners of this.listeners.values()) {
      count += listeners.length;
    }
    return count;
  }

  /**
   * Get event history
   */
  getHistory<T extends AethelredEventType>(
    type: T,
    limit?: number
  ): EventPayloads[T][] {
    const history = this.eventHistory.get(type) || [];
    if (limit) {
      return history.slice(-limit);
    }
    return [...history];
  }

  /**
   * Clear event history
   */
  clearHistory(type?: AethelredEventType): void {
    if (type) {
      this.eventHistory.delete(type);
    } else {
      this.eventHistory.clear();
    }
  }

  /**
   * Wait for an event
   */
  waitFor<T extends AethelredEventType>(
    type: T,
    filter?: EventFilter<T>,
    timeoutMs?: number
  ): Promise<EventPayloads[T]> {
    return new Promise((resolve, reject) => {
      let timeout: NodeJS.Timeout | undefined;

      const subscription = this.once(
        type,
        (payload) => {
          if (timeout) clearTimeout(timeout);
          resolve(payload);
        },
        { filter }
      );

      if (timeoutMs) {
        timeout = setTimeout(() => {
          subscription.unsubscribe();
          reject(new Error(`Timeout waiting for event ${type}`));
        }, timeoutMs);
      }
    });
  }

  /**
   * Create an async iterator for events
   */
  async *iterate<T extends AethelredEventType>(
    type: T,
    filter?: EventFilter<T>
  ): AsyncGenerator<EventPayloads[T]> {
    const queue: EventPayloads[T][] = [];
    let resolve: ((value: EventPayloads[T]) => void) | null = null;

    const subscription = this.on(
      type,
      (payload) => {
        if (resolve) {
          resolve(payload);
          resolve = null;
        } else {
          queue.push(payload);
        }
      },
      { filter }
    );

    try {
      while (true) {
        if (queue.length > 0) {
          yield queue.shift()!;
        } else {
          yield await new Promise<EventPayloads[T]>((r) => {
            resolve = r;
          });
        }
      }
    } finally {
      subscription.unsubscribe();
    }
  }

  /**
   * Add payload to history
   */
  private addToHistory<T extends AethelredEventType>(
    type: T,
    payload: EventPayloads[T]
  ): void {
    let history = this.eventHistory.get(type);
    if (!history) {
      history = [];
      this.eventHistory.set(type, history);
    }

    history.push(payload);

    // Trim to size
    if (history.length > this.historySize) {
      history.shift();
    }
  }
}

/**
 * Observable wrapper for events
 */
export class EventObservable<T extends AethelredEventType> {
  constructor(
    private emitter: EventEmitter,
    private type: T
  ) {}

  /**
   * Subscribe to events
   */
  subscribe(handler: EventHandler<T>): EventSubscription {
    return this.emitter.on(this.type, handler);
  }

  /**
   * Filter events
   */
  filter(predicate: EventFilter<T>): EventObservable<T> {
    const filtered = new FilteredEventObservable(this.emitter, this.type, predicate);
    return filtered as unknown as EventObservable<T>;
  }

  /**
   * Map events
   */
  map<U>(mapper: (payload: EventPayloads[T]) => U): MappedEventObservable<T, U> {
    return new MappedEventObservable(this.emitter, this.type, mapper);
  }

  /**
   * Take first N events
   */
  take(count: number): Promise<EventPayloads[T][]> {
    return new Promise((resolve) => {
      const results: EventPayloads[T][] = [];

      const subscription = this.emitter.on(this.type, (payload) => {
        results.push(payload);
        if (results.length >= count) {
          subscription.unsubscribe();
          resolve(results);
        }
      });
    });
  }

  /**
   * Convert to async iterator
   */
  [Symbol.asyncIterator](): AsyncGenerator<EventPayloads[T]> {
    return this.emitter.iterate(this.type);
  }
}

/**
 * Filtered event observable
 */
class FilteredEventObservable<T extends AethelredEventType> extends EventObservable<T> {
  constructor(
    emitter: EventEmitter,
    type: T,
    private predicate: EventFilter<T>
  ) {
    super(emitter, type);
  }

  subscribe(handler: EventHandler<T>): EventSubscription {
    return (this as any).emitter.on((this as any).type, handler, {
      filter: this.predicate,
    });
  }
}

/**
 * Mapped event observable
 */
class MappedEventObservable<T extends AethelredEventType, U> {
  constructor(
    private emitter: EventEmitter,
    private type: T,
    private mapper: (payload: EventPayloads[T]) => U
  ) {}

  subscribe(handler: (value: U) => void | Promise<void>): EventSubscription {
    return this.emitter.on(this.type, (payload) => {
      handler(this.mapper(payload));
    });
  }
}

/**
 * Global event emitter instance
 */
export const globalEmitter = new EventEmitter();

/**
 * Create an observable for an event type
 */
export function observe<T extends AethelredEventType>(
  type: T,
  emitter: EventEmitter = globalEmitter
): EventObservable<T> {
  return new EventObservable(emitter, type);
}
