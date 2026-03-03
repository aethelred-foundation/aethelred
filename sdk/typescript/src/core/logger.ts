/**
 * Aethelred SDK Logger
 *
 * Structured logging with levels, namespaces, and pluggable transports.
 */

/**
 * Log levels
 */
export enum LogLevel {
  TRACE = 0,
  DEBUG = 1,
  INFO = 2,
  WARN = 3,
  ERROR = 4,
  FATAL = 5,
  SILENT = 6,
}

/**
 * Log level names
 */
export const LOG_LEVEL_NAMES: Record<LogLevel, string> = {
  [LogLevel.TRACE]: 'TRACE',
  [LogLevel.DEBUG]: 'DEBUG',
  [LogLevel.INFO]: 'INFO',
  [LogLevel.WARN]: 'WARN',
  [LogLevel.ERROR]: 'ERROR',
  [LogLevel.FATAL]: 'FATAL',
  [LogLevel.SILENT]: 'SILENT',
};

/**
 * Log entry structure
 */
export interface LogEntry {
  timestamp: Date;
  level: LogLevel;
  levelName: string;
  namespace: string;
  message: string;
  data?: Record<string, unknown>;
  error?: Error;
  duration?: number;
  requestId?: string;
}

/**
 * Log transport interface
 */
export interface LogTransport {
  name: string;
  log(entry: LogEntry): void;
}

/**
 * Console transport with colors
 */
export class ConsoleTransport implements LogTransport {
  name = 'console';

  private colors: Record<LogLevel, string> = {
    [LogLevel.TRACE]: '\x1b[90m', // Gray
    [LogLevel.DEBUG]: '\x1b[36m', // Cyan
    [LogLevel.INFO]: '\x1b[32m', // Green
    [LogLevel.WARN]: '\x1b[33m', // Yellow
    [LogLevel.ERROR]: '\x1b[31m', // Red
    [LogLevel.FATAL]: '\x1b[35m', // Magenta
    [LogLevel.SILENT]: '',
  };

  private reset = '\x1b[0m';

  constructor(private useColors: boolean = true) {}

  log(entry: LogEntry): void {
    const color = this.useColors ? this.colors[entry.level] : '';
    const reset = this.useColors ? this.reset : '';

    const timestamp = entry.timestamp.toISOString();
    const prefix = `${color}[${timestamp}] [${entry.levelName}] [${entry.namespace}]${reset}`;

    let output = `${prefix} ${entry.message}`;

    if (entry.duration !== undefined) {
      output += ` (${entry.duration}ms)`;
    }

    if (entry.requestId) {
      output += ` [req:${entry.requestId}]`;
    }

    if (entry.data && Object.keys(entry.data).length > 0) {
      output += `\n  ${JSON.stringify(entry.data, null, 2).replace(/\n/g, '\n  ')}`;
    }

    if (entry.error) {
      output += `\n  Error: ${entry.error.message}`;
      if (entry.error.stack) {
        output += `\n  ${entry.error.stack.replace(/\n/g, '\n  ')}`;
      }
    }

    switch (entry.level) {
      case LogLevel.ERROR:
      case LogLevel.FATAL:
        console.error(output);
        break;
      case LogLevel.WARN:
        console.warn(output);
        break;
      default:
        console.log(output);
    }
  }
}

/**
 * JSON transport for structured logging
 */
export class JSONTransport implements LogTransport {
  name = 'json';

  constructor(private pretty: boolean = false) {}

  log(entry: LogEntry): void {
    const output = {
      timestamp: entry.timestamp.toISOString(),
      level: entry.levelName.toLowerCase(),
      namespace: entry.namespace,
      message: entry.message,
      ...(entry.data && { data: entry.data }),
      ...(entry.error && {
        error: {
          name: entry.error.name,
          message: entry.error.message,
          stack: entry.error.stack,
        },
      }),
      ...(entry.duration !== undefined && { durationMs: entry.duration }),
      ...(entry.requestId && { requestId: entry.requestId }),
    };

    console.log(
      this.pretty ? JSON.stringify(output, null, 2) : JSON.stringify(output)
    );
  }
}

/**
 * Memory transport for testing
 */
export class MemoryTransport implements LogTransport {
  name = 'memory';
  public entries: LogEntry[] = [];

  log(entry: LogEntry): void {
    this.entries.push(entry);
  }

  clear(): void {
    this.entries = [];
  }

  getEntries(level?: LogLevel): LogEntry[] {
    if (level === undefined) {
      return [...this.entries];
    }
    return this.entries.filter((e) => e.level === level);
  }
}

/**
 * Logger configuration
 */
export interface LoggerConfig {
  level: LogLevel;
  transports: LogTransport[];
  defaultNamespace: string;
}

/**
 * Default configuration
 */
const DEFAULT_CONFIG: LoggerConfig = {
  level: LogLevel.INFO,
  transports: [new ConsoleTransport()],
  defaultNamespace: 'aethelred',
};

/**
 * Global logger state
 */
let globalConfig: LoggerConfig = { ...DEFAULT_CONFIG };

/**
 * Logger class
 */
export class Logger {
  private namespace: string;
  private context: Record<string, unknown> = {};

  constructor(namespace?: string) {
    this.namespace = namespace || globalConfig.defaultNamespace;
  }

  /**
   * Create child logger with namespace
   */
  child(namespace: string): Logger {
    const childNamespace = this.namespace
      ? `${this.namespace}:${namespace}`
      : namespace;
    const child = new Logger(childNamespace);
    child.context = { ...this.context };
    return child;
  }

  /**
   * Add context to all log entries
   */
  withContext(context: Record<string, unknown>): Logger {
    const newLogger = new Logger(this.namespace);
    newLogger.context = { ...this.context, ...context };
    return newLogger;
  }

  /**
   * Log at trace level
   */
  trace(message: string, data?: Record<string, unknown>): void {
    this.log(LogLevel.TRACE, message, data);
  }

  /**
   * Log at debug level
   */
  debug(message: string, data?: Record<string, unknown>): void {
    this.log(LogLevel.DEBUG, message, data);
  }

  /**
   * Log at info level
   */
  info(message: string, data?: Record<string, unknown>): void {
    this.log(LogLevel.INFO, message, data);
  }

  /**
   * Log at warn level
   */
  warn(message: string, data?: Record<string, unknown>): void {
    this.log(LogLevel.WARN, message, data);
  }

  /**
   * Log at error level
   */
  error(message: string, error?: Error, data?: Record<string, unknown>): void {
    this.log(LogLevel.ERROR, message, data, error);
  }

  /**
   * Log at fatal level
   */
  fatal(message: string, error?: Error, data?: Record<string, unknown>): void {
    this.log(LogLevel.FATAL, message, data, error);
  }

  /**
   * Time an operation
   */
  time<T>(label: string, fn: () => T): T {
    const start = performance.now();
    try {
      const result = fn();
      const duration = Math.round(performance.now() - start);
      this.debug(`${label} completed`, { duration });
      return result;
    } catch (error) {
      const duration = Math.round(performance.now() - start);
      this.error(`${label} failed`, error as Error, { duration });
      throw error;
    }
  }

  /**
   * Time an async operation
   */
  async timeAsync<T>(label: string, fn: () => Promise<T>): Promise<T> {
    const start = performance.now();
    try {
      const result = await fn();
      const duration = Math.round(performance.now() - start);
      this.debug(`${label} completed`, { duration });
      return result;
    } catch (error) {
      const duration = Math.round(performance.now() - start);
      this.error(`${label} failed`, error as Error, { duration });
      throw error;
    }
  }

  /**
   * Core log method
   */
  private log(
    level: LogLevel,
    message: string,
    data?: Record<string, unknown>,
    error?: Error
  ): void {
    if (level < globalConfig.level) {
      return;
    }

    const entry: LogEntry = {
      timestamp: new Date(),
      level,
      levelName: LOG_LEVEL_NAMES[level],
      namespace: this.namespace,
      message,
      data: { ...this.context, ...data },
      error,
    };

    for (const transport of globalConfig.transports) {
      try {
        transport.log(entry);
      } catch (err) {
        console.error(`Logger transport ${transport.name} failed:`, err);
      }
    }
  }
}

/**
 * Configure the global logger
 */
export function configureLogger(config: Partial<LoggerConfig>): void {
  globalConfig = {
    ...globalConfig,
    ...config,
  };
}

/**
 * Get current log level
 */
export function getLogLevel(): LogLevel {
  return globalConfig.level;
}

/**
 * Set log level
 */
export function setLogLevel(level: LogLevel): void {
  globalConfig.level = level;
}

/**
 * Add a transport
 */
export function addTransport(transport: LogTransport): void {
  globalConfig.transports.push(transport);
}

/**
 * Remove a transport by name
 */
export function removeTransport(name: string): void {
  globalConfig.transports = globalConfig.transports.filter(
    (t) => t.name !== name
  );
}

/**
 * Create a logger instance
 */
export function createLogger(namespace?: string): Logger {
  return new Logger(namespace);
}

/**
 * Default logger instance
 */
export const logger = createLogger();

/**
 * Shorthand for creating child loggers
 */
export function getLogger(namespace: string): Logger {
  return logger.child(namespace);
}
