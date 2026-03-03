/**
 * Aethelred VS Code Extension - Logger
 *
 * Enterprise-grade logging with structured output, log levels,
 * and integration with VS Code's output channels.
 */

import * as vscode from 'vscode';

/**
 * Log levels in order of verbosity.
 */
export enum LogLevel {
    Error = 0,
    Warn = 1,
    Info = 2,
    Debug = 3,
    Trace = 4,
}

/**
 * Log entry structure.
 */
interface LogEntry {
    timestamp: Date;
    level: LogLevel;
    category: string;
    message: string;
    data?: unknown;
    error?: Error;
}

/**
 * Logger configuration.
 */
interface LoggerConfig {
    level: LogLevel;
    showTimestamp: boolean;
    showCategory: boolean;
    maxHistorySize: number;
}

/**
 * Enterprise-grade logger for the Aethelred extension.
 */
export class Logger {
    private static instance: Logger | null = null;

    private readonly outputChannel: vscode.OutputChannel;
    private readonly history: LogEntry[] = [];
    private config: LoggerConfig = {
        level: LogLevel.Info,
        showTimestamp: true,
        showCategory: true,
        maxHistorySize: 1000,
    };

    private constructor() {
        this.outputChannel = vscode.window.createOutputChannel(
            'Aethelred Sovereign Copilot',
            { log: true }
        );
    }

    /**
     * Get the singleton logger instance.
     */
    static getInstance(): Logger {
        if (!Logger.instance) {
            Logger.instance = new Logger();
        }
        return Logger.instance;
    }

    /**
     * Create a child logger with a category prefix.
     */
    createChild(category: string): CategoryLogger {
        return new CategoryLogger(this, category);
    }

    /**
     * Set the log level.
     */
    setLevel(level: LogLevel | string): void {
        if (typeof level === 'string') {
            this.config.level = this.parseLevel(level);
        } else {
            this.config.level = level;
        }
    }

    /**
     * Parse a string log level.
     */
    private parseLevel(level: string): LogLevel {
        const levels: Record<string, LogLevel> = {
            error: LogLevel.Error,
            warn: LogLevel.Warn,
            info: LogLevel.Info,
            debug: LogLevel.Debug,
            trace: LogLevel.Trace,
        };
        return levels[level.toLowerCase()] ?? LogLevel.Info;
    }

    /**
     * Show the output channel.
     */
    show(): void {
        this.outputChannel.show();
    }

    /**
     * Clear the output channel.
     */
    clear(): void {
        this.outputChannel.clear();
        this.history.length = 0;
    }

    /**
     * Get log history.
     */
    getHistory(): readonly LogEntry[] {
        return this.history;
    }

    /**
     * Log an error.
     */
    error(message: string, error?: Error | unknown, data?: unknown): void {
        this.log(LogLevel.Error, '', message, data, error as Error);
    }

    /**
     * Log a warning.
     */
    warn(message: string, data?: unknown): void {
        this.log(LogLevel.Warn, '', message, data);
    }

    /**
     * Log info.
     */
    info(message: string, data?: unknown): void {
        this.log(LogLevel.Info, '', message, data);
    }

    /**
     * Log debug info.
     */
    debug(message: string, data?: unknown): void {
        this.log(LogLevel.Debug, '', message, data);
    }

    /**
     * Log trace info.
     */
    trace(message: string, data?: unknown): void {
        this.log(LogLevel.Trace, '', message, data);
    }

    /**
     * Internal logging method.
     */
    log(
        level: LogLevel,
        category: string,
        message: string,
        data?: unknown,
        error?: Error
    ): void {
        if (level > this.config.level) {
            return;
        }

        const entry: LogEntry = {
            timestamp: new Date(),
            level,
            category,
            message,
            data,
            error,
        };

        // Store in history
        this.history.push(entry);
        if (this.history.length > this.config.maxHistorySize) {
            this.history.shift();
        }

        // Format and output
        const formatted = this.format(entry);
        this.outputChannel.appendLine(formatted);

        // Also log errors to the console for debugging
        if (level === LogLevel.Error && error) {
            console.error(`[Aethelred] ${message}`, error);
        }
    }

    /**
     * Format a log entry.
     */
    private format(entry: LogEntry): string {
        const parts: string[] = [];

        // Timestamp
        if (this.config.showTimestamp) {
            parts.push(`[${entry.timestamp.toISOString()}]`);
        }

        // Level
        parts.push(`[${LogLevel[entry.level].toUpperCase()}]`);

        // Category
        if (this.config.showCategory && entry.category) {
            parts.push(`[${entry.category}]`);
        }

        // Message
        parts.push(entry.message);

        // Data
        if (entry.data !== undefined) {
            try {
                const dataStr = JSON.stringify(entry.data, null, 2);
                if (dataStr.length < 500) {
                    parts.push(`\n  Data: ${dataStr}`);
                } else {
                    parts.push(`\n  Data: ${dataStr.substring(0, 500)}...`);
                }
            } catch {
                parts.push(`\n  Data: [Unserializable]`);
            }
        }

        // Error
        if (entry.error) {
            parts.push(`\n  Error: ${entry.error.message}`);
            if (entry.error.stack) {
                parts.push(`\n  Stack: ${entry.error.stack}`);
            }
        }

        return parts.join(' ');
    }

    /**
     * Dispose resources.
     */
    dispose(): void {
        this.outputChannel.dispose();
        Logger.instance = null;
    }
}

/**
 * Category-specific logger.
 */
export class CategoryLogger {
    constructor(
        private readonly parent: Logger,
        private readonly category: string
    ) {}

    error(message: string, error?: Error | unknown, data?: unknown): void {
        this.parent.log(LogLevel.Error, this.category, message, data, error as Error);
    }

    warn(message: string, data?: unknown): void {
        this.parent.log(LogLevel.Warn, this.category, message, data);
    }

    info(message: string, data?: unknown): void {
        this.parent.log(LogLevel.Info, this.category, message, data);
    }

    debug(message: string, data?: unknown): void {
        this.parent.log(LogLevel.Debug, this.category, message, data);
    }

    trace(message: string, data?: unknown): void {
        this.parent.log(LogLevel.Trace, this.category, message, data);
    }
}

// Export singleton accessor
export const logger = Logger.getInstance();
