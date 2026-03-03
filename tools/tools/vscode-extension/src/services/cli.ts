/**
 * Aethelred VS Code Extension - CLI Service
 *
 * Enterprise-grade wrapper for the 'aeth' Rust CLI binary.
 * Provides type-safe access to all CLI commands with proper
 * error handling, caching, and cancellation support.
 */

import * as vscode from 'vscode';
import * as cp from 'child_process';
import * as path from 'path';
import * as fs from 'fs';
import { promisify } from 'util';
import {
    CliResult,
    CliError,
    CliOptions,
    ComplianceReport,
    CostEstimate,
    HardwareInfo,
    Jurisdiction,
    Regulation,
    HardwareType,
    DigitalSeal,
} from '../types';
import { logger, CategoryLogger } from '../utils/logger';
import { configManager } from '../utils/config';

const execAsync = promisify(cp.exec);
const existsAsync = promisify(fs.exists);

/**
 * CLI execution context.
 */
interface ExecutionContext {
    command: string;
    args: string[];
    cwd: string;
    timeout: number;
    startTime: number;
    cancellationToken?: vscode.CancellationToken;
}

/**
 * CLI output parser.
 */
type OutputParser<T> = (stdout: string, stderr: string) => T;

/**
 * Command cache entry.
 */
interface CacheEntry<T> {
    result: T;
    timestamp: number;
    hash: string;
}

/**
 * Enterprise-grade CLI service for interacting with the aeth binary.
 */
export class AethCli {
    private static instance: AethCli | null = null;

    private readonly log: CategoryLogger;
    private cliPath: string | null = null;
    private cliVersion: string | null = null;
    private readonly cache = new Map<string, CacheEntry<unknown>>();
    private readonly cacheMaxAge = 5000; // 5 seconds
    private readonly runningCommands = new Map<string, cp.ChildProcess>();

    private constructor() {
        this.log = logger.createChild('CLI');
    }

    /**
     * Get the singleton instance.
     */
    static getInstance(): AethCli {
        if (!AethCli.instance) {
            AethCli.instance = new AethCli();
        }
        return AethCli.instance;
    }

    // =========================================================================
    // Initialization
    // =========================================================================

    /**
     * Initialize the CLI service.
     */
    async initialize(): Promise<boolean> {
        this.log.info('Initializing CLI service...');

        try {
            // Find CLI binary
            this.cliPath = await this.findCliBinary();
            if (!this.cliPath) {
                this.log.warn('CLI binary not found');
                return false;
            }

            // Get version
            this.cliVersion = await this.getVersion();
            this.log.info(`CLI initialized: ${this.cliPath} (v${this.cliVersion})`);

            return true;
        } catch (error) {
            this.log.error('Failed to initialize CLI', error);
            return false;
        }
    }

    /**
     * Find the CLI binary.
     */
    private async findCliBinary(): Promise<string | null> {
        // Check configured path first
        const configPath = configManager.getCliPath();
        if (configPath && await existsAsync(configPath)) {
            return configPath;
        }

        // Check common locations
        const searchPaths = [
            // In project
            path.join(vscode.workspace.workspaceFolders?.[0]?.uri.fsPath ?? '', 'target', 'release', 'aeth'),
            path.join(vscode.workspace.workspaceFolders?.[0]?.uri.fsPath ?? '', 'target', 'debug', 'aeth'),
            // In user's cargo bin
            path.join(process.env.HOME ?? '', '.cargo', 'bin', 'aeth'),
            // In system PATH
            'aeth',
        ];

        for (const searchPath of searchPaths) {
            try {
                if (searchPath === 'aeth') {
                    // Check if in PATH
                    const { stdout } = await execAsync('which aeth 2>/dev/null || where aeth 2>nul');
                    if (stdout.trim()) {
                        return stdout.trim().split('\n')[0];
                    }
                } else if (await existsAsync(searchPath)) {
                    return searchPath;
                }
            } catch {
                // Continue searching
            }
        }

        return null;
    }

    /**
     * Get CLI version.
     */
    async getVersion(): Promise<string> {
        const result = await this.execute<{ version: string }>(['--version'], {
            timeout: 5000,
        });

        if (result.success && result.data) {
            return result.data.version;
        }

        // Parse from stdout
        const match = result.stdout.match(/aeth\s+(\d+\.\d+\.\d+)/);
        return match?.[1] ?? 'unknown';
    }

    /**
     * Check if CLI is available.
     */
    isAvailable(): boolean {
        return this.cliPath !== null;
    }

    /**
     * Get the CLI path.
     */
    getPath(): string | null {
        return this.cliPath;
    }

    /**
     * Get cached CLI version.
     */
    getCachedVersion(): string | null {
        return this.cliVersion;
    }

    // =========================================================================
    // Core Execution
    // =========================================================================

    /**
     * Execute a CLI command.
     */
    async execute<T>(
        args: string[],
        options: CliOptions = {},
        parser?: OutputParser<T>
    ): Promise<CliResult<T>> {
        if (!this.cliPath) {
            return this.errorResult('CLI not available', 'CLI_NOT_FOUND');
        }

        const startTime = Date.now();
        const timeout = options.timeout ?? configManager.getCliTimeout();
        const cwd = options.cwd ?? vscode.workspace.workspaceFolders?.[0]?.uri.fsPath ?? process.cwd();

        const context: ExecutionContext = {
            command: this.cliPath,
            args,
            cwd,
            timeout,
            startTime,
            cancellationToken: options.cancellation,
        };

        this.log.debug(`Executing: ${this.cliPath} ${args.join(' ')}`, { cwd, timeout });

        return new Promise((resolve) => {
            const commandId = this.generateCommandId();

            // Build environment
            const env = {
                ...process.env,
                ...options.env,
                AETHELRED_OUTPUT_FORMAT: 'json',
                AETHELRED_NO_COLOR: '1',
            };

            // Spawn process
            const child = cp.spawn(this.cliPath!, args, {
                cwd,
                env,
                shell: true,
            });

            this.runningCommands.set(commandId, child);

            let stdout = '';
            let stderr = '';

            // Collect stdout
            child.stdout?.on('data', (data: Buffer) => {
                stdout += data.toString();
            });

            // Collect stderr
            child.stderr?.on('data', (data: Buffer) => {
                stderr += data.toString();
            });

            // Handle timeout
            const timeoutHandle = setTimeout(() => {
                child.kill('SIGTERM');
                resolve(this.errorResult(
                    `Command timed out after ${timeout}ms`,
                    'TIMEOUT',
                    stdout,
                    stderr,
                    -1,
                    Date.now() - startTime
                ));
            }, timeout);

            // Handle cancellation
            if (options.cancellation) {
                options.cancellation.onCancellationRequested(() => {
                    child.kill('SIGTERM');
                    resolve(this.errorResult(
                        'Command cancelled',
                        'CANCELLED',
                        stdout,
                        stderr,
                        -1,
                        Date.now() - startTime
                    ));
                });
            }

            // Handle completion
            child.on('close', (code) => {
                clearTimeout(timeoutHandle);
                this.runningCommands.delete(commandId);

                const durationMs = Date.now() - startTime;

                this.log.debug(`Command completed`, {
                    exitCode: code,
                    durationMs,
                    stdoutLen: stdout.length,
                    stderrLen: stderr.length,
                });

                // Parse result
                let data: T | undefined;
                let error: CliError | undefined;

                if (code === 0) {
                    try {
                        if (parser) {
                            data = parser(stdout, stderr);
                        } else {
                            data = this.parseJson<T>(stdout);
                        }
                    } catch (parseError) {
                        error = {
                            code: 'PARSE_ERROR',
                            message: 'Failed to parse CLI output',
                            details: String(parseError),
                        };
                    }
                } else {
                    error = this.parseError(stderr || stdout, code ?? -1);
                }

                resolve({
                    success: code === 0 && !error,
                    data,
                    error,
                    stdout,
                    stderr,
                    exitCode: code ?? -1,
                    durationMs,
                });
            });

            // Handle spawn error
            child.on('error', (err) => {
                clearTimeout(timeoutHandle);
                this.runningCommands.delete(commandId);

                resolve(this.errorResult(
                    `Failed to spawn CLI: ${err.message}`,
                    'SPAWN_ERROR',
                    stdout,
                    stderr,
                    -1,
                    Date.now() - startTime
                ));
            });
        });
    }

    /**
     * Execute with caching.
     */
    async executeCached<T>(
        args: string[],
        options: CliOptions = {},
        cacheKey?: string
    ): Promise<CliResult<T>> {
        const key = cacheKey ?? this.generateCacheKey(args, options);
        const cached = this.getFromCache<CliResult<T>>(key);

        if (cached) {
            this.log.trace('Cache hit', { key });
            return cached;
        }

        const result = await this.execute<T>(args, options);

        if (result.success) {
            this.setCache(key, result);
        }

        return result;
    }

    // =========================================================================
    // Compliance Commands
    // =========================================================================

    /**
     * Run compliance check on a file.
     */
    async checkCompliance(
        filePath: string,
        jurisdiction: Jurisdiction,
        regulations?: Regulation[],
        options: CliOptions = {}
    ): Promise<CliResult<ComplianceReport>> {
        const args = [
            'compliance',
            'check',
            '--file', filePath,
            '--jurisdiction', jurisdiction,
            '--json',
        ];

        if (regulations?.length) {
            args.push('--regulations', regulations.join(','));
        }

        return this.execute<ComplianceReport>(args, options);
    }

    /**
     * Run compliance check on entire workspace.
     */
    async checkWorkspaceCompliance(
        jurisdiction: Jurisdiction,
        regulations?: Regulation[],
        options: CliOptions = {}
    ): Promise<CliResult<ComplianceReport>> {
        const args = [
            'compliance',
            'check',
            '--jurisdiction', jurisdiction,
            '--json',
        ];

        if (regulations?.length) {
            args.push('--regulations', regulations.join(','));
        }

        return this.execute<ComplianceReport>(args, options);
    }

    /**
     * Analyze compliance requirements.
     */
    async analyzeCompliance(
        filePath: string,
        options: CliOptions = {}
    ): Promise<CliResult<{ requirements: string[]; recommendations: string[] }>> {
        return this.execute(['compliance', 'analyze', '--file', filePath, '--json'], options);
    }

    // =========================================================================
    // Hardware Commands
    // =========================================================================

    /**
     * Detect available hardware.
     */
    async detectHardware(options: CliOptions = {}): Promise<CliResult<HardwareInfo[]>> {
        return this.executeCached(['hardware', 'detect', '--json'], options, 'hardware:detect');
    }

    /**
     * Estimate execution cost.
     */
    async estimateCost(
        modelPath: string,
        hardware?: HardwareType,
        options: CliOptions = {}
    ): Promise<CliResult<CostEstimate>> {
        const args = ['hardware', 'estimate', '--model', modelPath, '--json'];

        if (hardware && hardware !== 'auto') {
            args.push('--hardware', hardware);
        }

        return this.execute<CostEstimate>(args, options);
    }

    /**
     * Start TEE simulator.
     */
    async startSimulator(
        hardware: HardwareType = 'intel-sgx',
        options: CliOptions = {}
    ): Promise<CliResult<{ port: number; pid: number }>> {
        return this.execute(
            ['hardware', 'simulate', hardware, '--json'],
            { ...options, timeout: 60000 }
        );
    }

    /**
     * Stop TEE simulator.
     */
    async stopSimulator(options: CliOptions = {}): Promise<CliResult<void>> {
        return this.execute(['hardware', 'simulate', '--stop', '--json'], options);
    }

    /**
     * Get attestation report.
     */
    async getAttestation(options: CliOptions = {}): Promise<CliResult<{
        available: boolean;
        hardware: HardwareType;
        report?: string;
    }>> {
        return this.execute(['hardware', 'attest', '--json'], options);
    }

    // =========================================================================
    // Seal Commands
    // =========================================================================

    /**
     * Create a digital seal.
     */
    async createSeal(
        modelPath: string,
        inputPath: string,
        outputPath: string,
        jurisdiction: Jurisdiction,
        options: CliOptions = {}
    ): Promise<CliResult<DigitalSeal>> {
        return this.execute([
            'seal', 'create',
            '--model', modelPath,
            '--input', inputPath,
            '--output', outputPath,
            '--jurisdiction', jurisdiction,
            '--json',
        ], { ...options, timeout: 120000 });
    }

    /**
     * Verify a digital seal.
     */
    async verifySeal(
        sealId: string,
        options: CliOptions = {}
    ): Promise<CliResult<{ valid: boolean; seal: DigitalSeal }>> {
        return this.execute(['seal', 'verify', sealId, '--json'], options);
    }

    /**
     * List digital seals.
     */
    async listSeals(
        limit: number = 10,
        options: CliOptions = {}
    ): Promise<CliResult<DigitalSeal[]>> {
        return this.execute(['seal', 'list', '--limit', String(limit), '--json'], options);
    }

    // =========================================================================
    // Project Commands
    // =========================================================================

    /**
     * Initialize an Aethelred project.
     */
    async initProject(
        template: string = 'default',
        jurisdiction: Jurisdiction = 'Global',
        options: CliOptions = {}
    ): Promise<CliResult<{ configPath: string }>> {
        return this.execute([
            'init',
            '--template', template,
            '--jurisdiction', jurisdiction,
            '--json',
        ], options);
    }

    /**
     * Get project configuration.
     */
    async getProjectConfig(options: CliOptions = {}): Promise<CliResult<{
        name: string;
        version: string;
        jurisdiction: Jurisdiction;
        regulations: Regulation[];
    }>> {
        return this.executeCached(['config', 'show', '--json'], options, 'project:config');
    }

    // =========================================================================
    // Network Commands
    // =========================================================================

    /**
     * Get network status.
     */
    async getNetworkStatus(options: CliOptions = {}): Promise<CliResult<{
        connected: boolean;
        chain: string;
        blockHeight: number;
        validators: number;
    }>> {
        return this.execute(['network', 'status', '--json'], options);
    }

    // =========================================================================
    // Helper Methods
    // =========================================================================

    /**
     * Parse JSON from stdout.
     */
    private parseJson<T>(stdout: string): T {
        // Handle multiple JSON objects (one per line)
        const lines = stdout.trim().split('\n');
        for (const line of lines.reverse()) {
            try {
                return JSON.parse(line) as T;
            } catch {
                // Try next line
            }
        }
        throw new Error('No valid JSON found in output');
    }

    /**
     * Parse error from stderr.
     */
    private parseError(output: string, exitCode: number): CliError {
        // Try to parse structured error
        try {
            const json = JSON.parse(output);
            if (json.error) {
                return {
                    code: json.error.code ?? `EXIT_${exitCode}`,
                    message: json.error.message ?? output,
                    details: json.error.details,
                    suggestion: json.error.suggestion,
                };
            }
        } catch {
            // Not JSON
        }

        // Extract error message from output
        const errorMatch = output.match(/error(?:\[E\d+\])?:\s*(.+)/i);
        const message = errorMatch?.[1] ?? output.trim() || `Command failed with exit code ${exitCode}`;

        return {
            code: `EXIT_${exitCode}`,
            message,
        };
    }

    /**
     * Create an error result.
     */
    private errorResult<T>(
        message: string,
        code: string,
        stdout = '',
        stderr = '',
        exitCode = -1,
        durationMs = 0
    ): CliResult<T> {
        return {
            success: false,
            error: { code, message },
            stdout,
            stderr,
            exitCode,
            durationMs,
        };
    }

    /**
     * Generate a unique command ID.
     */
    private generateCommandId(): string {
        return `cmd_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    }

    /**
     * Generate a cache key.
     */
    private generateCacheKey(args: string[], options: CliOptions): string {
        const hash = JSON.stringify({ args, cwd: options.cwd });
        return `cli:${Buffer.from(hash).toString('base64').substr(0, 32)}`;
    }

    /**
     * Get from cache.
     */
    private getFromCache<T>(key: string): T | null {
        const entry = this.cache.get(key) as CacheEntry<T> | undefined;
        if (entry && Date.now() - entry.timestamp < this.cacheMaxAge) {
            return entry.result;
        }
        this.cache.delete(key);
        return null;
    }

    /**
     * Set cache entry.
     */
    private setCache<T>(key: string, result: T): void {
        this.cache.set(key, {
            result,
            timestamp: Date.now(),
            hash: key,
        });

        // Limit cache size
        if (this.cache.size > 100) {
            const oldest = this.cache.keys().next().value;
            if (oldest) {
                this.cache.delete(oldest);
            }
        }
    }

    /**
     * Clear cache.
     */
    clearCache(): void {
        this.cache.clear();
    }

    /**
     * Cancel all running commands.
     */
    cancelAll(): void {
        for (const [id, child] of this.runningCommands) {
            this.log.debug(`Cancelling command: ${id}`);
            child.kill('SIGTERM');
        }
        this.runningCommands.clear();
    }

    /**
     * Dispose resources.
     */
    dispose(): void {
        this.cancelAll();
        this.cache.clear();
        AethCli.instance = null;
    }
}

// Export singleton accessor
export const aethCli = AethCli.getInstance();
