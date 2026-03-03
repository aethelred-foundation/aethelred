#!/usr/bin/env node

import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import chalk from "chalk";
import { Command } from "commander";
import ora from "ora";

import { AethelredClient } from "@aethelred/sdk";
import { verifySealOffline, type SealVerificationOptions } from "@aethelred/sdk/devtools";

type JsonValue = null | boolean | number | string | JsonValue[] | { [k: string]: JsonValue };

interface CliVerifyOptions {
  json?: boolean;
  strict?: boolean;
  minConsensusBps?: string;
  maxAttestationAgeMs?: string;
  requireTeeNonce?: boolean;
  trustedEnclave?: string[];
  trustedPcr0?: string[];
  rpcUrl?: string;
  network?: string;
}

const NETWORK_RPC: Record<string, string> = {
  mainnet: "https://rpc.mainnet.aethelred.org",
  testnet: "https://rpc.testnet.aethelred.org",
  devnet: "http://localhost:26657",
  local: "http://localhost:26657",
};

function readJsonFile(filePath: string): Record<string, unknown> {
  const raw = fs.readFileSync(filePath, "utf8");
  return JSON.parse(raw) as Record<string, unknown>;
}

function resolveRpcUrl(opts: { rpcUrl?: string; network?: string }): string {
  if (opts.rpcUrl) return opts.rpcUrl;
  const network = (opts.network ?? "testnet").toLowerCase();
  return NETWORK_RPC[network] ?? NETWORK_RPC.testnet;
}

function toVerificationOptions(opts: CliVerifyOptions): SealVerificationOptions {
  const minConsensusBps = opts.minConsensusBps ? Number(opts.minConsensusBps) : undefined;
  const maxAttestationAgeMs = opts.maxAttestationAgeMs ? Number(opts.maxAttestationAgeMs) : undefined;

  return {
    minConsensusBps: Number.isFinite(minConsensusBps) ? minConsensusBps : undefined,
    maxAttestationAgeMs: Number.isFinite(maxAttestationAgeMs) ? maxAttestationAgeMs : undefined,
    requireTeeNonce: Boolean(opts.requireTeeNonce),
    trustedEnclaveHashes: opts.trustedEnclave,
    trustedPcr0Values: opts.trustedPcr0,
  };
}

function printResult(result: ReturnType<typeof verifySealOffline>, asJson: boolean): void {
  if (asJson) {
    console.log(
      JSON.stringify(
        {
          valid: result.valid,
          score: result.score,
          fingerprintSha256: result.fingerprintSha256,
          errors: result.errors,
          warnings: result.warnings,
          metadata: result.metadata,
          checks: result.checks,
        },
        null,
        2,
      ),
    );
    return;
  }

  const title = result.valid
    ? chalk.green.bold("SEAL VERIFIED")
    : chalk.red.bold("SEAL VERIFICATION FAILED");
  console.log(title, chalk.gray(`score=${result.score}/100`));
  console.log(chalk.cyan("Fingerprint:"), result.fingerprintSha256);
  console.log(
    chalk.cyan("Consensus:"),
    result.metadata.consensusBps !== undefined
      ? `${(result.metadata.consensusBps / 100).toFixed(2)}%`
      : "unknown",
  );
  console.log(chalk.cyan("Validator attestations:"), result.metadata.validatorCount);
  console.log();

  for (const check of result.checks) {
    const symbol = check.ok ? chalk.green("✓") : check.severity === "error" ? chalk.red("✗") : chalk.yellow("!");
    const labelColor =
      check.severity === "error" ? chalk.red : check.severity === "warning" ? chalk.yellow : chalk.gray;
    console.log(`${symbol} ${labelColor(check.id)} ${check.message}`);
  }

  if (result.errors.length > 0) {
    console.log();
    console.log(chalk.red.bold("Errors"));
    for (const error of result.errors) console.log(chalk.red(`- ${error}`));
  }
  if (result.warnings.length > 0) {
    console.log();
    console.log(chalk.yellow.bold("Warnings"));
    for (const warning of result.warnings) console.log(chalk.yellow(`- ${warning}`));
  }
}

function exitForResult(result: ReturnType<typeof verifySealOffline>, strict: boolean): never | void {
  if (!result.valid || (strict && result.warnings.length > 0)) {
    process.exitCode = 2;
  }
}

async function fetchSealFromNetwork(sealId: string, opts: { rpcUrl?: string; network?: string }): Promise<Record<string, unknown>> {
  const rpcUrl = resolveRpcUrl(opts);
  const client = new AethelredClient({ rpcUrl });
  const seal = await client.seals.get(sealId);
  return seal as unknown as Record<string, unknown>;
}

function writeAuditReport(
  outputPath: string,
  sealSource: string,
  result: ReturnType<typeof verifySealOffline>,
): void {
  const lines = [
    "# Aethelred Seal Audit Report",
    "",
    `- Source: \`${sealSource}\``,
    `- Valid: **${result.valid ? "YES" : "NO"}**`,
    `- Score: **${result.score}/100**`,
    `- Fingerprint (SHA-256): \`${result.fingerprintSha256}\``,
    `- Validator attestations: **${result.metadata.validatorCount}**`,
    `- Consensus (bps): **${result.metadata.consensusBps ?? "unknown"}**`,
    "",
    "## Checks",
    "",
    ...result.checks.map((c) => `- [${c.ok ? "x" : " "}] \`${c.id}\` (${c.severity}) - ${c.message}`),
    "",
  ];
  fs.mkdirSync(path.dirname(outputPath), { recursive: true });
  fs.writeFileSync(outputPath, lines.join("\n"), "utf8");
}

async function verifySingleSeal(
  seal: Record<string, unknown>,
  opts: CliVerifyOptions,
): Promise<ReturnType<typeof verifySealOffline>> {
  const spinner = ora("Verifying seal offline...").start();
  try {
    const result = verifySealOffline(seal, toVerificationOptions(opts));
    spinner.succeed(result.valid ? "Seal verification completed" : "Seal verification completed with failures");
    return result;
  } catch (error) {
    spinner.fail("Seal verification failed");
    throw error;
  }
}

const program = new Command();

program.name("seal-verifier").description("Aethelred offline and network-backed Digital Seal verifier").version("2.0.0");

program
  .command("verify <seal_id>")
  .description("Fetch a seal from the network and verify it offline")
  .option("-n, --network <network>", "Network (mainnet, testnet, devnet, local)", "testnet")
  .option("--rpc-url <url>", "Override RPC URL")
  .option("--json", "Output JSON report")
  .option("--strict", "Fail on warnings")
  .option("--min-consensus-bps <bps>", "Consensus threshold in basis points", "6700")
  .option("--max-attestation-age-ms <ms>", "Maximum TEE attestation age in milliseconds", "3600000")
  .option("--require-tee-nonce", "Require nonce in TEE attestation")
  .option("--trusted-enclave <hash...>", "Trusted enclave hash allowlist")
  .option("--trusted-pcr0 <hash...>", "Trusted PCR0 hash allowlist")
  .action(async (sealId: string, opts: CliVerifyOptions) => {
    const spinner = ora(`Fetching seal ${sealId} from ${resolveRpcUrl(opts)}`).start();
    try {
      const seal = await fetchSealFromNetwork(sealId, opts);
      spinner.succeed(`Fetched seal ${sealId}`);
      const result = await verifySingleSeal(seal, opts);
      printResult(result, Boolean(opts.json));
      exitForResult(result, Boolean(opts.strict));
    } catch (error) {
      spinner.fail("Failed to fetch seal");
      console.error(chalk.red((error as Error).message));
      process.exitCode = 1;
    }
  });

program
  .command("verify-file <file>")
  .description("Verify a seal JSON export offline")
  .option("--json", "Output JSON report")
  .option("--strict", "Fail on warnings")
  .option("--min-consensus-bps <bps>", "Consensus threshold in basis points", "6700")
  .option("--max-attestation-age-ms <ms>", "Maximum TEE attestation age in milliseconds", "3600000")
  .option("--require-tee-nonce", "Require nonce in TEE attestation")
  .option("--trusted-enclave <hash...>", "Trusted enclave hash allowlist")
  .option("--trusted-pcr0 <hash...>", "Trusted PCR0 hash allowlist")
  .action(async (file: string, opts: CliVerifyOptions) => {
    try {
      const seal = readJsonFile(file);
      const result = await verifySingleSeal(seal, opts);
      printResult(result, Boolean(opts.json));
      exitForResult(result, Boolean(opts.strict));
    } catch (error) {
      console.error(chalk.red(`verify-file failed: ${(error as Error).message}`));
      process.exitCode = 1;
    }
  });

program
  .command("verify-stdin")
  .description("Read a seal JSON payload from stdin and verify it offline")
  .option("--json", "Output JSON report")
  .option("--strict", "Fail on warnings")
  .option("--min-consensus-bps <bps>", "Consensus threshold in basis points", "6700")
  .option("--max-attestation-age-ms <ms>", "Maximum TEE attestation age in milliseconds", "3600000")
  .option("--require-tee-nonce", "Require nonce in TEE attestation")
  .option("--trusted-enclave <hash...>", "Trusted enclave hash allowlist")
  .option("--trusted-pcr0 <hash...>", "Trusted PCR0 hash allowlist")
  .action(async (opts: CliVerifyOptions) => {
    try {
      const raw = fs.readFileSync(0, "utf8");
      const seal = JSON.parse(raw) as Record<string, unknown>;
      const result = await verifySingleSeal(seal, opts);
      printResult(result, Boolean(opts.json));
      exitForResult(result, Boolean(opts.strict));
    } catch (error) {
      console.error(chalk.red(`verify-stdin failed: ${(error as Error).message}`));
      process.exitCode = 1;
    }
  });

program
  .command("batch-verify <file>")
  .description("Verify a list of seals from a JSON array or NDJSON file")
  .option("--json", "Output JSON summary")
  .option("--strict", "Fail if any warnings occur")
  .option("--parallel <n>", "Reserved for future parallel workers", "1")
  .option("--min-consensus-bps <bps>", "Consensus threshold in basis points", "6700")
  .option("--max-attestation-age-ms <ms>", "Maximum TEE attestation age in milliseconds", "3600000")
  .option("--require-tee-nonce", "Require nonce in TEE attestation")
  .action(async (file: string, opts: CliVerifyOptions) => {
    try {
      const raw = fs.readFileSync(file, "utf8");
      const payloads = raw.trim().startsWith("[")
        ? (JSON.parse(raw) as Record<string, unknown>[])
        : raw
            .split(/\r?\n/)
            .map((line) => line.trim())
            .filter(Boolean)
            .map((line) => JSON.parse(line) as Record<string, unknown>);

      const results = payloads.map((payload) => verifySealOffline(payload, toVerificationOptions(opts)));
      const summary = {
        total: results.length,
        valid: results.filter((r) => r.valid).length,
        invalid: results.filter((r) => !r.valid).length,
        withWarnings: results.filter((r) => r.warnings.length > 0).length,
        averageScore:
          results.length > 0
            ? Number((results.reduce((sum, r) => sum + r.score, 0) / results.length).toFixed(2))
            : 0,
      };

      if (opts.json) {
        console.log(JSON.stringify({ summary, results }, null, 2));
      } else {
        console.log(chalk.bold("Batch Verification Summary"));
        console.log(`Total: ${summary.total}`);
        console.log(chalk.green(`Valid: ${summary.valid}`));
        console.log(chalk.red(`Invalid: ${summary.invalid}`));
        console.log(chalk.yellow(`With warnings: ${summary.withWarnings}`));
        console.log(`Average score: ${summary.averageScore}`);
      }

      if (summary.invalid > 0 || (opts.strict && summary.withWarnings > 0)) {
        process.exitCode = 2;
      }
    } catch (error) {
      console.error(chalk.red(`batch-verify failed: ${(error as Error).message}`));
      process.exitCode = 1;
    }
  });

program
  .command("check-expiry <file>")
  .description("Check expiration status from a local seal export")
  .option("--json", "Output JSON")
  .action((file: string, opts: { json?: boolean }) => {
    try {
      const seal = readJsonFile(file);
      const expiresAtRaw = (seal.expiresAt ?? (seal as any)?.seal?.expiresAt) as string | undefined;
      if (!expiresAtRaw) {
        throw new Error("Seal does not contain expiresAt");
      }
      const expiresAt = new Date(expiresAtRaw);
      if (Number.isNaN(expiresAt.getTime())) {
        throw new Error("expiresAt is invalid");
      }
      const now = new Date();
      const expired = expiresAt.getTime() <= now.getTime();
      const result = {
        expired,
        expiresAt: expiresAt.toISOString(),
        now: now.toISOString(),
        secondsRemaining: Math.max(0, Math.floor((expiresAt.getTime() - now.getTime()) / 1000)),
      };
      if (opts.json) {
        console.log(JSON.stringify(result, null, 2));
      } else {
        console.log(expired ? chalk.red.bold("EXPIRED") : chalk.green.bold("ACTIVE"));
        console.log(`expiresAt: ${result.expiresAt}`);
        console.log(`secondsRemaining: ${result.secondsRemaining}`);
      }
      if (expired) process.exitCode = 2;
    } catch (error) {
      console.error(chalk.red(`check-expiry failed: ${(error as Error).message}`));
      process.exitCode = 1;
    }
  });

program
  .command("audit <target>")
  .description("Generate a detailed audit report from a local file or network seal ID")
  .option("-n, --network <network>", "Network (mainnet, testnet, devnet, local)", "testnet")
  .option("--rpc-url <url>", "Override RPC URL")
  .option("-o, --output <file>", "Output report path")
  .option("--json", "Print JSON report to stdout instead of markdown file")
  .option("--min-consensus-bps <bps>", "Consensus threshold in basis points", "6700")
  .option("--max-attestation-age-ms <ms>", "Maximum TEE attestation age in milliseconds", "3600000")
  .option("--require-tee-nonce", "Require nonce in TEE attestation")
  .action(async (target: string, opts: CliVerifyOptions & { output?: string; json?: boolean }) => {
    try {
      const isFile = fs.existsSync(target);
      const seal = isFile ? readJsonFile(target) : await fetchSealFromNetwork(target, opts);
      const result = await verifySingleSeal(seal, opts);
      if (opts.json) {
        printResult(result, true);
      } else {
        const defaultPath = path.join(os.homedir(), ".aethelred", "seal-audits", `${path.basename(target)}.md`);
        const outputPath = opts.output ?? defaultPath;
        writeAuditReport(outputPath, target, result);
        console.log(chalk.green(`Audit report written to ${outputPath}`));
      }
      exitForResult(result, false);
    } catch (error) {
      console.error(chalk.red(`audit failed: ${(error as Error).message}`));
      process.exitCode = 1;
    }
  });

program.parseAsync().catch((error) => {
  console.error(chalk.red((error as Error).message));
  process.exit(1);
});
