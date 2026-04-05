#!/usr/bin/env node

import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

import chalk from "chalk";
import Table from "cli-table3";
import { Command } from "commander";
import ora from "ora";

import { AethelredClient } from "@aethelred/sdk";
import { verifySealOffline } from "@aethelred/sdk/devtools";

type OutputFormat = "text" | "json";

interface GlobalOptions {
  network?: string;
  rpcUrl?: string;
  output?: OutputFormat;
}

const DEFAULT_NETWORKS: Record<string, string> = {
  mainnet: "https://rpc.mainnet.aethelred.io",
  testnet: "https://rpc.testnet.aethelred.io",
  // Use IPv4 loopback to avoid "::1" resolution mismatches with local mock RPC binds.
  devnet: "http://127.0.0.1:26657",
  local: "http://127.0.0.1:26657",
};

const CONFIG_PATH = path.join(os.homedir(), ".aethelred", "aethel-cli.json");

interface CliConfig {
  network: string;
  rpcUrl?: string;
  headerPrefix?: string;
}

function ensureDir(filePath: string): void {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
}

function loadConfig(): CliConfig {
  if (!fs.existsSync(CONFIG_PATH)) {
    return { network: "testnet" };
  }
  return JSON.parse(fs.readFileSync(CONFIG_PATH, "utf8")) as CliConfig;
}

function saveConfig(config: CliConfig): void {
  ensureDir(CONFIG_PATH);
  fs.writeFileSync(CONFIG_PATH, `${JSON.stringify(config, null, 2)}\n`, "utf8");
}

function effectiveRpcUrl(globalOpts: GlobalOptions): string {
  const config = loadConfig();
  if (globalOpts.rpcUrl) return globalOpts.rpcUrl;
  if (config.rpcUrl) return config.rpcUrl;
  const network = (globalOpts.network ?? config.network ?? "testnet").toLowerCase();
  return DEFAULT_NETWORKS[network] ?? DEFAULT_NETWORKS.testnet;
}

function print(data: unknown, format: OutputFormat = "text"): void {
  if (format === "json") {
    console.log(JSON.stringify(data, null, 2));
    return;
  }
  if (typeof data === "string") {
    console.log(data);
    return;
  }
  console.log(data);
}

function resolveLocalTestnetComposePath(): string {
  if (process.env.AETHEL_LOCAL_TESTNET_COMPOSE) {
    return process.env.AETHEL_LOCAL_TESTNET_COMPOSE;
  }

  const candidates: string[] = [];
  let cursor = process.cwd();
  for (let i = 0; i < 6; i += 1) {
    candidates.push(path.join(cursor, "integrations", "deploy", "docker", "docker-compose.local-testnet.yml"));
    const next = path.dirname(cursor);
    if (next === cursor) break;
    cursor = next;
  }

  const cliDir = path.dirname(fileURLToPath(import.meta.url));
  candidates.push(path.resolve(cliDir, "../../../../integrations/deploy/docker/docker-compose.local-testnet.yml"));

  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) return candidate;
  }
  return candidates[0];
}

async function fetchJson(url: string): Promise<any> {
  const resp = await fetch(url);
  if (!resp.ok) {
    throw new Error(`HTTP ${resp.status} ${resp.statusText} for ${url}`);
  }
  return resp.json();
}

function parseKV(pair: string): [string, string] {
  const idx = pair.indexOf("=");
  if (idx <= 0) throw new Error(`Invalid key=value pair: ${pair}`);
  return [pair.slice(0, idx), pair.slice(idx + 1)];
}

async function getBalance(rpcUrl: string, address: string): Promise<any> {
  return await fetchJson(`${rpcUrl}/cosmos/bank/v1beta1/balances/${address}`);
}

function dockerCompose(args: string[]): void {
  const composeFile = resolveLocalTestnetComposePath();
  const candidates = [
    ["docker", "compose"],
    ["docker-compose"],
  ];
  for (const [bin, ...prefix] of candidates) {
    try {
      execFileSync(bin, [...prefix, "version"], { stdio: "ignore" });
      execFileSync(bin, [...prefix, "-f", composeFile, ...args], { stdio: "inherit" });
      return;
    } catch {
      continue;
    }
  }
  throw new Error("Docker Compose not available (tried docker compose and docker-compose)");
}

const program = new Command();

program
  .name("aethel")
  .description("Aethelred Developer CLI (network diagnostics, validators, seals, token ops, local testnet)")
  .version("2.0.0")
  .option("-n, --network <network>", "Network (mainnet, testnet, devnet, local)")
  .option("--rpc-url <url>", "Override RPC URL")
  .option("-o, --output <format>", "Output format (text|json)", "text");

program
  .command("config")
  .description("View or update CLI configuration")
  .option("--get <key>", "Get a config value")
  .option("--set <key=value...>", "Set one or more config values")
  .option("--list", "List configuration")
  .action((opts) => {
    const config = loadConfig();
    if (opts.set?.length) {
      for (const pair of opts.set as string[]) {
        const [k, v] = parseKV(pair);
        (config as any)[k] = v;
      }
      saveConfig(config);
      console.log(chalk.green(`Updated ${CONFIG_PATH}`));
    }
    if (opts.get) {
      console.log((config as any)[opts.get] ?? "");
      return;
    }
    if (opts.list || !opts.get) {
      console.log(JSON.stringify(config, null, 2));
    }
  });

program
  .command("status")
  .description("Get network status, node info, and RPC latency")
  .action(async (_, command) => {
    const globalOpts = command.parent?.opts() as GlobalOptions;
    const rpcUrl = effectiveRpcUrl(globalOpts);
    const spinner = ora(`Checking ${rpcUrl}`).start();
    try {
      const start = Date.now();
      const [health, nodeInfo, latestBlock] = await Promise.all([
        fetchJson(`${rpcUrl}/health`).catch(() => ({ status: "unavailable" })),
        fetchJson(`${rpcUrl}/cosmos/base/tendermint/v1beta1/node_info`),
        fetchJson(`${rpcUrl}/cosmos/base/tendermint/v1beta1/blocks/latest`).catch(() => null),
      ]);
      const latencyMs = Date.now() - start;
      spinner.succeed("Network status collected");

      const payload = {
        rpcUrl,
        latencyMs,
        health,
        nodeInfo: nodeInfo?.default_node_info ?? nodeInfo,
        latestBlock: latestBlock?.block?.header ?? latestBlock?.header ?? null,
      };

      if ((globalOpts.output ?? "text") === "json") {
        print(payload, "json");
        return;
      }

      console.log(chalk.cyan.bold("Aethelred Network Status"));
      console.log(`RPC URL: ${rpcUrl}`);
      console.log(`Latency: ${latencyMs} ms`);
      console.log(`Moniker: ${payload.nodeInfo?.moniker ?? "unknown"}`);
      console.log(`Chain ID: ${payload.nodeInfo?.network ?? payload.latestBlock?.chain_id ?? "unknown"}`);
      console.log(`Latest block: ${payload.latestBlock?.height ?? "unknown"}`);
      console.log(`Health: ${health?.result ? chalk.green("ok") : chalk.yellow("partial")}`);
    } catch (error) {
      spinner.fail("Status check failed");
      console.error(chalk.red((error as Error).message));
      process.exitCode = 1;
    }
  });

const diagnostics = program.command("diagnostics").description("Network and local environment diagnostics");

diagnostics
  .command("doctor")
  .description("Run local environment diagnostics (Docker, compose file, local endpoints)")
  .action(async (_, command) => {
    const globalOpts = command.parent?.parent?.opts() as GlobalOptions;
    const rpcUrl = effectiveRpcUrl(globalOpts);
    const skipDashboard = process.env.AETHELRED_SMOKE_SKIP_DASHBOARD === "1";
    const checks: Array<{ check: string; ok: boolean; detail: string }> = [];

    try {
      execFileSync("docker", ["info", "--format", "{{.ServerVersion}}"], { stdio: "pipe" });
      checks.push({ check: "docker-daemon", ok: true, detail: "Docker daemon reachable" });
    } catch (error) {
      checks.push({ check: "docker-daemon", ok: false, detail: `Docker unavailable: ${(error as Error).message}` });
    }

    checks.push({
      check: "local-testnet-compose",
      ok: fs.existsSync(resolveLocalTestnetComposePath()),
      detail: resolveLocalTestnetComposePath(),
    });

    try {
      const start = Date.now();
      await fetchJson(`${rpcUrl}/health`);
      checks.push({ check: "rpc-health", ok: true, detail: `${rpcUrl} (${Date.now() - start} ms)` });
    } catch (error) {
      checks.push({ check: "rpc-health", ok: false, detail: `${rpcUrl}: ${(error as Error).message}` });
    }

    const endpointChecks = [
      ["fastapi-verifier", "http://127.0.0.1:8000/health"],
      ["nextjs-verifier", "http://127.0.0.1:3000/api/health"],
      ...(skipDashboard ? [] : ([["developer-dashboard", "http://127.0.0.1:3101/devtools"]] as const)),
    ];

    for (const [name, url] of endpointChecks) {
      try {
        await fetch(url, { method: "GET" });
        checks.push({ check: name, ok: true, detail: url });
      } catch (error) {
        checks.push({ check: name, ok: false, detail: `${url}: ${(error as Error).message}` });
      }
    }

    if ((globalOpts.output ?? "text") === "json") {
      print({ checks }, "json");
      return;
    }

    for (const check of checks) {
      console.log(`${check.ok ? chalk.green("✓") : chalk.red("✗")} ${check.check}: ${check.detail}`);
    }
    const failed = checks.filter((c) => !c.ok).length;
    if (failed > 0) {
      console.log(chalk.yellow(`Doctor found ${failed} issue(s)`));
      process.exitCode = 2;
    }
  });

const validator = program.command("validator").description("Validator management and diagnostics");

validator
  .command("list")
  .description("List validators from the PoUW API")
  .option("--limit <n>", "Limit results", "20")
  .action(async (opts, command) => {
    const globalOpts = command.parent?.parent?.opts() as GlobalOptions;
    const client = new AethelredClient({ rpcUrl: effectiveRpcUrl(globalOpts) });
    const spinner = ora("Fetching validators").start();
    try {
      const validators = await client.validators.list({ limit: Number(opts.limit) || 20 });
      spinner.succeed(`Fetched ${validators.length} validator(s)`);
      if ((globalOpts.output ?? "text") === "json") {
        print(validators, "json");
        return;
      }
      const table = new Table({ head: ["Address", "Uptime", "Jobs", "Latency(ms)", "Reputation"] });
      for (const v of validators) {
        table.push([
          `${v.address.slice(0, 10)}...${v.address.slice(-6)}`,
          `${v.uptimePercentage.toFixed(2)}%`,
          v.jobsCompleted,
          v.averageLatencyMs,
          v.reputationScore,
        ]);
      }
      console.log(table.toString());
    } catch (error) {
      spinner.fail("Failed to fetch validators");
      console.error(chalk.red((error as Error).message));
      process.exitCode = 1;
    }
  });

validator
  .command("stats <address>")
  .description("Fetch a single validator's stats")
  .action(async (address, command) => {
    const globalOpts = command.parent?.parent?.opts() as GlobalOptions;
    const client = new AethelredClient({ rpcUrl: effectiveRpcUrl(globalOpts) });
    try {
      const stats = await client.validators.getStats(address);
      print(stats, (globalOpts.output ?? "text") as OutputFormat);
    } catch (error) {
      console.error(chalk.red((error as Error).message));
      process.exitCode = 1;
    }
  });

const seal = program.command("seal").description("Seal verification and export diagnostics");

seal
  .command("verify <seal_id>")
  .description("Fetch a seal from the network and verify it offline")
  .option("--min-consensus-bps <bps>", "Consensus threshold bps", "6700")
  .option("--max-attestation-age-ms <ms>", "TEE freshness window", "3600000")
  .option("--require-tee-nonce", "Require nonce in TEE attestation")
  .action(async (sealId, opts, command) => {
    const globalOpts = command.parent?.parent?.opts() as GlobalOptions;
    const client = new AethelredClient({ rpcUrl: effectiveRpcUrl(globalOpts) });
    const spinner = ora(`Fetching seal ${sealId}`).start();
    try {
      const sealPayload = (await client.seals.get(sealId)) as unknown as Record<string, unknown>;
      spinner.text = "Running offline verification";
      const result = verifySealOffline(sealPayload, {
        minConsensusBps: Number(opts.minConsensusBps),
        maxAttestationAgeMs: Number(opts.maxAttestationAgeMs),
        requireTeeNonce: Boolean(opts.requireTeeNonce),
      });
      spinner.succeed(result.valid ? "Seal verified" : "Seal verification failed");
      print(result, (globalOpts.output ?? "text") as OutputFormat);
      if (!result.valid) process.exitCode = 2;
    } catch (error) {
      spinner.fail("Seal verification failed");
      console.error(chalk.red((error as Error).message));
      process.exitCode = 1;
    }
  });

seal
  .command("verify-file <file>")
  .description("Verify a local seal export offline")
  .option("--min-consensus-bps <bps>", "Consensus threshold bps", "6700")
  .option("--max-attestation-age-ms <ms>", "TEE freshness window", "3600000")
  .option("--require-tee-nonce", "Require nonce in TEE attestation")
  .action((file, opts, command) => {
    const globalOpts = command.parent?.parent?.opts() as GlobalOptions;
    try {
      const payload = JSON.parse(fs.readFileSync(file, "utf8")) as Record<string, unknown>;
      const result = verifySealOffline(payload, {
        minConsensusBps: Number(opts.minConsensusBps),
        maxAttestationAgeMs: Number(opts.maxAttestationAgeMs),
        requireTeeNonce: Boolean(opts.requireTeeNonce),
      });
      print(result, (globalOpts.output ?? "text") as OutputFormat);
      if (!result.valid) process.exitCode = 2;
    } catch (error) {
      console.error(chalk.red((error as Error).message));
      process.exitCode = 1;
    }
  });

const wallet = program.command("wallet").description("Token operations and transaction manifests");

wallet
  .command("balance <address>")
  .description("Query token balances from Cosmos bank module")
  .action(async (address, command) => {
    const globalOpts = command.parent?.parent?.opts() as GlobalOptions;
    try {
      const balances = await getBalance(effectiveRpcUrl(globalOpts), address);
      print(balances, (globalOpts.output ?? "text") as OutputFormat);
    } catch (error) {
      console.error(chalk.red((error as Error).message));
      process.exitCode = 1;
    }
  });

wallet
  .command("send")
  .description("Create an unsigned token transfer manifest (for offline signing)")
  .requiredOption("--from <address>", "Sender address")
  .requiredOption("--to <address>", "Recipient address")
  .requiredOption("--amount <amount>", "Amount (e.g., 1000000uaethel)")
  .option("--memo <memo>", "Transaction memo")
  .option("--out <file>", "Write manifest to file")
  .action((opts, command) => {
    const globalOpts = command.parent?.parent?.opts() as GlobalOptions;
    const manifest = {
      type: "cosmos.bank.v1beta1.MsgSend",
      chainContext: {
        rpcUrl: effectiveRpcUrl(globalOpts),
        network: globalOpts.network ?? loadConfig().network,
      },
      message: {
        fromAddress: opts.from,
        toAddress: opts.to,
        amount: [
          {
            denom: opts.amount.replace(/^[0-9]+/, "").trim() || "uaethel",
            amount: opts.amount.match(/^[0-9]+/)?.[0] ?? opts.amount,
          },
        ],
      },
      memo: opts.memo ?? "",
      generatedAt: new Date().toISOString(),
      signing: {
        mode: "offline",
        note: "Sign with your preferred wallet/HSM and submit via tx broadcast.",
      },
    };
    if (opts.out) {
      ensureDir(opts.out);
      fs.writeFileSync(opts.out, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
      console.log(chalk.green(`Wrote unsigned tx manifest to ${opts.out}`));
    } else {
      print(manifest, (globalOpts.output ?? "text") as OutputFormat);
    }
  });

const local = program.command("local").description("Manage the Docker-based local Aethelred developer testnet");

local
  .command("up")
  .description("Start the local developer testnet stack")
  .option("--build", "Build images before starting")
  .option("--profile <name>", "Compose profile (mock|real-node)", "mock")
  .action((opts) => {
    const composeFile = resolveLocalTestnetComposePath();
    if (!fs.existsSync(composeFile)) {
      console.error(chalk.red(`Compose file not found: ${composeFile}`));
      process.exit(1);
    }
    const profileArgs = opts.profile ? ["--profile", String(opts.profile)] : [];
    if (opts.build) {
      dockerCompose([...profileArgs, "build"]);
    }
    dockerCompose([...profileArgs, "up", "-d"]);
  });

local
  .command("down")
  .description("Stop the local developer testnet stack")
  .option("-v, --volumes", "Remove volumes")
  .option("--profile <name>", "Compose profile (mock|real-node)", "mock")
  .action((opts) => {
    const args = opts.profile ? ["--profile", String(opts.profile), "down"] : ["down"];
    if (opts.volumes) args.push("-v");
    dockerCompose(args);
  });

local
  .command("status")
  .description("Show local developer testnet service status")
  .option("--profile <name>", "Compose profile (mock|real-node)", "mock")
  .action((opts) => {
    const args = opts.profile ? ["--profile", String(opts.profile), "ps"] : ["ps"];
    dockerCompose(args);
  });

local
  .command("logs")
  .description("Tail local testnet logs")
  .option("--service <name>", "Service name")
  .option("--profile <name>", "Compose profile (mock|real-node)", "mock")
  .action((opts) => {
    const args = opts.profile ? ["--profile", String(opts.profile), "logs", "-f"] : ["logs", "-f"];
    if (opts.service) args.push(opts.service);
    dockerCompose(args);
  });

program
  .command("query <endpoint>")
  .description("Run a raw HTTP GET query against the configured RPC/API base URL")
  .option("--params <json>", "JSON params object")
  .action(async (endpoint, opts, command) => {
    const globalOpts = command.parent?.opts() as GlobalOptions;
    try {
      const rpcUrl = effectiveRpcUrl(globalOpts);
      const url = new URL(endpoint.replace(/^\//, ""), `${rpcUrl}/`);
      if (opts.params) {
        const params = JSON.parse(opts.params) as Record<string, string>;
        for (const [k, v] of Object.entries(params)) url.searchParams.set(k, String(v));
      }
      const data = await fetchJson(url.toString());
      print(data, (globalOpts.output ?? "text") as OutputFormat);
    } catch (error) {
      console.error(chalk.red((error as Error).message));
      process.exitCode = 1;
    }
  });

program.parseAsync().catch((error) => {
  console.error(chalk.red((error as Error).message));
  process.exit(1);
});
