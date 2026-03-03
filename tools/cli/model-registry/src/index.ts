#!/usr/bin/env node

import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import chalk from "chalk";
import Table from "cli-table3";
import { Command } from "commander";
import ora from "ora";

interface RegistryEntry {
  modelHash: string;
  name: string;
  version: string;
  architecture?: string;
  category?: string;
  owner?: string;
  storageUri?: string;
  filePath?: string;
  fileSizeBytes?: number;
  inputSchema?: string;
  outputSchema?: string;
  tags?: string[];
  metadata?: Record<string, string>;
  createdAt: string;
  updatedAt: string;
}

interface RegistryDb {
  version: number;
  models: RegistryEntry[];
}

const DEFAULT_DB_PATH = path.join(os.homedir(), ".aethelred", "model-registry", "registry.json");

function ensureDir(filePath: string): void {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
}

function loadDb(filePath: string): RegistryDb {
  if (!fs.existsSync(filePath)) {
    return { version: 1, models: [] };
  }
  const raw = fs.readFileSync(filePath, "utf8");
  const parsed = JSON.parse(raw) as Partial<RegistryDb>;
  return {
    version: parsed.version ?? 1,
    models: Array.isArray(parsed.models) ? parsed.models : [],
  };
}

function saveDb(filePath: string, db: RegistryDb): void {
  ensureDir(filePath);
  fs.writeFileSync(filePath, `${JSON.stringify(db, null, 2)}\n`, "utf8");
}

function sha256File(filePath: string): Promise<string> {
  const hash = crypto.createHash("sha256");
  const stream = fs.createReadStream(filePath);
  return new Promise<string>((resolve, reject) => {
    stream.on("data", (chunk) => hash.update(chunk));
    stream.on("error", reject);
    stream.on("end", () => resolve(`0x${hash.digest("hex")}`));
  });
}

function parseKeyValues(values: string[] | undefined): Record<string, string> | undefined {
  if (!values?.length) return undefined;
  const out: Record<string, string> = {};
  for (const pair of values) {
    const idx = pair.indexOf("=");
    if (idx <= 0) {
      throw new Error(`Invalid metadata key=value pair: ${pair}`);
    }
    out[pair.slice(0, idx)] = pair.slice(idx + 1);
  }
  return out;
}

function printEntry(entry: RegistryEntry, json: boolean): void {
  if (json) {
    console.log(JSON.stringify(entry, null, 2));
    return;
  }
  console.log(chalk.bold(entry.name), chalk.gray(entry.version));
  console.log(`hash: ${entry.modelHash}`);
  console.log(`architecture: ${entry.architecture ?? "n/a"}`);
  console.log(`category: ${entry.category ?? "general"}`);
  console.log(`storageUri: ${entry.storageUri ?? "n/a"}`);
  console.log(`filePath: ${entry.filePath ?? "n/a"}`);
  console.log(`createdAt: ${entry.createdAt}`);
  console.log(`updatedAt: ${entry.updatedAt}`);
  if (entry.tags?.length) {
    console.log(`tags: ${entry.tags.join(", ")}`);
  }
  if (entry.metadata && Object.keys(entry.metadata).length > 0) {
    console.log("metadata:");
    for (const [k, v] of Object.entries(entry.metadata)) console.log(`  ${k}=${v}`);
  }
}

function resolveDbPath(dbPath?: string): string {
  return dbPath ?? DEFAULT_DB_PATH;
}

function upsertModel(db: RegistryDb, entry: RegistryEntry): { db: RegistryDb; created: boolean } {
  const idx = db.models.findIndex((m) => m.modelHash === entry.modelHash);
  if (idx === -1) {
    db.models.push(entry);
    return { db, created: true };
  }
  db.models[idx] = { ...db.models[idx], ...entry, createdAt: db.models[idx].createdAt, updatedAt: entry.updatedAt };
  return { db, created: false };
}

const program = new Command();

program.name("model-registry").description("Aethelred Model Registry CLI (local-first developer workflow)").version("2.0.0");

program
  .command("register")
  .description("Register a model in the local developer registry")
  .requiredOption("-n, --name <name>", "Model name")
  .requiredOption("-f, --file <path>", "Model file path")
  .option("-a, --architecture <arch>", "Model architecture")
  .option("-v, --version <version>", "Model version", "1.0.0")
  .option("-c, --category <category>", "Model category", "general")
  .option("--owner <address>", "Owner address")
  .option("--input-schema <schema>", "Input schema JSON string")
  .option("--output-schema <schema>", "Output schema JSON string")
  .option("--storage <uri>", "Storage URI (IPFS/S3/etc)")
  .option("--tag <tag...>", "Tags")
  .option("--meta <key=value...>", "Metadata key=value pairs")
  .option("--db <path>", "Registry database file path")
  .option("--json", "Output JSON")
  .action(async (options) => {
    const dbPath = resolveDbPath(options.db);
    const spinner = ora(`Hashing model file ${options.file}`).start();
    try {
      const stats = fs.statSync(options.file);
      const modelHash = await sha256File(options.file);
      spinner.text = "Updating local registry";
      const now = new Date().toISOString();
      const entry: RegistryEntry = {
        modelHash,
        name: options.name,
        version: options.version,
        architecture: options.architecture,
        category: options.category,
        owner: options.owner,
        storageUri: options.storage,
        filePath: path.resolve(options.file),
        fileSizeBytes: stats.size,
        inputSchema: options.inputSchema,
        outputSchema: options.outputSchema,
        tags: options.tag,
        metadata: parseKeyValues(options.meta),
        createdAt: now,
        updatedAt: now,
      };
      const db = loadDb(dbPath);
      const { created } = upsertModel(db, entry);
      saveDb(dbPath, db);
      spinner.succeed(created ? "Model registered" : "Model updated (hash already existed)");
      printEntry(entry, Boolean(options.json));
    } catch (error) {
      spinner.fail("Registration failed");
      console.error(chalk.red((error as Error).message));
      process.exitCode = 1;
    }
  });

program
  .command("update <model_hash>")
  .description("Update metadata for an existing local registry entry")
  .option("-n, --name <name>", "Model name")
  .option("-a, --architecture <arch>", "Model architecture")
  .option("-v, --version <version>", "Model version")
  .option("-c, --category <category>", "Model category")
  .option("--owner <address>", "Owner address")
  .option("--storage <uri>", "Storage URI")
  .option("--tag <tag...>", "Replace tags")
  .option("--meta <key=value...>", "Merge metadata key=value pairs")
  .option("--db <path>", "Registry database file path")
  .option("--json", "Output JSON")
  .action((modelHash: string, options) => {
    try {
      const dbPath = resolveDbPath(options.db);
      const db = loadDb(dbPath);
      const idx = db.models.findIndex((m) => m.modelHash === modelHash);
      if (idx === -1) throw new Error(`Model not found: ${modelHash}`);
      const existing = db.models[idx];
      const metadata = options.meta ? { ...(existing.metadata ?? {}), ...parseKeyValues(options.meta) } : existing.metadata;
      const updated: RegistryEntry = {
        ...existing,
        name: options.name ?? existing.name,
        version: options.version ?? existing.version,
        architecture: options.architecture ?? existing.architecture,
        category: options.category ?? existing.category,
        owner: options.owner ?? existing.owner,
        storageUri: options.storage ?? existing.storageUri,
        tags: options.tag ?? existing.tags,
        metadata,
        updatedAt: new Date().toISOString(),
      };
      db.models[idx] = updated;
      saveDb(dbPath, db);
      printEntry(updated, Boolean(options.json));
    } catch (error) {
      console.error(chalk.red((error as Error).message));
      process.exitCode = 1;
    }
  });

program
  .command("get <model_hash>")
  .description("Get model details from the local registry")
  .option("--db <path>", "Registry database file path")
  .option("--json", "Output JSON")
  .action((modelHash: string, options) => {
    try {
      const db = loadDb(resolveDbPath(options.db));
      const entry = db.models.find((m) => m.modelHash === modelHash);
      if (!entry) throw new Error(`Model not found: ${modelHash}`);
      printEntry(entry, Boolean(options.json));
    } catch (error) {
      console.error(chalk.red((error as Error).message));
      process.exitCode = 1;
    }
  });

program
  .command("list")
  .description("List models in the local registry")
  .option("-o, --owner <address>", "Filter by owner")
  .option("-c, --category <category>", "Filter by category")
  .option("-l, --limit <n>", "Limit results", "20")
  .option("--db <path>", "Registry database file path")
  .option("--json", "Output JSON")
  .action((options) => {
    try {
      const db = loadDb(resolveDbPath(options.db));
      let models = db.models.slice();
      if (options.owner) models = models.filter((m) => m.owner === options.owner);
      if (options.category) models = models.filter((m) => (m.category ?? "general") === options.category);
      models.sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));
      models = models.slice(0, Math.max(1, Number(options.limit) || 20));

      if (options.json) {
        console.log(JSON.stringify(models, null, 2));
        return;
      }

      const table = new Table({
        head: ["Hash", "Name", "Version", "Category", "Updated"],
        style: { head: ["cyan"] },
      });
      for (const model of models) {
        table.push([
          `${model.modelHash.slice(0, 10)}...${model.modelHash.slice(-6)}`,
          model.name,
          model.version,
          model.category ?? "general",
          model.updatedAt,
        ]);
      }
      console.log(table.toString());
      console.log(chalk.gray(`Registry DB: ${resolveDbPath(options.db)}`));
    } catch (error) {
      console.error(chalk.red((error as Error).message));
      process.exitCode = 1;
    }
  });

program
  .command("verify <model_hash>")
  .description("Verify local model metadata against a local file")
  .requiredOption("-f, --file <path>", "Model file path to compare")
  .option("--db <path>", "Registry database file path")
  .option("--json", "Output JSON")
  .action(async (modelHash: string, options) => {
    const spinner = ora("Verifying model integrity").start();
    try {
      const db = loadDb(resolveDbPath(options.db));
      const entry = db.models.find((m) => m.modelHash === modelHash);
      if (!entry) throw new Error(`Model not found: ${modelHash}`);
      const computed = await sha256File(options.file);
      const size = fs.statSync(options.file).size;
      const result = {
        valid: computed === entry.modelHash,
        expectedHash: entry.modelHash,
        actualHash: computed,
        expectedSizeBytes: entry.fileSizeBytes,
        actualSizeBytes: size,
      };
      spinner.succeed(result.valid ? "Model verified" : "Model verification mismatch");
      if (options.json) {
        console.log(JSON.stringify(result, null, 2));
      } else {
        console.log(result.valid ? chalk.green("✓ Hash matches registry") : chalk.red("✗ Hash mismatch"));
        console.log(`expected: ${result.expectedHash}`);
        console.log(`actual:   ${result.actualHash}`);
        console.log(`size:     ${result.actualSizeBytes} bytes`);
      }
      if (!result.valid) process.exitCode = 2;
    } catch (error) {
      spinner.fail("Verification failed");
      console.error(chalk.red((error as Error).message));
      process.exitCode = 1;
    }
  });

program
  .command("hash <file>")
  .description("Compute model SHA-256 hash without registering")
  .option("--json", "Output JSON")
  .action(async (file: string, options) => {
    try {
      const hash = await sha256File(file);
      const size = fs.statSync(file).size;
      if (options.json) {
        console.log(JSON.stringify({ file: path.resolve(file), sha256: hash, sizeBytes: size }, null, 2));
      } else {
        console.log(chalk.cyan(`File: ${path.resolve(file)}`));
        console.log(`SHA-256: ${hash}`);
        console.log(`Size: ${size} bytes`);
      }
    } catch (error) {
      console.error(chalk.red((error as Error).message));
      process.exitCode = 1;
    }
  });

program
  .command("export")
  .description("Export the local registry database to a JSON file")
  .requiredOption("-o, --output <file>", "Output file path")
  .option("--db <path>", "Registry database file path")
  .action((options) => {
    try {
      const db = loadDb(resolveDbPath(options.db));
      ensureDir(options.output);
      fs.writeFileSync(options.output, `${JSON.stringify(db, null, 2)}\n`, "utf8");
      console.log(chalk.green(`Exported ${db.models.length} models to ${options.output}`));
    } catch (error) {
      console.error(chalk.red((error as Error).message));
      process.exitCode = 1;
    }
  });

program
  .command("import <file>")
  .description("Import a registry database snapshot (merge by model hash)")
  .option("--db <path>", "Registry database file path")
  .action((file: string, options) => {
    try {
      const incoming = JSON.parse(fs.readFileSync(file, "utf8")) as RegistryDb;
      if (!incoming || !Array.isArray(incoming.models)) {
        throw new Error("Invalid registry snapshot");
      }
      const dbPath = resolveDbPath(options.db);
      const db = loadDb(dbPath);
      let merged = 0;
      for (const model of incoming.models) {
        upsertModel(db, { ...model, updatedAt: model.updatedAt ?? new Date().toISOString() });
        merged += 1;
      }
      saveDb(dbPath, db);
      console.log(chalk.green(`Imported ${merged} entries into ${dbPath}`));
    } catch (error) {
      console.error(chalk.red((error as Error).message));
      process.exitCode = 1;
    }
  });

program
  .command("convert")
  .description("Generate a deterministic conversion plan for zkML compilation (no prover execution)")
  .requiredOption("-f, --file <path>", "Model file")
  .option("--framework <fw>", "Framework (pytorch, tensorflow, onnx)", "onnx")
  .option("--quantization <bits>", "Quantization bits", "8")
  .option("-o, --output <path>", "Output plan file")
  .action((options) => {
    try {
      const stats = fs.statSync(options.file);
      const plan = {
        inputFile: path.resolve(options.file),
        framework: options.framework,
        quantizationBits: Number(options.quantization),
        fileSizeBytes: stats.size,
        estimatedConstraints: Math.max(10_000, Math.round(stats.size * 2.1)),
        estimatedCircuitSizeBytes: Math.round(stats.size * 0.35),
        generatedAt: new Date().toISOString(),
      };
      if (options.output) {
        ensureDir(options.output);
        fs.writeFileSync(options.output, `${JSON.stringify(plan, null, 2)}\n`, "utf8");
        console.log(chalk.green(`Conversion plan written to ${options.output}`));
      } else {
        console.log(JSON.stringify(plan, null, 2));
      }
    } catch (error) {
      console.error(chalk.red((error as Error).message));
      process.exitCode = 1;
    }
  });

program.parseAsync().catch((error) => {
  console.error(chalk.red((error as Error).message));
  process.exit(1);
});
