import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    coverage: {
      provider: "v8",
      reporter: ["text", "json-summary"],
      all: true,
      include: [
        "src/core/client.ts",
        "src/core/config.ts",
        "src/core/errors.ts",
        "src/crypto/index.ts",
        "src/crypto/pqc.ts",
        "src/devtools/seal-verifier.ts",
        "src/jobs/index.ts",
        "src/seals/index.ts",
        "src/nn/module.ts",
        "src/nn/containers.ts",
      ],
      exclude: [
        "**/*.test.ts",
      ],
      thresholds: {
        lines: 95,
        functions: 90,
        statements: 95,
        branches: 85,
      },
    },
  },
});
