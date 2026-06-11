import { defineConfig } from "vitest/config";

// Vision-LLM steps are slow (each ai* call is a model round-trip), so the
// per-test and per-hook timeouts are generous. Tests run serially (single fork)
// because each spins up a `dx serve` dev server on a fixed port + a browser; we
// do not want two suites racing for the same port or saturating the model API.
export default defineConfig({
  test: {
    include: ["tests/**/*.test.ts"],
    // Load `.env` (model keys + harness overrides) before any test.
    setupFiles: ["./setup.ts"],
    testTimeout: 240_000,
    hookTimeout: 240_000,
    fileParallelism: false,
    pool: "forks",
    poolOptions: {
      forks: { singleFork: true },
    },
    reporters: ["default"],
  },
});
