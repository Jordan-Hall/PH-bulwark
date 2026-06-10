// Load `.env` (model keys + harness overrides) before any test runs. Referenced
// by vitest.config.ts `setupFiles`. Keys are read from the environment by
// Midscene; nothing is hard-coded here.
import "dotenv/config";
