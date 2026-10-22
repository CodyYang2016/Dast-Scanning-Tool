import { defineConfig } from "@playwright/test";

// global-setup.ts starts a real `python -m dast ui` against a copy of tests/ui/fixtures and signs
// in once through its launch URL. The server's address is only known after that, so specs reach
// it through e2e/server.ts rather than a baseURL here.
export default defineConfig({
  testDir: "e2e",
  globalSetup: "./e2e/global-setup.ts",
  globalTeardown: "./e2e/global-teardown.ts",
  fullyParallel: false,
  workers: 1,
  timeout: 60_000,
  use: { storageState: "e2e/.auth.json" },
});
