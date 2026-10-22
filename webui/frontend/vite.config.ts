import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";

// The built app is served by `python -m dast ui`; in development, Vite proxies the API to it.
export default defineConfig({
  plugins: [react()],
  build: { outDir: "dist", sourcemap: false },
  server: {
    proxy: { "/api": "http://127.0.0.1:8765", "/auth": "http://127.0.0.1:8765" },
  },
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./tests/setup.ts"],
    include: ["tests/**/*.test.tsx"],
  },
});
