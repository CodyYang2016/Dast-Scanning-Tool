// Start a real `python -m dast ui` against a throwaway copy of the fixtures, and sign in once.
import { request } from "@playwright/test";
import { spawn } from "node:child_process";
import { cpSync, existsSync, mkdtempSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = fileURLToPath(new URL(".", import.meta.url));

const ROOT = resolve(HERE, "../../..");

function freePort(): Promise<number> {
  return new Promise((ok, fail) => {
    const s = createServer();
    s.listen(0, "127.0.0.1", () => {
      const port = (s.address() as { port: number }).port;
      s.close(() => ok(port));
    });
    s.on("error", fail);
  });
}

export default async function globalSetup() {
  const work = mkdtempSync(join(tmpdir(), "dast-ui-e2e-"));
  cpSync(join(ROOT, "tests/ui/fixtures/apps"), join(work, "security/dast"), { recursive: true });
  cpSync(join(ROOT, "tests/ui/fixtures/out"), join(work, "out"), { recursive: true });
  const python = existsSync(join(ROOT, ".venv/bin/python")) ? join(ROOT, ".venv/bin/python") : "python3";
  const port = await freePort();
  const env = {
    ...process.env,
    DAST_APPS_DIR: join(work, "security/dast"),
    DAST_OUT: join(work, "out"),
    DAST_ENV_REGISTRY: join(work, "security/dast/environments.yaml"),
  };
  // Deterministic without AI — except in live runs, whose onboarding test (ONB-8) needs discovery.
  if (!process.env.LIVE) delete (env as Record<string, string | undefined>).ANTHROPIC_API_KEY;
  const proc = spawn(python, ["-m", "dast", "ui", "--no-open", "--port", String(port)], {
    cwd: ROOT, env, stdio: ["ignore", "pipe", "pipe"], detached: false,
  });
  const launch: string = await new Promise((ok, fail) => {
    const timer = setTimeout(() => fail(new Error("dast ui did not print its launch URL")), 30_000);
    const scan = (chunk: Buffer) => {
      const m = chunk.toString().match(/http:\/\/127\.0\.0\.1:\d+\/auth\?token=\S+/);
      if (m) { clearTimeout(timer); ok(m[0]); }
    };
    proc.stdout.on("data", scan);
    proc.stderr.on("data", scan);
    proc.on("exit", (code) => fail(new Error(`dast ui exited early (${code})`)));
  });
  const baseURL = `http://127.0.0.1:${port}`;
  const ctx = await request.newContext({ baseURL });
  const res = await ctx.get(launch.replace(baseURL, ""), { maxRedirects: 0 });
  if (res.status() !== 303) throw new Error(`launch URL answered ${res.status()}`);
  await ctx.storageState({ path: join(HERE, ".auth.json") });
  await ctx.dispose();
  writeFileSync(join(HERE, ".server.json"), JSON.stringify({ baseURL, pid: proc.pid, work }));
}
