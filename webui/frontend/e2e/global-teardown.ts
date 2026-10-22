import { existsSync, readFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = fileURLToPath(new URL(".", import.meta.url));

export default async function globalTeardown() {
  const state = join(HERE, ".server.json");
  if (!existsSync(state)) return;
  const { pid, work } = JSON.parse(readFileSync(state, "utf-8"));
  try { process.kill(pid, "SIGTERM"); } catch { /* already gone */ }
  rmSync(work, { recursive: true, force: true });
  rmSync(state, { force: true });
  rmSync(join(HERE, ".auth.json"), { force: true });
}
