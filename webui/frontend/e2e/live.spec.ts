// LIVE: ONB-8, RUN-5, GEN-6 against the real tools. They need the semgate lab on :8084, ZAP and
// Juice Shop from compose, and an AI key, so they run only with LIVE=1 (npm run e2e:live).
import { expect, test } from "@playwright/test";
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, readdirSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { open, server } from "./server";
import { walkWizard } from "./wizard";
import { fileURLToPath } from "node:url";

const HERE = fileURLToPath(new URL(".", import.meta.url));

const ROOT = resolve(HERE, "../../..");
const PY = existsSync(join(ROOT, ".venv/bin/python")) ? join(ROOT, ".venv/bin/python") : "python3";
const dirs = () => ({
  DAST_APPS_DIR: join(server().work, "security/dast"), DAST_OUT: join(server().work, "out"),
  DAST_ENV_REGISTRY: join(server().work, "security/dast/environments.yaml"),
});
const cli = (args: string[]) => execFileSync(PY, ["-m", "dast", ...args], {
  cwd: ROOT, encoding: "utf-8", env: { ...process.env, ...dirs() },
});
const runs = (app: string) => {
  const d = join(dirs().DAST_OUT, app, "scans");
  return existsSync(d) ? readdirSync(d).sort() : [];
};

test.skip(!process.env.LIVE, "LIVE=1 runs the tests that need the semgate lab, ZAP and an AI key");

test("ONB-8 semgate onboarded through the UI passes `dast author`", async ({ page }) => {
  await open(page, "/onboard");
  await walkWizard(page, {
    app_id: "semgate", base_url: "http://localhost:8084", environment_class: "dev",
    "scope.allow": "localhost", "auth.login_url": "/signin",
    "auth.credentials.email_env": "SEMGATE_USER", "auth.credentials.password_env": "SEMGATE_PASS",
    "record.authenticated_routes": "/home", "scope.exclude": "/logout",
  }, "proof-confirm");
  await page.getByTestId("proof-confirm").click();
  await expect(page).toHaveURL(/\/apps\/semgate\/settings/, { timeout: 30_000 });
  const out = cli(["author", "semgate", "--explore", "--zap-proxy", "", "--no-replay"]);
  expect(out).toContain('"app_id": "semgate"');
});

test("RUN-5 a real refusal reads as a sentence, never a traceback", async ({ page }) => {
  const app = join(dirs().DAST_APPS_DIR, "billing");
  mkdirSync(app, { recursive: true });
  writeFileSync(join(app, "app.yaml"), [
    "app_id: billing", "environment_class: test", "base_url: https://billing.test.example.internal",
    "scope:", "  allow: [billing.test.example.internal]",
    "auth:", "  mode: form", "  login_url: /login",
    "  steps:", "    - {action: click, selector: \"button[type=submit]\"}",
    "  proof:", "    selector: \"#signed-in\"",
    "  credentials:", "    email_env: BILLING_USER", "    password_env: BILLING_PASS", "",
  ].join("\n"));
  await open(page, "/apps/billing/settings");
  await page.getByRole("button", { name: /run a scan/i }).click();
  const refusal = page.getByTestId("refusal");
  await expect(refusal).toBeVisible({ timeout: 90_000 });
  await expect(refusal).toContainText("billing.test.example.internal");
  await expect(page.locator("body")).not.toContainText("Traceback");
});

test("GEN-6 the command the UI shows, run by hand, produces the same artifacts", async ({ page }) => {
  await open(page, "/apps/juice-shop/settings");
  const shown = (await page.getByTestId("equivalent-command").first().innerText()).trim();
  expect(shown).toBe("python -m dast scan juice-shop");
  const before = runs("juice-shop");
  await page.getByRole("button", { name: /run a scan/i }).click();
  await expect(page.getByTestId("run-stage-coverage")).toHaveAttribute("data-state", "done", { timeout: 20 * 60_000 });
  const fromUi = runs("juice-shop").filter((r) => !before.includes(r));
  expect(fromUi).toHaveLength(1);
  cli(shown.replace(/^python -m dast /, "").split(" "));
  const byHand = runs("juice-shop").filter((r) => !before.includes(r) && r !== fromUi[0]);
  expect(byHand).toHaveLength(1);
  const files = (r: string) => readdirSync(join(dirs().DAST_OUT, "juice-shop", "scans", r)).sort();
  expect(files(byHand[0])).toEqual(files(fromUi[0]));
});
