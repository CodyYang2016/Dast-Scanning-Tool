// Where global-setup.ts started the UI, and which fixture data it serves.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { Page } from "@playwright/test";
import { fileURLToPath } from "node:url";

const HERE = fileURLToPath(new URL(".", import.meta.url));

export function server(): { baseURL: string; work: string } {
  return JSON.parse(readFileSync(join(HERE, ".server.json"), "utf-8"));
}

export const url = (path: string) => server().baseURL + path;

export async function open(page: Page, path: string) {
  await page.goto(url(path));
  await page.waitForLoadState("networkidle");
}

export const APP = "juice-shop";
export const COMPLETE_RUN = "20261019T125049Z";

// Read from the repository's fixtures (identical to the served copy) so specs can be listed
// before global-setup has started the server.
const FIXTURES = join(HERE, "..", "..", "..", "tests", "ui", "fixtures");

export function firstHighFingerprint(): string {
  const labeled = JSON.parse(readFileSync(
    join(FIXTURES, "out", APP, "scans", COMPLETE_RUN, "labeled.json"), "utf-8"));
  return labeled.find((r: { severity: string }) => r.severity === "high").fingerprint;
}

export function screens(): string[] {
  return [
    "/", "/onboard", `/apps/${APP}/settings`,
    `/apps/${APP}/runs/${COMPLETE_RUN}/progress`, `/apps/${APP}/runs/${COMPLETE_RUN}/results`,
    `/apps/${APP}/runs/${COMPLETE_RUN}/findings/${firstHighFingerprint()}`,
    "/governance", "/apps/orders-portal/automate",
  ];
}
