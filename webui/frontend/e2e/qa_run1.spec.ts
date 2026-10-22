// Regression tests for manual QA run 1 (docs/ui-docs/ui_qa_findings.md), onboarding half:
// QA-2 (the browser's back arrow steps back through the wizard) and QA-8 (pre-fills follow the
// current address and id until the person edits them).
import { expect, test, type Page } from "@playwright/test";
import { open } from "./server";

const field = (page: Page, name: string) => page.getByTestId(`onboard-field-${name}`);
const cont = (page: Page) => page.getByTestId("onboard-continue").click();

async function first(page: Page, app_id: string, base_url: string, env: string) {
  await field(page, "app_id").fill(app_id);
  await field(page, "base_url").fill(base_url);
  await field(page, "environment_class").selectOption(env);
}

test("QA-2 the browser's back arrow steps back through the wizard, keeping what was typed", async ({ page }) => {
  await open(page, "/onboard");
  await first(page, "qa-back", "http://qa-back.dev.local", "dev");
  await cont(page);
  await expect(field(page, "scope.allow")).toBeVisible();
  await expect(page).toHaveURL(/[?&]step=2\b/);
  await cont(page);
  await expect(field(page, "auth.login_url")).toBeVisible();
  await expect(page).toHaveURL(/[?&]step=3\b/);

  await page.goBack();
  await expect(field(page, "scope.allow")).toHaveValue("qa-back.dev.local");
  await page.goBack();
  await expect(field(page, "app_id")).toHaveValue("qa-back");
  await expect(page).toHaveURL(/\/onboard(\?step=1)?$/);
});

test("QA-2 a step the form can't be on falls back to the first step", async ({ page }) => {
  await open(page, "/onboard?step=4");
  await expect(field(page, "app_id")).toBeVisible();
});

test("QA-8 after a refusal, pre-fills follow the corrected address and id", async ({ page }) => {
  await open(page, "/onboard");
  await first(page, "billing", "https://billing.test.example.internal", "test");
  await cont(page);
  await expect(page.getByTestId("onboard-refusal")).toBeVisible();

  await first(page, "qa-app", "http://qa-app.dev.local", "dev");
  await cont(page);
  await expect(field(page, "scope.allow")).toHaveValue("qa-app.dev.local");
  await cont(page);
  await expect(field(page, "auth.credentials.email_env")).toHaveValue("QA_APP_USER");
  await expect(field(page, "auth.credentials.password_env")).toHaveValue("QA_APP_PASS");
});

test("QA-8 a host the person typed survives going back and changing the address", async ({ page }) => {
  await open(page, "/onboard");
  await first(page, "qa-keep", "http://qa-keep.dev.local", "dev");
  await cont(page);
  await field(page, "scope.allow").fill("hand-typed.dev.local");
  await page.getByRole("button", { name: "Back" }).click();
  await first(page, "qa-keep2", "http://qa-keep2.dev.local", "dev");
  await cont(page);
  await expect(field(page, "scope.allow")).toHaveValue("hand-typed.dev.local");
});
