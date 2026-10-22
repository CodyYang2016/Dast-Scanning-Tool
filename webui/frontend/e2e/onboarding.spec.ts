// ONB-1, ONB-2, ONB-7 — the onboarding wizard asks only the must-ask questions, refuses an
// unregistered host, and treats secrets as names.
import { expect, test } from "@playwright/test";
import { open } from "./server";
import { fillVisibleFields, walkWizard } from "./wizard";

// ui_acceptance_criteria.md §4: the tier A onboarding fields (data is durable by default).
const TIER_A = [
  "app_id", "base_url", "environment_class", "scope.allow", "scope.exclude", "auth.mode",
  "auth.login_url", "auth.credentials.email_env", "auth.credentials.password_env",
  "record.authenticated_routes",
];

test("ONB-1 the wizard asks exactly the tier A onboarding questions", async ({ page }) => {
  await open(page, "/onboard");
  const asked = await walkWizard(page, { environment_class: "dev" }, "proof-confirm");
  expect([...asked].sort()).toEqual([...TIER_A].sort());
});

test("ONB-2 an unregistered test host is refused at the first step", async ({ page }) => {
  await open(page, "/onboard");
  await fillVisibleFields(page, { app_id: "billing", base_url: "https://billing.test.example.internal",
                                  environment_class: "test" });
  await page.getByTestId("onboard-continue").click();
  const refusal = page.getByTestId("onboard-refusal");
  await expect(refusal).toBeVisible();
  await expect(refusal).toContainText("billing.test.example.internal");
});

test("ONB-7 secrets are asked for by name, with set/unset status, never by value", async ({ page }) => {
  await open(page, "/onboard");
  await walkWizard(page, { environment_class: "dev" }, "onboard-field-auth.credentials.password_env");
  for (const f of ["auth.credentials.email_env", "auth.credentials.password_env"]) {
    await expect(page.getByTestId(`onboard-field-${f}`)).toBeVisible();
    await expect(page.getByTestId(`onboard-secret-status-${f}`)).toBeVisible();
  }
  await expect(page.locator("input[type='password']")).toHaveCount(0);
});
