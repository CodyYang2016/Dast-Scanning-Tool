// Fills whatever onboarding fields the current wizard step shows, for the E2E specs.
import type { Page } from "@playwright/test";

export const VALUES: Record<string, string> = {
  app_id: "e2e-app", base_url: "http://e2e-app.dev.local", "scope.allow": "e2e-app.dev.local",
  "scope.exclude": "/api/notify", "auth.login_url": "/login",
  "auth.credentials.email_env": "E2E_APP_USER", "auth.credentials.password_env": "E2E_APP_PASS",
  "record.authenticated_routes": "/account",
};

export async function fillVisibleFields(page: Page, overrides: Record<string, string> = {}) {
  const fields = page.locator("[data-testid^='onboard-field-']");
  const names: string[] = [];
  for (const f of await fields.all()) {
    if (!(await f.isVisible())) continue;
    const name = ((await f.getAttribute("data-testid")) as string).replace("onboard-field-", "");
    names.push(name);
    const value = overrides[name] ?? VALUES[name];
    const tag = await f.evaluate((el) => el.tagName.toLowerCase());
    if (tag === "select") {
      const options = await f.locator("option").evaluateAll((os) => os.map((o) => (o as HTMLOptionElement).value));
      await f.selectOption(overrides[name] ?? options[0]);
    } else if (tag === "input" || tag === "textarea") {
      const type = await f.getAttribute("type");
      if (type === "radio" || type === "checkbox") await f.check();
      else if (value !== undefined && !(await f.inputValue())) await f.fill(value);
    } else {
      const input = f.locator("input, select, textarea").first();
      if (await input.count()) {
        const type = await input.getAttribute("type");
        if (type === "radio" || type === "checkbox") await input.check();
        else if (value !== undefined) await input.fill(value);
      }
    }
  }
  return names;
}

export async function walkWizard(page: Page, overrides: Record<string, string>, until: string) {
  const asked = new Set<string>();
  for (let step = 0; step < 10; step++) {
    for (const n of await fillVisibleFields(page, overrides)) asked.add(n);
    if (await page.getByTestId(until).isVisible().catch(() => false)) break;
    const next = page.getByTestId("onboard-continue");
    if (!(await next.isVisible().catch(() => false))) break;
    await next.click();
    await page.waitForLoadState("networkidle");
  }
  return asked;
}
