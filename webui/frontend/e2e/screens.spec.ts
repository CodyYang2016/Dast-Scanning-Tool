// GEN-2, GEN-3, GEN-6 (display part) — every screen, against a real `dast ui` and real fixture data.
import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";
import { APP, COMPLETE_RUN, open, screens, url } from "./server";

for (const path of screens()) {
  test(`GEN-2 renders without console errors or broken links: ${path}`, async ({ page, request }) => {
    const errors: string[] = [];
    page.on("console", (m) => { if (m.type() === "error") errors.push(m.text()); });
    page.on("pageerror", (e) => errors.push(String(e)));
    await open(page, path);
    await expect(page.getByTestId("nav-overview")).toBeVisible();
    expect(errors).toEqual([]);
    const hrefs = await page.locator("a[href^='/']").evaluateAll(
      (els) => els.map((e) => (e as HTMLAnchorElement).getAttribute("href") as string));
    for (const href of new Set(hrefs)) {
      const res = await request.get(url(href));
      expect(res.status(), href).toBe(200);
    }
  });

  test(`GEN-3 accessible and keyboard-reachable: ${path}`, async ({ page }) => {
    await open(page, path);
    const results = await new AxeBuilder({ page }).analyze();
    const serious = results.violations.filter((v) => v.impact === "serious" || v.impact === "critical");
    expect(serious.map((v) => `${v.id}: ${v.help}`)).toEqual([]);
    const controls = page.locator(
      "a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex='-1'])");
    const visible = [];
    for (const c of await controls.all()) if (await c.isVisible()) visible.push(c);
    const ids = await Promise.all(visible.map((c, i) => c.evaluate((el, n) => {
      (el as HTMLElement).dataset.kbd = String(n); return String(n);
    }, i)));
    const reached = new Set<string>();
    for (let i = 0; i < ids.length + 5; i++) {
      await page.keyboard.press("Tab");
      const k = await page.evaluate(() => (document.activeElement as HTMLElement | null)?.dataset.kbd);
      if (k) reached.add(k);
    }
    expect(ids.filter((id) => !reached.has(id))).toEqual([]);
  });
}

test("GEN-6 screens that start an action show the equivalent command", async ({ page }) => {
  for (const [path, expected] of [
    [`/apps/${APP}/settings`, `python -m dast scan ${APP}`],
    [`/apps/${APP}/runs/${COMPLETE_RUN}/results`, `python -m dast report ${APP}`],
    ["/onboard", "python -m dast onboard"],
  ] as const) {
    await open(page, path);
    await expect(page.getByTestId("equivalent-command").first()).toContainText(expected);
  }
});
