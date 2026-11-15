// tests/a11y.spec.ts — automated accessibility pass (09-accessibility-i18n §13)
// Requires: npm i -D @playwright/test @axe-core/playwright
// Automated tools catch only part of WCAG issues; still do a manual keyboard + screen reader pass.
import { test, expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';

const PAGES = ['/', '/about']; // add your key routes

for (const path of PAGES) {
  test(`axe: ${path} has no WCAG 2.2 AA violations`, async ({ page }) => {
    await page.goto(path);
    const results = await new AxeBuilder({ page })
      .withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa'])
      .analyze();
    expect(results.violations, JSON.stringify(results.violations, null, 2)).toEqual([]);
  });

  test(`keyboard: ${path} first Tab reaches the skip link`, async ({ page }) => {
    await page.goto(path);
    await page.keyboard.press('Tab');
    const focused = page.locator(':focus');
    await expect(focused).toHaveAttribute('href', '#main');
  });
}
