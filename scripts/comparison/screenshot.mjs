// Regenerate docs/assets/comparison.png (the README image) from docs/comparison/index.html.
//   node scripts/comparison/screenshot.mjs
import { chromium } from "@playwright/test";

const root = new URL("../../", import.meta.url);
const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 1280, height: 900 }, colorScheme: "light" });
await page.goto(new URL("docs/comparison/index.html", root).href);
await page.waitForLoadState("networkidle");
await page.screenshot({
  path: new URL("docs/assets/comparison.png", root).pathname,
  fullPage: true,
  clip: { x: 0, y: 0, width: 1280, height: 1640 },
});
await browser.close();
console.log("wrote docs/assets/comparison.png");
