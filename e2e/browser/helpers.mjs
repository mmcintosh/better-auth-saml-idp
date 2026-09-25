import { expect } from "@playwright/test";
import { IDP } from "../lib/config.mjs";
import { hostFetch } from "../lib/procs.mjs";

export const PASSWORD = "correct-horse-battery";
export const newEmail = (tag) => `${tag}-${Date.now()}-${Math.random().toString(36).slice(2, 7)}@example.com`;

/** Collects CSP violations and blocked navigations reported by Chromium. */
export function watchCsp(page) {
  const violations = [];
  page.on("console", (m) => {
    if (/Content Security Policy|violates the following/i.test(m.text())) violations.push(m.text());
  });
  return violations;
}

/** On the IdP's /sign-in page: create an account, click the (dev mailbox) verification link. */
export async function idpSignUpAndVerify(page, email) {
  await expect(page).toHaveURL(new RegExp(`^${IDP}/sign-in\\?`));
  await page.getByRole("button", { name: "Create an account instead" }).click();
  await page.getByLabel("Email").fill(email);
  await page.getByLabel("Password").fill(PASSWORD);
  await page.getByLabel("Name").fill("Pat Playwright");
  await page.getByRole("button", { name: "Create account" }).click();
  await expect(page.getByText("Check your email")).toBeVisible();
  const r = await hostFetch(`${IDP}/dev/mailbox?email=${encodeURIComponent(email)}`);
  const { link } = await r.json();
  expect(link, "verification link").toBeTruthy();
  await page.goto(link); // verifies, signs in, and continues to the SAML resume URL
}

export async function idpSignIn(page, email) {
  await expect(page).toHaveURL(new RegExp(`^${IDP}/sign-in\\?`));
  await page.getByLabel("Email").fill(email);
  await page.getByLabel("Password").fill(PASSWORD);
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
}

/** Record every URL the tab visits, to prove whether the IdP login page was shown. */
export function trackNavigations(page) {
  const urls = [];
  page.on("framenavigated", (f) => f === page.mainFrame() && urls.push(f.url()));
  return urls;
}
