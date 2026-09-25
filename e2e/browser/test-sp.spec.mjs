// node-saml SP on sp.test that redirects to app.test after its ACS (cross-site, like the
// hosted SPs). Guards review findings #5 (CSP form-action vs. post-ACS redirects) and
// #6 (SameSite=Lax cookies are not sent on the SP's cross-site POST).
import { expect, test } from "@playwright/test";
import { IDP, TEST_APP, TEST_SP } from "../lib/config.mjs";
import { idpSignIn, idpSignUpAndVerify, newEmail, trackNavigations, watchCsp } from "./helpers.mjs";

// One account for the whole file: sign-ups are rate limited (3 per 10 s per IP), and every
// spec signs up from 127.0.0.1. The IdP-initiated tests below sign in with it instead.
const email = newEmail("sp");
const INIT = `${IDP}/api/auth/saml2/idp/init`;

async function result(page) {
  await expect(page).toHaveURL(new RegExp(`^${TEST_APP}/done`));
  return JSON.parse(await page.locator("#result").textContent());
}

test.describe.serial("node-saml SP (HTTP-POST binding, cross-site redirect after ACS)", () => {
  /** @type {import("@playwright/test").BrowserContext} */
  let ctx;
  test.beforeAll(async ({ browser }) => {
    ctx = await browser.newContext();
  });
  test.afterAll(async () => ctx.close());

  test("new user: POST AuthnRequest → IdP sign-up + email verification → SP → app", async () => {
    const page = await ctx.newPage();
    const csp = watchCsp(page);
    await page.goto(`${TEST_SP}/login?variant=post`);
    await idpSignUpAndVerify(page, email);
    const r = await result(page);
    expect(r).toMatchObject({ ok: true, nameID: email, email, issuer: `${IDP}/api/auth/saml2/idp` });
    expect(csp).toEqual([]);
  });

  test("signed in at the IdP: POST AuthnRequest is answered without the login page", async () => {
    const page = await ctx.newPage();
    const csp = watchCsp(page);
    const nav = trackNavigations(page);
    await page.goto(`${TEST_SP}/login?variant=post`);
    const r = await result(page);
    expect(r).toMatchObject({ ok: true, nameID: email });
    expect(nav.filter((u) => u.startsWith(`${IDP}/sign-in`))).toEqual([]);
    expect(csp).toEqual([]);
  });

  test("signed in: Redirect-binding AuthnRequest is answered without the login page", async () => {
    const page = await ctx.newPage();
    const nav = trackNavigations(page);
    await page.goto(`${TEST_SP}/login?variant=redirect`);
    expect(await result(page)).toMatchObject({ ok: true, nameID: email });
    expect(nav.filter((u) => u.startsWith(`${IDP}/sign-in`))).toEqual([]);
  });

  test("signed in: IsPassive POST request succeeds", async () => {
    const page = await ctx.newPage();
    await page.goto(`${TEST_SP}/login?variant=post-passive`);
    expect(await result(page)).toMatchObject({ ok: true, nameID: email });
  });

  test("not signed in: IsPassive POST request returns a SAML NoPassive status to the SP", async ({ browser }) => {
    const fresh = await browser.newContext();
    const page = await fresh.newPage();
    const nav = trackNavigations(page);
    await page.goto(`${TEST_SP}/login?variant=post-passive`);
    const r = await result(page);
    expect(r).toMatchObject({ ok: false, noPassive: true });
    expect(nav.filter((u) => u.startsWith(`${IDP}/sign-in`))).toEqual([]);
    await fresh.close();
  });
});

// IdP-initiated SSO (DECISIONS.md D-021): the same node-saml SP, registered a second time with
// validateInResponseTo "never", receives an unsolicited Response. Also checks that Chromium's
// Fetch Metadata headers drive the login-CSRF confirmation as designed.
test.describe.serial("IdP-initiated SSO (node-saml SP, unsolicited Response)", () => {
  /** @type {import("@playwright/test").BrowserContext} */
  let ctx;
  test.beforeAll(async ({ browser }) => {
    ctx = await browser.newContext();
  });
  test.afterAll(async () => ctx.close());

  test("not signed in: init → IdP sign-in → resume → SP accepts the unsolicited Response", async () => {
    const page = await ctx.newPage();
    const csp = watchCsp(page);
    await page.goto(`${INIT}?sp=test-sp-idp-init`);
    await idpSignIn(page, email);
    const r = await result(page);
    expect(r).toMatchObject({ ok: true, nameID: email, inResponseTo: null, relayState: "default-landing" });
    expect(csp).toEqual([]);
  });

  test("signed in: a portal link on another site signs in directly, with an allow-listed RelayState", async () => {
    const page = await ctx.newPage();
    const nav = trackNavigations(page);
    await page.goto(`${TEST_APP}/portal?to=${encodeURIComponent(`${INIT}?sp=test-sp-idp-init&RelayState=reports`)}`);
    await page.locator("#launch").click();
    expect(await result(page)).toMatchObject({ ok: true, nameID: email, relayState: "reports" });
    expect(nav.filter((u) => u.startsWith(`${IDP}/sign-in`))).toEqual([]);
  });

  test("signed in: a RelayState not on the allow-list is replaced by the SP's default", async () => {
    const page = await ctx.newPage();
    await page.goto(`${INIT}?sp=test-sp-idp-init&RelayState=${encodeURIComponent("https://evil.test/phish")}`);
    expect(await result(page)).toMatchObject({ ok: true, relayState: "default-landing" });
  });

  test("signed in: a drive-by redirect from another site (no user activation) must be confirmed on the IdP", async () => {
    const page = await ctx.newPage();
    await page.goto(`${TEST_APP}/drive-by?to=${encodeURIComponent(`${INIT}?sp=test-sp-idp-init`)}`);
    await expect(page).toHaveURL(new RegExp(`^${INIT}\\?sp=test-sp-idp-init$`));
    await expect(page.getByRole("heading", { name: "Continue to test-sp-idp-init?" })).toBeVisible();
    await page.getByRole("link", { name: "Continue" }).click();
    expect(await result(page)).toMatchObject({ ok: true, nameID: email, relayState: "default-landing" });
  });

  test("an SP without the opt-in gets nothing", async () => {
    const page = await ctx.newPage();
    const res = await page.goto(`${INIT}?sp=test-sp`);
    expect(res?.status()).toBe(400);
    await expect(page.locator("code")).toHaveText("IDP_INITIATED_NOT_ALLOWED");
  });
});
