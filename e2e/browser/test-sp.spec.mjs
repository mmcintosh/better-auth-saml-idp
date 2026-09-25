// node-saml SP on sp.test that redirects to app.test after its ACS (cross-site, like the
// hosted SPs). Guards review findings #5 (CSP form-action vs. post-ACS redirects) and
// #6 (SameSite=Lax cookies are not sent on the SP's cross-site POST).
import { expect, test } from "@playwright/test";
import { IDP, TEST_APP, TEST_SP } from "../lib/config.mjs";
import { idpSignUpAndVerify, newEmail, trackNavigations, watchCsp } from "./helpers.mjs";

async function result(page) {
  await expect(page).toHaveURL(new RegExp(`^${TEST_APP}/done`));
  return JSON.parse(await page.locator("#result").textContent());
}

test.describe.serial("node-saml SP (HTTP-POST binding, cross-site redirect after ACS)", () => {
  const email = newEmail("sp");
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
