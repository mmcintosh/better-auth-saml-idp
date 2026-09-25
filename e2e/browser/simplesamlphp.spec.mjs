// SimpleSAMLphp 2.5 SP (HTTP-Redirect binding).
import { expect, test } from "@playwright/test";
import { IDP, SSP } from "../lib/config.mjs";
import { idpSignUpAndVerify, newEmail, trackNavigations, watchCsp } from "./helpers.mjs";

test("SimpleSAMLphp: new user, then an existing IdP session skips the login page", async ({ page, context }) => {
  const csp = watchCsp(page);
  const email = newEmail("ssp");
  await page.goto(`${SSP}/whoami.php`);
  await idpSignUpAndVerify(page, email);
  await page.waitForURL(`${SSP}/whoami.php`);
  const who = JSON.parse(await page.locator("body").textContent());
  expect(who).toMatchObject({ nameId: email, idp: `${IDP}/api/auth/saml2/idp` });
  expect(who.attributes.email).toEqual([email]);
  expect(csp).toEqual([]);

  // Fresh SP session, same IdP session: no login page.
  await context.clearCookies({ domain: "ssp.test" });
  const second = await context.newPage();
  const nav = trackNavigations(second);
  await second.goto(`${SSP}/whoami.php`);
  await second.waitForURL(`${SSP}/whoami.php`);
  expect(JSON.parse(await second.locator("body").textContent()).nameId).toBe(email);
  expect(nav.filter((u) => u.startsWith(`${IDP}/sign-in`))).toEqual([]);
});
