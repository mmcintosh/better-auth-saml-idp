// The example's reference admin page (/admin), in real Chromium on workerd (review 5 R5-7):
// the admin gate, the IdP details, and the add → save → disable → delete cycle on the
// registry API, with the page's own CSP enforced.
import { expect, test } from "@playwright/test";
import { ADMIN_EMAIL, IDP } from "../lib/config.mjs";
import { idpSignUpAndVerify, newEmail, watchCsp } from "./helpers.mjs";

const SP_ID = `e2e-${Date.now().toString(36)}`;
const SP_ENTITY = `https://${SP_ID}.test/sp`;
const SP_METADATA = `<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="${SP_ENTITY}">
<md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
<md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://${SP_ID}.test/acs" index="0" isDefault="true"/>
</md:SPSSODescriptor></md:EntityDescriptor>`;

test.describe.serial("example admin page", () => {
  test("a signed-in user who isn't a listed admin is refused", async ({ browser }) => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await page.goto(`${IDP}/admin`);
    await idpSignUpAndVerify(page, newEmail("not-admin"));
    await page.goto(`${IDP}/admin`);
    await expect(page.getByRole("heading", { name: "Not an administrator" })).toBeVisible();
    await ctx.close();
  });

  test("the listed admin manages SPs: details, add from metadata, disable, delete", async ({ browser }) => {
    await new Promise((r) => setTimeout(r, 10_000)); // sign-ups are rate limited per IP
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    const csp = watchCsp(page);
    await page.goto(`${IDP}/admin`);
    await idpSignUpAndVerify(page, ADMIN_EMAIL); // continues to /admin after verification
    await page.goto(`${IDP}/admin`);
    await expect(page.getByRole("heading", { name: "This identity provider" })).toBeVisible();
    await expect(page.getByText(`${IDP}/api/auth/saml2/idp/sso`)).toBeVisible();
    // Code SPs (the e2e SPs) are listed, read-only.
    const keycloakRow = page.locator("#sps tr", { hasText: "keycloak" });
    await expect(keycloakRow).toContainText("defined in code");

    // Add from metadata, review, save.
    await page.getByLabel(/^ID/).fill(SP_ID);
    await page.getByLabel("SP metadata XML").fill(SP_METADATA);
    await page.getByRole("button", { name: "Convert to configuration" }).click();
    await expect(page.locator("#editor")).toBeVisible();
    await expect(page.locator("#cfg")).toHaveValue(new RegExp(SP_ENTITY.replace(/[.]/g, "\\.")));
    await page.getByRole("button", { name: "Save" }).click();
    const row = page.locator("#sps tr", { hasText: SP_ID });
    await expect(row).toContainText("active");

    // Disable (a switch-only update), then delete.
    await row.getByRole("button", { name: "Disable" }).click();
    await expect(row).toContainText("disabled");
    page.once("dialog", (d) => d.accept());
    await row.getByRole("button", { name: "Delete" }).click();
    await expect(page.locator("#sps tr", { hasText: SP_ID })).toHaveCount(0);

    expect(csp).toEqual([]);
    await ctx.close();
  });
});
