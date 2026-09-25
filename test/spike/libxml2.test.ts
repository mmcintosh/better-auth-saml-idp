import { beforeAll, describe, expect, inject, it } from "vitest";
import * as samlify from "samlify";
import { createValidator } from "../../spike/libxml2-validator";

const isWorkerd = typeof navigator !== "undefined" && navigator.userAgent === "Cloudflare-Workers";
const keys = inject("keys");
let validator: Awaited<ReturnType<typeof createValidator>>;

// Known blocker (see DECISIONS.md D-003): even with a precompiled module passed via
// emscripten's instantiateWasm hook, libxml2-wasm's addFunction() compiles a tiny Wasm
// module at runtime for every JS callback, which workerd forbids. If this test starts
// failing, upstream fixed it and the decision should be revisited.
describe.runIf(isWorkerd)("libxml2-wasm under workerd", () => {
  it("is blocked by runtime Wasm code generation", async () => {
    await expect(import("../../spike/libxml2-vendor/index.mjs")).rejects.toThrow(
      /Wasm code generation disallowed by embedder/,
    );
  });
});

beforeAll(async () => {
  if (isWorkerd) return;
  const t0 = performance.now();
  validator = createValidator((await import("libxml2-wasm")) as any);
  console.log(`libxml2-wasm init+schema compile ms: ${(performance.now() - t0).toFixed(1)}`);
});

describe.skipIf(isWorkerd)("libxml2-wasm validator (node)", () => {
  it("round-trips through a strict samlify SP with libxml2-wasm as the validator", async () => {
    samlify.setSchemaValidator(validator);
    const idp = samlify.IdentityProvider({
      entityID: "https://idp.test/saml2/idp",
      privateKey: keys.idp.privateKey,
      signingCert: keys.idp.certificate,
      singleSignOnService: [{ Binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", Location: "https://idp.test/sso" }],
      nameIDFormat: ["urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"],
    });
    const sp = samlify.ServiceProvider({
      entityID: "https://sp.test/metadata",
      wantAssertionsSigned: true,
      wantMessageSigned: true,
      assertionConsumerService: [{ Binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", Location: "https://sp.test/acs" }],
    });
    const { context } = sp.createLoginRequest(idp, "redirect") as { context: string };
    const url = new URL(context);
    const req = await idp.parseLoginRequest(sp, "redirect", { query: Object.fromEntries(url.searchParams), octetString: url.search.slice(1) });
    const res = (await idp.createLoginResponse(sp, req, "post", { email: "alice@example.com" })) as { context: string };
    const parsed = await sp.parseLoginResponse(idp, "post", { body: { SAMLResponse: res.context } });
    expect(parsed.extract.nameID).toBe("alice@example.com");

    const xml = atob(res.context);
    const t0 = performance.now();
    for (let i = 0; i < 20; i++) await validator.validate(xml);
    console.log(`validate avg ms over 20 runs: ${((performance.now() - t0) / 20).toFixed(2)}`);

    await expect(validator.validate(xml.replace("<saml:Issuer", "<samlp:Bogus/><saml:Issuer"))).rejects.toThrow(/Bogus/);
  });

  it("rejects DOCTYPE/entity tricks without expanding them", async () => {
    const xxe = `<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_a" Version="2.0" IssueInstant="2026-01-01T00:00:00Z">&x;</samlp:AuthnRequest>`;
    await expect(validator.validate(xxe)).rejects.toThrow();
  });
});
