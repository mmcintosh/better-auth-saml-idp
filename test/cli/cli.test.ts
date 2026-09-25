// The CLI (Node only), driven through run() with fetch routed to an in-process IdP.
import { X509Certificate } from "node:crypto";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, inject, it, vi } from "vitest";
import { run } from "../../src/cli/main";
import { parseDoc, verifyEnveloped } from "../../src/cli/saml";
import { resolveOptions } from "../../src/options";
import { SP_ACS, SP_ENTITY_ID } from "../support/config";
import { BASE_URL, createHost, type HostOptions } from "../support/host";
import { authnRequestXml, Browser, readAutoPost, redirectUrl } from "../support/sp";

const keys = inject("keys");
const dir = mkdtempSync(join(tmpdir(), "saml-cli-"));
const file = (name: string, content: string) => {
  const p = join(dir, name);
  writeFileSync(p, content);
  return p;
};
const IDP_CERT = file("idp.crt", keys.idp.certificate);
const SP_CERT = file("sp.crt", keys.sp.certificate);
const SP_KEY = file("sp.key", keys.sp.privateKey);
const OTHER_CERT = file("other.crt", keys.idpNext.certificate);

async function host(options: HostOptions = {}) {
  const h = await createHost(options);
  vi.stubGlobal("fetch", (url: string | URL | Request, init?: RequestInit) => h.auth.handler(new Request(url, init)));
  return { ...h, browser: new Browser(h.auth) };
}
afterEach(() => vi.unstubAllGlobals());

async function signedResponse(options: HostOptions = {}) {
  const { browser } = await host(options);
  await browser.signUp();
  return readAutoPost(await browser.fetch(await redirectUrl(authnRequestXml().xml)));
}

const json = async (argv: string[]) => {
  const r = await run([...argv, "--json"]);
  return { ...r, report: JSON.parse(r.stdout) as { ok: boolean; checks: { status: string; message: string }[]; data: any; output?: string } };
};
const failures = (r: { report: { checks: { status: string; message: string }[] } }) =>
  r.report.checks.filter((c) => c.status === "fail").map((c) => c.message);

describe("cli: usage", () => {
  it("prints help; unknown commands and options are usage errors (exit 2)", async () => {
    expect((await run(["--help"])).stdout).toMatch(/Commands/);
    expect((await run([])).code).toBe(2);
    expect((await run(["frobnicate"])).code).toBe(2);
    expect((await run(["inspect", "--nope"])).code).toBe(2);
    expect((await run(["inspect", "http://auth.test"])).stderr).toMatch(/use https/);
  });
});

describe("cli: inspect", () => {
  it("reports metadata, schema validity and certificates", async () => {
    await host();
    const r = await json(["inspect", BASE_URL]);
    expect(r.code).toBe(0);
    expect(r.report.data.metadata.entityId).toBe("https://auth.test/api/auth/saml2/idp");
    expect(r.report.checks.map((c) => c.message)).toEqual(expect.arrayContaining([expect.stringMatching(/metadata schema/), expect.stringMatching(/certificate #1: valid/)]));
  });

  it("verifies signed metadata, and fails against a pinned certificate it wasn't signed with", async () => {
    await host({ saml: { signMetadata: true } });
    const ok = await json(["inspect", BASE_URL, "--cert", IDP_CERT]);
    expect(ok.code).toBe(0);
    expect(ok.report.checks.some((c) => c.status === "pass" && /pinned certificate/.test(c.message))).toBe(true);
    const bad = await json(["inspect", BASE_URL, "--cert", OTHER_CERT]);
    expect(bad.code).toBe(1);
    expect(failures(bad).join()).toMatch(/pinned/);
  });

  it("explains a 404 (wrong base path)", async () => {
    await host();
    const r = await json(["inspect", BASE_URL, "--base-path", "/auth"]);
    expect(r.code).toBe(1);
    expect(failures(r).join()).toMatch(/--base-path/);
  });
});

describe("cli: decode a Response", () => {
  it("verifies both signatures and reports the assertion, from a form body, base64 or XML", async () => {
    const form = await signedResponse();
    for (const input of [`SAMLResponse=${form.samlResponse}`, form.samlResponse, form.xml]) {
      const r = await json(["decode", input, "--cert", IDP_CERT, "--sp", SP_ENTITY_ID, "--acs", SP_ACS]);
      expect(failures(r)).toEqual([]);
      const passed = r.report.checks.filter((c) => c.status === "pass").map((c) => c.message);
      expect(passed).toEqual(expect.arrayContaining([expect.stringMatching(/^Response signature is valid/), expect.stringMatching(/^Assertion signature is valid/), `Audience includes ${SP_ENTITY_ID}`]));
    }
  });

  it("a form body with '+' in the base64 decodes (form decoding turns + into space)", async () => {
    const form = await signedResponse();
    expect(form.samlResponse).toMatch(/\+/);
    const r = await json(["decode", `SAMLResponse=${form.samlResponse}&RelayState=x`, "--cert", IDP_CERT]);
    expect(failures(r)).toEqual([]);
  });

  it("an altered Response fails verification (exit 1)", async () => {
    const form = await signedResponse();
    const tampered = form.xml.replace(/(<saml:NameID [^>]*>)[^<]+/, "$1mallory@example.com");
    const r = await json(["decode", tampered, "--cert", IDP_CERT]);
    expect(r.code).toBe(1);
    expect(failures(r).join()).toMatch(/signature is INVALID/);
  });

  it("the wrong certificate fails; no certificate only warns", async () => {
    const form = await signedResponse();
    expect((await json(["decode", form.xml, "--cert", OTHER_CERT])).code).toBe(1);
    const none = await json(["decode", form.xml]);
    expect(none.code).toBe(0);
    expect(none.report.checks.filter((c) => c.status === "warn").map((c) => c.message).join()).toMatch(/not verified/);
  });

  it("takes certificates from --idp metadata and checks the Issuer", async () => {
    const form = await signedResponse();
    const r = await json(["decode", form.xml, "--idp", BASE_URL]);
    expect(failures(r)).toEqual([]);
  });

  it("wrong Audience / ACS / request ID are failures", async () => {
    const form = await signedResponse();
    const r = await json(["decode", form.xml, "--cert", IDP_CERT, "--sp", "https://other.test", "--acs", "https://other.test/acs", "--request-id", "_nope"]);
    expect(r.code).toBe(1);
    expect(failures(r).join("\n")).toMatch(/Audience[\s\S]*Destination|Destination[\s\S]*Audience/);
  });

  it("decrypts an EncryptedAssertion with --key and verifies the inner signature", async () => {
    const form = await signedResponse({
      saml: { serviceProviders: [{ id: "test-sp", entityId: SP_ENTITY_ID, acsUrls: [SP_ACS], encryption: { certificate: keys.sp.certificate } }] },
    });
    expect(form.xml).toMatch(/EncryptedAssertion/);
    const locked = await json(["decode", form.xml, "--cert", IDP_CERT]);
    expect(locked.report.checks.some((c) => /pass --key/.test(c.message))).toBe(true);
    const r = await json(["decode", form.xml, "--cert", IDP_CERT, "--key", SP_KEY, "--sp", SP_ENTITY_ID, "--xml"]);
    expect(failures(r)).toEqual([]);
    expect(r.report.checks.map((c) => c.message)).toEqual(expect.arrayContaining(["decrypted the assertion", expect.stringMatching(/^Assertion signature is valid/)]));
    expect(r.report.data.decryptedAssertion).toMatch(/<saml:Assertion /);
    const wrong = await run(["decode", form.xml, "--key", file("wrong.key", keys.idpNext.privateKey)]);
    expect(wrong.code).toBe(2);
    expect(wrong.stderr).toMatch(/wrong private key/);
  });

  it("detects a duplicated ID (signature wrapping)", async () => {
    const form = await signedResponse();
    const id = /<saml:Assertion [^>]*ID="([^"]+)"/.exec(form.xml)![1]!;
    const doc = parseDoc(form.xml.replace("<saml:Issuer", `<saml:Issuer`).replace(/<samlp:Status>/, `<samlp:Extensions><x ID="${id}"/></samlp:Extensions><samlp:Status>`));
    const assertion = doc.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:assertion", "Assertion")[0];
    const r = verifyEnveloped(form.xml, doc, assertion, [keys.idp.certificate]);
    expect(r.valid).toBe(false);
    expect(r.problem).toMatch(/appears on 2 elements/);
  });

  it("refuses a DOCTYPE", async () => {
    const r = await run(["decode", `<!DOCTYPE x [<!ENTITY e "a">]><samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"/>`]);
    expect(r.code).toBe(2);
    expect(r.stderr).toMatch(/refusing to parse/);
  });
});

describe("cli: request + decode an AuthnRequest", () => {
  it("builds a Redirect URL the IdP accepts, and decode explains it", async () => {
    const { browser } = await host();
    const r = await run(["request", BASE_URL, "--sp", SP_ENTITY_ID, "--acs", SP_ACS, "--relay-state", "rs", "--name-id-format", "email"]);
    expect(r.code).toBe(0);
    const url = r.stdout.trim();
    expect(url).toMatch(/^https:\/\/auth\.test\/api\/auth\/saml2\/idp\/sso\?SAMLRequest=/);
    expect(r.stderr).toMatch(/AuthnRequest/); // the report goes to stderr, the URL alone to stdout
    expect((await browser.fetch(url)).status).toBe(302); // to sign-in: accepted
    const d = await json(["decode", url]);
    expect(failures(d)).toEqual([]);
    expect(d.report.checks.some((c) => /valid AuthnRequest/.test(c.message))).toBe(true);
  });

  it("signs with --sign-key; decode verifies it with the SP certificate and rejects another", async () => {
    await host();
    const url = (await run(["request", BASE_URL, "--sp", SP_ENTITY_ID, "--sign-key", SP_KEY])).stdout.trim();
    expect(url).toMatch(/&SigAlg=.*&Signature=/);
    expect(failures(await json(["decode", url, "--cert", SP_CERT]))).toEqual([]);
    const bad = await json(["decode", url, "--cert", OTHER_CERT]);
    expect(failures(bad).join()).toMatch(/signature is invalid/);
  });

  it("post binding with --sign-key: an XML-signed request that decode verifies and the IdP accepts", async () => {
    const { browser } = await host({ saml: { serviceProviders: [{ id: "test-sp", entityId: SP_ENTITY_ID, acsUrls: [SP_ACS], requireSignedAuthnRequests: true, spCertificate: keys.sp.certificate }] } });
    await browser.signUp();
    const r = await json(["request", BASE_URL, "--sp", SP_ENTITY_ID, "--binding", "post", "--sign-key", SP_KEY]);
    const b64 = /name="SAMLRequest" value="([^"]+)"/.exec(r.report.output!)![1]!;
    const d = await json(["decode", `SAMLRequest=${b64}`, "--cert", SP_CERT]);
    expect(d.report.checks.some((c) => c.status === "pass" && /embedded XML signature is valid/.test(c.message))).toBe(true);
    expect(failures(await json(["decode", `SAMLRequest=${b64}`, "--cert", OTHER_CERT])).join()).toMatch(/embedded XML signature/);
    const res = await browser.follow(
      await browser.fetch(`${BASE_URL}/api/auth/saml2/idp/sso`, {
        method: "POST",
        crossSite: true,
        headers: { "content-type": "application/x-www-form-urlencoded", origin: "https://sp.test" },
        body: new URLSearchParams({ SAMLRequest: b64 }).toString(),
      }),
    );
    expect(res.status).toBe(200);
    expect((await readAutoPost(res)).xml).toMatch(/status:Success/);
  });

  it("post binding prints an auto-submit form", async () => {
    await host();
    const r = await run(["request", BASE_URL, "--sp", SP_ENTITY_ID, "--binding", "post"]);
    expect(r.stdout).toMatch(/<form method="post" action="https:\/\/auth\.test\/api\/auth\/saml2\/idp\/sso">/);
  });
});

describe("cli: smoke", () => {
  it("passes every check against the in-process IdP", async () => {
    await host();
    const r = await json(["smoke", BASE_URL, "--sp", SP_ENTITY_ID, "--acs", SP_ACS]);
    expect(failures(r)).toEqual([]);
    expect(r.report.checks.filter((c) => c.status === "pass").length).toBeGreaterThanOrEqual(15);
  });

  it("says so when the SP isn't registered", async () => {
    await host();
    const r = await json(["smoke", BASE_URL, "--sp", "https://unregistered.test"]);
    expect(r.code).toBe(1);
    expect(failures(r).join()).toMatch(/not registered/);
  });
});

describe("cli: sp-from-metadata", () => {
  it("prints a serviceProviders entry as JSON on stdout", async () => {
    const r = await run(["sp-from-metadata", "test/fixtures/sp-metadata/cloudflare-access.xml", "--id", "cf"]);
    expect(r.code).toBe(0);
    const entry = JSON.parse(r.stdout);
    expect(entry).toMatchObject({ id: "cf", requireSignedAuthnRequests: true });
    expect(entry.acsUrls[0]).toMatch(/cloudflareaccess\.com/);
  });

  it("rejects non-metadata", async () => {
    const r = await run(["sp-from-metadata", file("x.xml", "<a/>")]);
    expect(r.code).toBe(1);
  });
});

describe("cli: check-config", () => {
  const config = (o: Record<string, unknown>) =>
    file(
      `c${Math.random().toString(36).slice(2)}.json`,
      JSON.stringify({
        entityId: "https://auth.test/api/auth/saml2/idp",
        baseURL: "https://auth.test/api/auth",
        loginPage: "/sign-in",
        signing: { privateKey: `file:${file("idp.key", keys.idp.privateKey)}`, certificate: "file:./idp.crt" },
        serviceProviders: [{ id: "s", entityId: SP_ENTITY_ID, acsUrls: [SP_ACS] }],
        ...o,
      }),
    );

  it("a valid config passes and is summarised; file: references resolve relative to the config", async () => {
    const r = await json(["check-config", config({})]);
    expect(r.code).toBe(0);
    expect(r.report.checks[0]).toEqual({ status: "pass", message: "options are valid" });
  });

  it("lists every issue and exits 1", async () => {
    const r = await json(["check-config", config({ loginPage: "//evil.example", serviceProviders: [{ id: "s", entityId: SP_ENTITY_ID, acsUrls: [] }] })]);
    expect(r.code).toBe(1);
    expect(failures(r).length).toBe(2);
    expect(failures(r).join("\n")).toMatch(/loginPage/);
    // Key material is checked once the schema passes.
    const keyMismatch = await json(["check-config", config({ signing: { privateKey: keys.idp.privateKey, certificate: keys.sp.certificate } })]);
    expect(failures(keyMismatch)).toEqual(["signing.certificate: does not match signing.privateKey"]);
  });

  it("reports the SP encryption certificate", async () => {
    const r = await json(["check-config", config({ serviceProviders: [{ id: "s", entityId: SP_ENTITY_ID, acsUrls: [SP_ACS], encryption: { certificate: keys.sp.certificate } }] })]);
    expect(r.code).toBe(0);
    expect(r.report.checks.some((c) => c.status === "pass" && /SP s encryption certificate: valid/.test(c.message))).toBe(true);
  });

  it("warns when baseURL isn't pinned", async () => {
    const r = await json(["check-config", config({ baseURL: undefined })]);
    expect(r.report.checks.some((c) => c.status === "warn" && /baseURL/.test(c.message))).toBe(true);
  });
});

describe("cli: keygen", () => {
  it("writes a certificate and a 0600 key that the plugin accepts", async () => {
    const cert = join(dir, "gen.crt");
    const key = join(dir, "gen.key");
    const r = await run(["keygen", "--cert-out", cert, "--key-out", key, "--cn", "My IdP", "--days", "365", "--bits", "2048"]);
    expect(r.code).toBe(0);
    expect(statSync(key).mode & 0o777).toBe(0o600);
    const x = new X509Certificate(readFileSync(cert));
    expect(x.subject).toBe("CN=My IdP");
    expect(x.verify(x.publicKey)).toBe(true);
    expect(x.publicKey.asymmetricKeyDetails?.modulusLength).toBe(2048);
    const days = (new Date(x.validTo).getTime() - Date.now()) / 86_400_000;
    expect(days).toBeGreaterThan(364);
    expect(days).toBeLessThan(366);
    // The plugin accepts the pair (key matches certificate, RSA, size).
    expect(() => resolveOptions({ entityId: "https://a.test/idp", loginPage: "/l", signing: { privateKey: readFileSync(key, "utf8"), certificate: readFileSync(cert, "utf8") }, serviceProviders: [] })).not.toThrow();
    // Doesn't overwrite without --force.
    expect((await run(["keygen", "--cert-out", cert, "--key-out", key])).code).toBe(2);
  });

  it("without --key-out, the key is the only thing on stdout (for piping into a secret store)", async () => {
    const cert = join(dir, "pipe.crt");
    const r = await run(["keygen", "--cert-out", cert, "--bits", "2048"]);
    expect(r.code).toBe(0);
    expect(r.stdout).toMatch(/^-----BEGIN PRIVATE KEY-----\n[\s\S]+-----END PRIVATE KEY-----\n$/);
    expect(r.stderr).toMatch(/Generated/);
    expect(r.stderr).not.toMatch(/PRIVATE KEY/);
  });

  it("OpenSSL parses the certificate (DER encoding check)", () => {
    const cert = join(dir, "gen.crt");
    const out = spawnSync("openssl", ["x509", "-in", cert, "-noout", "-text"], { encoding: "utf8" });
    if (out.error) return; // no openssl on this machine
    expect(out.status).toBe(0);
    expect(out.stdout).toMatch(/Version: 3/);
    expect(out.stdout).toMatch(/sha256WithRSAEncryption/);
    expect(out.stdout).toMatch(/CA:FALSE/);
    expect(out.stdout).toMatch(/Digital Signature/);
  });
});

