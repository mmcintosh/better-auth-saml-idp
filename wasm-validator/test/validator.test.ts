import { beforeAll, describe, expect, inject, it, vi } from "vitest";
import * as samlify from "samlify";
import { createWasmValidator, EXPECTED_IMPORTS, type WasmValidator } from "../../src/saml/wasm/validator";
import { isWorkerd, loadWasm } from "./load";

const RUNTIME = isWorkerd ? "workerd" : "node";
const keys = inject("keys");

const P = "urn:oasis:names:tc:SAML:2.0:protocol";
const A = "urn:oasis:names:tc:SAML:2.0:assertion";
const authnRequest = (attrs = `ID="_abc123" Version="2.0" IssueInstant="2026-09-24T10:00:00Z"`, body = `<saml:Issuer>https://sp.test/metadata</saml:Issuer>`) =>
  `<samlp:AuthnRequest xmlns:samlp="${P}" xmlns:saml="${A}" ${attrs}>${body}</samlp:AuthnRequest>`;
const VALID = authnRequest();

let wasm: WebAssembly.Module | Uint8Array<ArrayBuffer>;
let v: WasmValidator;

beforeAll(async () => {
  wasm = await loadWasm();
  v = createWasmValidator(wasm);
  const t0 = performance.now();
  await v.ready();
  console.log(`[${RUNTIME}] instantiate + compile both schema sets: ${(performance.now() - t0).toFixed(1)} ms (in-runtime timer)`);
});

function invalid(r: Awaited<ReturnType<WasmValidator["validate"]>>): string[] {
  expect(r.valid).toBe(false);
  return r.valid ? [] : r.errors;
}

describe(`wasm module (${RUNTIME})`, () => {
  it("imports exactly the expected WASI/env functions", async () => {
    const mod = wasm instanceof WebAssembly.Module ? wasm : await WebAssembly.compile(wasm);
    const imports = WebAssembly.Module.imports(mod).map((i) => `${i.module}.${i.name}`).sort();
    expect(imports).toEqual([...EXPECTED_IMPORTS].sort());
    const exports = WebAssembly.Module.exports(mod).map((e) => e.name);
    expect(exports).toContain("xv_validate");
  });

  it.runIf(isWorkerd)("runs where runtime wasm code generation is forbidden", async () => {
    // The smallest valid module: proves this isolate really forbids codegen,
    // so every passing test here ran without it.
    const empty = new Uint8Array([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]);
    await expect(WebAssembly.compile(empty)).rejects.toThrow(/Wasm code generation disallowed by embedder/);
    expect(wasm).toBeInstanceOf(WebAssembly.Module);
  });

  it("resolves schema imports only from the in-memory registry", async () => {
    const XS = "http://www.w3.org/2001/XMLSchema";
    const entry = (loc: string) =>
      `<schema xmlns="${XS}" xmlns:e="urn:evil" targetNamespace="${P}"><import namespace="urn:evil" schemaLocation="${loc}"/>` +
      `<element name="AuthnRequest" type="e:T"/></schema>`;
    for (const loc of ["http://evil.test/x.xsd", "file:///etc/passwd", "/etc/passwd", "../src/saml/schemas.generated.ts"]) {
      const custom = createWasmValidator(wasm, { "saml-schema-protocol-2.0.xsd": entry(loc) });
      await expect(custom.validate(VALID, "protocol")).rejects.toThrow(/compiling protocol schemas failed/);
      await expect(custom.validate(VALID, "protocol")).rejects.toThrow(new RegExp(`failed to load "${loc.replace(/[./]/g, "\\$&")}"`));
      expect(custom.stats().stdioBytes).toBe(0);
    }
    // ... and a registered name resolves.
    const ok = createWasmValidator(wasm, {
      "saml-schema-protocol-2.0.xsd": entry("t.xsd"),
      "t.xsd": `<schema xmlns="${XS}" targetNamespace="urn:evil"><complexType name="T"><sequence><any processContents="skip" minOccurs="0" maxOccurs="unbounded"/></sequence><anyAttribute processContents="skip"/></complexType></schema>`,
    });
    expect(await ok.validate(VALID, "protocol")).toEqual({ valid: true });
  });

  it("rejects prototype keys as schema kinds", async () => {
    expect(invalid(await v.validate(VALID, "toString" as never))).toEqual(["unknown schema kind: toString"]);
  });

  it.runIf(!isWorkerd)("wasm/xsd.wasm matches wasm/xsd.wasm.sha256", async () => {
    const { readFile } = await import("node:fs/promises");
    const { createHash } = await import("node:crypto");
    const bin = await readFile(new URL("../../wasm/xsd.wasm", import.meta.url));
    const recorded = (await readFile(new URL("../../wasm/xsd.wasm.sha256", import.meta.url), "utf8")).split(/\s+/)[0];
    expect(createHash("sha256").update(bin).digest("hex")).toBe(recorded);
  });

  it.runIf(!isWorkerd)("does not cache a failed WebAssembly.compile", async () => {
    // Node only: workerd forbids compiling bytes, so there the loader is always given a Module.
    expect(wasm).toBeInstanceOf(Uint8Array);
    const spy = vi.spyOn(WebAssembly, "compile").mockRejectedValueOnce(new Error("transient compile failure"));
    try {
      const fresh = createWasmValidator(wasm);
      await expect(fresh.validate(VALID, "protocol")).rejects.toThrow("transient compile failure");
      expect(await fresh.validate(VALID, "protocol")).toEqual({ valid: true });
      expect(spy).toHaveBeenCalledTimes(2);
      expect(fresh.stats().instantiations).toBe(1);
    } finally {
      spy.mockRestore();
    }
  });

  it("rejects invalid wasm bytes (and keeps rejecting, without caching a stale module)", async () => {
    const bad = createWasmValidator(new Uint8Array([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0xff]));
    await expect(bad.validate(VALID, "protocol")).rejects.toThrow();
    await expect(bad.validate(VALID, "protocol")).rejects.toThrow();
    expect(bad.stats().instantiations).toBe(0);
  });

  it("instantiates once even with concurrent first calls", async () => {
    const fresh = createWasmValidator(wasm);
    const results = await Promise.all(Array.from({ length: 5 }, () => fresh.validate(VALID, "protocol")));
    expect(results.every((r) => r.valid)).toBe(true);
    expect(fresh.stats().instantiations).toBe(1);
  });
});

describe(`protocol schema (${RUNTIME})`, () => {
  it("accepts a valid AuthnRequest", async () => {
    expect(await v.validate(VALID, "protocol")).toEqual({ valid: true });
  });

  it("rejects a single schema error with a message", async () => {
    const errors = invalid(await v.validate(authnRequest(`ID="_abc123" Version="2.0" IssueInstant="yesterday"`), "protocol"));
    expect(errors).toHaveLength(1);
    expect(errors[0]).toMatch(/IssueInstant.*'yesterday' is not a valid value of the atomic type 'xs:dateTime'/);
  });

  it("rejects an unexpected child element", async () => {
    const errors = invalid(await v.validate(authnRequest(undefined, `<samlp:Bogus/><saml:Issuer>x</saml:Issuer>`), "protocol"));
    expect(errors.join("\n")).toMatch(/Element '\{urn:oasis:names:tc:SAML:2.0:protocol\}Bogus': This element is not expected/);
  });

  it("rejects a missing required attribute", async () => {
    const errors = invalid(await v.validate(authnRequest(`Version="2.0" IssueInstant="2026-09-24T10:00:00Z"`), "protocol"));
    expect(errors.join("\n")).toMatch(/The attribute 'ID' is required but missing/);
  });

  it("rejects an ID that is not an xs:ID", async () => {
    const errors = invalid(await v.validate(authnRequest(`ID="123" Version="2.0" IssueInstant="2026-09-24T10:00:00Z"`), "protocol"));
    expect(errors.join("\n")).toMatch(/'123' is not a valid value of the atomic type 'xs:ID'/);
  });

  it("rejects a document of the wrong schema kind", async () => {
    const errors = invalid(await v.validate(VALID, "metadata"));
    expect(errors.join("\n")).toMatch(/No matching global declaration available for the validation root/);
    const md = `<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://x"/>`;
    expect(invalid(await v.validate(md, "protocol")).join("\n")).toMatch(/No matching global declaration/);
  });

  it("rejects an unknown kind without touching wasm", async () => {
    expect(invalid(await v.validate(VALID, "assertion" as never))).toEqual(["unknown schema kind: assertion"]);
  });

  it("forces UTF-8 regardless of the declared encoding", async () => {
    const xml = `<?xml version="1.0" encoding="ISO-8859-1"?>` + authnRequest(undefined, `<saml:Issuer>héllo €</saml:Issuer>`);
    expect(await v.validate(xml, "protocol")).toEqual({ valid: true });
  });
});

describe(`non-well-formed input (${RUNTIME})`, () => {
  const cases: [string, string, RegExp][] = [
    ["empty", "", /empty document/],
    ["plain text", "hello world", /Start tag expected/],
    ["truncated", VALID.slice(0, VALID.indexOf("</saml:Issuer>")), /Premature end of data/],
    ["mismatched tag", `<samlp:AuthnRequest xmlns:samlp="${P}"><a></b></samlp:AuthnRequest>`, /Opening and ending tag mismatch/],
    ["unbound prefix", `<samlp:AuthnRequest ID="_a" Version="2.0" IssueInstant="2026-09-24T10:00:00Z"/>`, /Namespace prefix samlp .* is not defined/],
    ["two roots", `${VALID}${VALID}`, /Extra content at the end of the document/],
    ["NUL byte", `<a>\u0000</a>`, /Char 0x0 out of allowed range|invalid character/i],
  ];
  for (const [name, xml, re] of cases) {
    it(`rejects ${name}`, async () => {
      const errors = invalid(await v.validate(xml, "protocol"));
      expect(errors.join("\n")).toMatch(re);
    });
  }
});

describe(`namespace well-formedness (${RUNTIME})`, () => {
  // Each bad construct sits inside <samlp:Extensions> (xs:any ##other, lax) on an
  // element with no schema, so schema validation alone would accept the document:
  // only the parser's namespace well-formedness check (nsWellFormed) rejects it.
  const ext = (inner: string) => authnRequest(undefined, `<saml:Issuer>x</saml:Issuer><samlp:Extensions>${inner}</samlp:Extensions>`);
  it("accepts the well-formed control document", async () => {
    expect(await v.validate(ext(`<e:x xmlns:e="urn:ext" e:a="1"/>`), "protocol")).toEqual({ valid: true });
  });
  const cases: [string, string, RegExp][] = [
    ["an unbound prefix on an attribute", `<e:x xmlns:e="urn:ext" foo:a="1"/>`, /Namespace prefix foo for a on x is not defined/],
    ["duplicate namespaced attributes via two prefixes", `<e:x xmlns:e="urn:ext" xmlns:a="urn:dup" xmlns:b="urn:dup" a:x="1" b:x="2"/>`, /Namespaced Attribute x in 'urn:dup' redefined/],
    ["the xml prefix bound to the wrong URI", `<e:x xmlns:e="urn:ext" xmlns:xml="urn:wrong"/>`, /xml namespace prefix mapped to wrong URI/],
    ["the xmlns prefix declared", `<e:x xmlns:e="urn:ext" xmlns:xmlns="urn:wrong"/>`, /redefinition of the xmlns prefix is forbidden/],
    ["an empty prefixed namespace declaration", `<e:x xmlns:e="urn:ext" xmlns:p=""/>`, /xmlns:p: Empty XML namespace is not allowed/],
  ];
  for (const [name, inner, re] of cases) {
    it(`rejects ${name}`, async () => {
      const errors = invalid(await v.validate(ext(inner), "protocol"));
      expect(errors.join("\n")).toMatch(re);
    });
  }
});

describe(`DOCTYPE and entities (${RUNTIME})`, () => {
  const cases: [string, string][] = [
    ["internal entity", `<!DOCTYPE r [<!ENTITY x "y">]>${authnRequest(undefined, "<saml:Issuer>&x;</saml:Issuer>")}`],
    ["external entity (XXE)", `<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]>${authnRequest(undefined, "<saml:Issuer>&x;</saml:Issuer>")}`],
    ["billion laughs", `<!DOCTYPE r [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;"><!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;"><!ENTITY d "&c;&c;&c;&c;&c;&c;&c;&c;&c;&c;">]>${authnRequest(undefined, "<saml:Issuer>&d;&d;&d;</saml:Issuer>")}`],
    ["parameter entity", `<!DOCTYPE r [<!ENTITY % p SYSTEM "http://evil.test/x.dtd"> %p;]>${VALID}`],
    ["external DTD", `<!DOCTYPE samlp:AuthnRequest SYSTEM "http://evil.test/x.dtd">${VALID}`],
    ["bare DOCTYPE", `<!DOCTYPE samlp:AuthnRequest>${VALID}`],
  ];
  for (const [name, xml] of cases) {
    it(`rejects ${name}`, async () => {
      expect(invalid(await v.validate(xml, "protocol"))).toEqual(["DOCTYPE is not allowed"]);
    });
  }

  it("rejects undeclared entity references without a DOCTYPE", async () => {
    const errors = invalid(await v.validate(authnRequest(undefined, "<saml:Issuer>&x;</saml:Issuer>"), "protocol"));
    expect(errors.join("\n")).toMatch(/Entity 'x' not defined/);
  });

  it("ignores xsi:schemaLocation hints (nothing is fetched, schema is fixed)", async () => {
    const xml = authnRequest(`ID="_a" Version="2.0" IssueInstant="2026-09-24T10:00:00Z" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="${P} http://evil.test/p.xsd"`);
    expect(await v.validate(xml, "protocol")).toEqual({ valid: true });
  });

  it("survives very deep nesting without trapping", async () => {
    const depth = 5000;
    const xml = authnRequest(undefined, "<saml:Issuer>x</saml:Issuer>" + "<a>".repeat(depth) + "</a>".repeat(depth));
    const errors = invalid(await v.validate(xml, "protocol"));
    expect(errors.join("\n")).toMatch(/depth|not expected/i);
    expect(await v.validate(VALID, "protocol")).toEqual({ valid: true });
    expect(v.stats().instantiations).toBe(1);
  });
});

describe(`samlify interop (${RUNTIME})`, () => {
  let idp: ReturnType<typeof samlify.IdentityProvider>;
  let sp: ReturnType<typeof samlify.ServiceProvider>;

  beforeAll(() => {
    // samlify's validator contract: resolve on success, reject on failure.
    samlify.setSchemaValidator({
      validate: async (xml: string) => {
        const kind = /<(\w+:)?EntityDescriptor[\s>]/.test(xml) ? "metadata" : "protocol";
        const r = await v.validate(xml, kind);
        if (!r.valid) throw new Error(r.errors.join("\n"));
        return "SUCCESS_VALIDATE_XML";
      },
    });
    idp = samlify.IdentityProvider({
      entityID: "https://idp.test/saml2/idp",
      privateKey: keys.idp.privateKey,
      signingCert: keys.idp.certificate,
      isAssertionEncrypted: false,
      wantAuthnRequestsSigned: false,
      singleSignOnService: [{ Binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", Location: "https://idp.test/sso" }],
      nameIDFormat: ["urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"],
    });
    sp = samlify.ServiceProvider({
      entityID: "https://sp.test/metadata",
      authnRequestsSigned: false,
      wantAssertionsSigned: true,
      wantMessageSigned: true,
      signingCert: keys.sp.certificate,
      assertionConsumerService: [{ Binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", Location: "https://sp.test/acs" }],
    });
  });

  async function issue() {
    const { context } = sp.createLoginRequest(idp, "redirect") as { context: string };
    const url = new URL(context);
    const req = await idp.parseLoginRequest(sp, "redirect", { query: Object.fromEntries(url.searchParams), octetString: url.search.slice(1) });
    const res = (await idp.createLoginResponse(sp, req as never, "post", { email: "alice@example.com" })) as { context: string };
    return res.context;
  }

  it("accepts a samlify-generated signed Response, end to end through a strict SP", async () => {
    const samlResponse = await issue(); // IdP-side parseLoginRequest validated the AuthnRequest with us
    const xml = atob(samlResponse);
    expect(xml).toContain("<ds:Signature");
    expect(await v.validate(xml, "protocol")).toEqual({ valid: true });
    const parsed = await sp.parseLoginResponse(idp, "post", { body: { SAMLResponse: samlResponse } });
    expect(parsed.extract.nameID).toBe("alice@example.com");
  });

  it("rejects a schema-invalid variant of that Response", async () => {
    const xml = atob(await issue()).replace("<saml:Issuer", "<samlp:Bogus/><saml:Issuer");
    expect(invalid(await v.validate(xml, "protocol")).join("\n")).toMatch(/Bogus': This element is not expected/);
  });

  it("accepts IdP and SP metadata on the metadata kind", async () => {
    for (const md of [idp.getMetadata(), sp.getMetadata()]) {
      expect(await v.validate(md, "metadata")).toEqual({ valid: true });
      expect((await v.validate(md, "protocol")).valid).toBe(false);
    }
  });
});

describe(`resource use (${RUNTIME})`, () => {
  it("200 sequential validations do not leak", async () => {
    const bad = authnRequest(undefined, `<samlp:Bogus/>`);
    const doctype = `<!DOCTYPE r [<!ENTITY x "y">]>${VALID}`;
    const round = async () => {
      expect((await v.validate(VALID, "protocol")).valid).toBe(true);
      expect((await v.validate(bad, "protocol")).valid).toBe(false);
      expect((await v.validate("<a><b></a>", "protocol")).valid).toBe(false);
      expect((await v.validate(doctype, "protocol")).valid).toBe(false);
    };
    await round(); // warm up
    const before = v.stats();
    for (let i = 0; i < 200; i++) await round();
    const after = v.stats();
    console.log(
      `[${RUNTIME}] 800 validations: heapUsed ${before.heapUsed} -> ${after.heapUsed} B, ` +
        `linear memory ${before.memoryBytes} -> ${after.memoryBytes} B, stdio bytes ${after.stdioBytes}`,
    );
    expect(after.heapUsed).toBe(before.heapUsed);
    expect(after.memoryBytes).toBe(before.memoryBytes);
    expect(after.stdioBytes).toBe(0);
    expect(after.instantiations).toBe(1);
  });

  it("never writes to stdout/stderr", () => {
    expect(v.stats().stdioBytes).toBe(0);
  });
});
