import { describe, expect, it } from "vitest";
import { precheckXml, libxml2Validator } from "../../src/saml/validator";

const validator = libxml2Validator();

const authnRequest = (inner = "", attrs = "") =>
  `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_abc123" Version="2.0" IssueInstant="2026-09-24T10:00:00Z" AssertionConsumerServiceURL="https://sp.test/acs"${attrs}><saml:Issuer>https://sp.test/metadata</saml:Issuer>${inner}</samlp:AuthnRequest>`;

describe("libxml2Validator", { timeout: 60_000 }, () => {
  it("accepts a schema-valid AuthnRequest", async () => {
    expect(await validator.validate(authnRequest(), "protocol")).toEqual({ valid: true });
  });

  it("rejects a document with exactly one schema error (not swallowed by node-xmllint's line trimming)", async () => {
    const r = await validator.validate(authnRequest("", ' Bogus="1"'), "protocol");
    expect(r.valid).toBe(false);
    if (!r.valid) expect(r.errors.join("\n")).toMatch(/Bogus/);
  });

  it("rejects an unexpected child element", async () => {
    const r = await validator.validate(authnRequest("<samlp:Nope/>"), "protocol");
    expect(r.valid).toBe(false);
  });

  it("rejects a missing required attribute", async () => {
    const r = await validator.validate(authnRequest().replace(' Version="2.0"', ""), "protocol");
    expect(r.valid).toBe(false);
  });

  it("rejects an element from the wrong schema kind", async () => {
    const r = await validator.validate(authnRequest(), "metadata");
    expect(r.valid).toBe(false);
  });

  it.each([
    ["empty string", ""],
    ["plain text", "hello"],
    ["truncated", authnRequest().slice(0, 60)],
    ["mismatched tag", "<a><b></a>"],
    ["unbound prefix", "<samlp:AuthnRequest/>"],
  ])("rejects non-well-formed input: %s", async (_, xml) => {
    const r = await validator.validate(xml, "protocol");
    expect(r.valid).toBe(false);
    if (!r.valid) expect(r.errors.length).toBeGreaterThan(0);
  });

  it("rejects DOCTYPE and ENTITY before parsing", async () => {
    const xxe = `<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]>${authnRequest()}`;
    const r = await validator.validate(xxe, "protocol");
    expect(r).toEqual({ valid: false, errors: ["DOCTYPE is not allowed", "ENTITY declarations are not allowed"] });
  });

  it("rejects oversized documents before parsing", async () => {
    const small = libxml2Validator({ maxBytes: 100 });
    const r = await small.validate(authnRequest(), "protocol");
    expect(r).toEqual({ valid: false, errors: ["document exceeds 100 bytes"] });
  });

  it("precheck counts bytes, not UTF-16 code units", () => {
    expect(precheckXml("é".repeat(60), 100)).toEqual(["document exceeds 100 bytes"]);
  });

  it("keeps working across validator instances (each instance loads its own wasm)", async () => {
    for (let i = 0; i < 3; i++) {
      expect(await libxml2Validator().validate(authnRequest(), "protocol")).toEqual({ valid: true });
    }
  });

  it("does not add process-wide listeners or write to stdout per call", async () => {
    const proc = (globalThis as any).process;
    const before = proc?.listenerCount?.("uncaughtException") ?? 0;
    const write = proc?.stdout?.write;
    let writes = 0;
    if (write) proc.stdout.write = (...a: unknown[]) => {
        writes++;
        return write.apply(proc.stdout, a);
      };
    try {
      for (let i = 0; i < 5; i++) await validator.validate(authnRequest(), "protocol");
    } finally {
      if (write) proc.stdout.write = write;
    }
    expect(proc?.listenerCount?.("uncaughtException") ?? 0).toBe(before);
    expect(writes).toBe(0);
  });
});
