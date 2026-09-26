// Property-based fuzzing of everything that reads attacker-controlled input, and of what the IdP
// issues. Invariants: hostile input only ever yields a clean rejection (never a crash or another
// error type), and whatever the user data, the issued Response is well-formed, schema-valid and
// verifies. Runs: FUZZ_RUNS (default 150).
import { deflateRawSync } from "node:zlib";
import fc from "fast-check";
import { describe, expect, inject, it } from "vitest";
import { compileAttributeMap } from "../../src/attributes";
import { resolveOptions } from "../../src/options";
import { decodeAuthnRequest, logSafe, parseAuthnRequest, parseRedirectQuery, SamlRequestError } from "../../src/saml/request";
import { buildSignedResponse, escapeXml } from "../../src/saml/response";
import { libxml2Validator } from "../../src/saml/validator";
import { parseXmlStrict, XmlParseError } from "../../src/saml/xml";
import { verifyEnvelopedSignature } from "../../src/saml/xmldsig";
import { baseOptions } from "../support/config";

const keys = inject("keys");
const RUNS = Number(process.env.FUZZ_RUNS ?? 150);
// biome-ignore lint/suspicious/noControlCharactersInRegex: the characters XML 1.0 can't carry
const NOT_XML_CHAR_TEST = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\uFFFD-\uFFFF]|[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/g;
const validator = libxml2Validator();
const NS = 'xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"';
const now = new Date("2026-09-26T00:00:30Z");
const VALID =
  `<samlp:AuthnRequest ${NS} ID="_abc" Version="2.0" IssueInstant="2026-09-26T00:00:00Z" ` +
  `Destination="https://idp.test/sso" AssertionConsumerServiceURL="https://sp.test/acs">` +
  `<saml:Issuer>https://sp.test/metadata</saml:Issuer><samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"/></samlp:AuthnRequest>`;

/** Only SamlRequestError (or XmlParseError) may escape, never a TypeError or the like. */
const onlyCleanErrors = async (fn: () => unknown) => {
  try {
    await fn();
  } catch (e) {
    if (!(e instanceof SamlRequestError) && !(e instanceof XmlParseError)) throw e;
  }
};

describe("fuzz: inbound input only ever produces clean rejections", () => {
  it("parseRedirectQuery: any query string", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.oneof(
          fc.string({ maxLength: 400 }),
          fc.array(fc.tuple(fc.constantFrom("SAMLRequest", "RelayState", "SigAlg", "Signature", "SAMLResponse", "Relay%53tate", "x"), fc.string({ maxLength: 60 })), { maxLength: 6 }).map((ps) => ps.map(([k, v]) => `${k}=${v}`).join("&")),
        ),
        (q) => onlyCleanErrors(() => parseRedirectQuery(q)),
      ),
      { numRuns: RUNS },
    );
  });

  it("decodeAuthnRequest: any base64, any DEFLATE, either binding", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.oneof(
          fc.string({ maxLength: 300 }),
          fc.uint8Array({ maxLength: 300 }).map((b) => Buffer.from(b).toString("base64")),
          fc.uint8Array({ maxLength: 300 }).map((b) => deflateRawSync(b).toString("base64")),
          fc.string({ maxLength: 300 }).map((s) => deflateRawSync(Buffer.from(s)).toString("base64")),
        ),
        fc.constantFrom("redirect" as const, "post" as const),
        (samlRequest, binding) => onlyCleanErrors(() => decodeAuthnRequest({ binding, samlRequest, relayState: undefined })),
      ),
      { numRuns: RUNS },
    );
  });

  it("parseAuthnRequest: random insertions, deletions and replacements in a valid request", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.array(fc.tuple(fc.nat(), fc.constantFrom("insert", "delete", "replace"), fc.string({ minLength: 1, maxLength: 12 })), { minLength: 1, maxLength: 4 }),
        async (edits) => {
          let xml = VALID;
          for (const [pos, op, text] of edits) {
            const at = pos % (xml.length + 1);
            xml = op === "insert" ? xml.slice(0, at) + text + xml.slice(at) : op === "delete" ? xml.slice(0, at) + xml.slice(at + text.length) : xml.slice(0, at) + text + xml.slice(at + text.length);
          }
          await onlyCleanErrors(async () => {
            const info = await parseAuthnRequest(xml, validator, { now, clockSkewSeconds: 60, ssoUrl: "https://idp.test/sso" });
            // Anything accepted must still be a coherent request.
            expect(info.issuer.length).toBeGreaterThan(0);
            expect(info.id.length).toBeGreaterThan(0);
          });
        },
      ),
      { numRuns: RUNS },
    );
  });

  it("parseXmlStrict: any string, bounded time", () => {
    fc.assert(
      fc.property(fc.oneof(fc.string({ maxLength: 2000 }), fc.string({ maxLength: 200 }).map((s) => `<a ${s}>`), fc.string({ maxLength: 200 }).map((s) => `<a xmlns:p="u" p:x="1" ${s}/>`)), (s) => {
        const t = performance.now();
        try {
          parseXmlStrict(s);
        } catch (e) {
          if (!(e instanceof XmlParseError)) throw e;
        }
        return performance.now() - t < 500;
      }),
      { numRuns: RUNS * 2 },
    );
  });

  it("logSafe: never returns control characters, always bounded", () => {
    fc.assert(
      fc.property(fc.string({ maxLength: 500 }), fc.integer({ min: 1, max: 200 }), (s, max) => {
        const out = logSafe(s, max);
        // biome-ignore lint/suspicious/noControlCharactersInRegex: checking for control characters
        return !/[\u0000-\u001f\u007f]/.test(out) && out.length <= max + 1;
      }),
      { numRuns: RUNS },
    );
  });

  it("escapeXml: output never contains markup characters unescaped, nor characters XML can't carry", () => {
    fc.assert(
      fc.property(fc.string({ unit: "binary", maxLength: 200 }), (s) => {
        const out = escapeXml(s);
        NOT_XML_CHAR_TEST.lastIndex = 0;
        return !/[<>"'\r]|&(?!(amp|lt|gt|quot|apos);)/.test(out) && !NOT_XML_CHAR_TEST.test(out);
      }),
      { numRuns: RUNS },
    );
  });
});

describe("fuzz: whatever the user data, the issued Response is valid and verifies", () => {
  const options = resolveOptions(baseOptions());
  // User data may contain anything a database can hold: unicode, markup, quotes, C0 controls,
  // U+FFFE/U+FFFF and lone surrogates (the last three found the D-036 bug).
  const hostile = fc.constantFrom("\u0000", "\u0001", "\u0008", "\u000b", "\u001f", "\u007f", "\ufffd", "\ufffe", "\uffff", "\ud800", "\udc00", "<", "&", '"', "'", "]]>", "\t", "\n", "\r", "\u0085", "\u2028", "\u2029");
  const userText = fc.oneof(
    fc.string({ unit: "grapheme", maxLength: 60 }),
    fc.array(fc.oneof(fc.string({ unit: "grapheme", maxLength: 4 }), hostile), { maxLength: 20 }).map((parts) => parts.join("")),
  );
  const asSent = (v: string) => v.replace(NOT_XML_CHAR_TEST, "").replace(/\r[\n\u0085]?|[\u0085\u2028\u2029]/g, "\n");

  it("NameID and attribute values round-trip exactly (or are refused), and the Response stays schema-valid and signed", async () => {
    await fc.assert(
      fc.asyncProperty(userText, fc.array(fc.tuple(fc.stringMatching(/^[A-Za-z][A-Za-z0-9._:-]{0,20}$/), userText), { maxLength: 4 }), async (nameId, attrs) => {
        if (nameId.length === 0) return true;
        const attributes = Object.fromEntries(attrs);
        let built: ReturnType<typeof buildSignedResponse>;
        try {
          built = buildSignedResponse(options, {
            requestId: "_r1",
            acsUrl: "https://sp.test/acs",
            audience: "https://sp.test/metadata",
            nameId,
            nameIdFormat: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
            attributes,
            authnInstant: now,
            sessionIndex: "_s",
            now,
          });
        } catch {
          return true; // refusing to build is acceptable; producing a broken document is not
        }
        const xml = built.xml;
        const doc = parseXmlStrict(xml); // must be well-formed
        expect(await validator.validate(xml, "protocol")).toEqual({ valid: true });
        const root = doc.documentElement as any;
        const assertion = root.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:assertion", "Assertion")[0];
        expect(verifyEnvelopedSignature(xml, doc, root, [keys.idp.certificate], { allowSha1: false }).valid).toBe(true);
        expect(verifyEnvelopedSignature(xml, doc, assertion, [keys.idp.certificate], { allowSha1: false }).valid).toBe(true);
        // (The IdP refuses such NameIDs before building; here buildSignedResponse sees them raw.)
        expect(root.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:assertion", "NameID")[0].textContent).toBe(asSent(nameId));
        const got: Record<string, string> = {};
        for (const a of Array.from(root.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:assertion", "Attribute") as ArrayLike<any>))
          got[a.getAttribute("Name")] = a.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:assertion", "AttributeValue")[0].textContent;
        for (const [k, v] of Object.entries(attributes)) expect(got[k]).toBe(asSent(v));
        // The bytes actually sent (UTF-8, as in the POST form) still verify.
        const sent = new TextDecoder().decode(Buffer.from(built.base64, "base64"));
        const sentDoc = parseXmlStrict(sent);
        expect(verifyEnvelopedSignature(sent, sentDoc, sentDoc.documentElement, [keys.idp.certificate], { allowSha1: false }).valid).toBe(true);
        return true;
      }),
      { numRuns: RUNS },
    );
  });

  it("attribute maps never throw on any user object, and only emit strings or string arrays", () => {
    const map = compileAttributeMap({
      a: "anything",
      b: { field: "anything", split: "," },
      c: { field: "anything", part: "first" },
      d: { field: "other", part: "last" },
      e: { value: ["x", "y"] },
      f: { organization: "roles" },
    });
    fc.assert(
      fc.property(fc.dictionary(fc.constantFrom("anything", "other", "__proto__", "constructor"), fc.anything()), (user) => {
        const out = map(user as any, { organizations: [], organization: undefined });
        return Object.values(out).every((v) => typeof v === "string" || (Array.isArray(v) && v.every((x) => typeof x === "string")));
      }),
      { numRuns: RUNS },
    );
  });
});
