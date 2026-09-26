// Property-based fuzzing of the XML signature verifier (D-025): whatever an attacker does to a
// correctly signed message, it must never verify. Runs: FUZZ_RUNS (default 150).
import fc from "fast-check";
import { SignedXml } from "xml-crypto";
import { describe, expect, inject, it } from "vitest";
import { parseXmlStrict } from "../../src/saml/xml";
import { verifyEnvelopedSignature } from "../../src/saml/xmldsig";

const keys = inject("keys");
const RUNS = Number(process.env.FUZZ_RUNS ?? 150);
const EXC = "http://www.w3.org/2001/10/xml-exc-c14n#";
const NS = 'xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"';

function signed(id = "_orig") {
  const xml =
    `<samlp:AuthnRequest ${NS} ID="${id}" Version="2.0" IssueInstant="2026-09-26T00:00:00Z" ` +
    `Destination="https://idp.test/sso" AssertionConsumerServiceURL="https://sp.test/acs">` +
    `<saml:Issuer>https://sp.test/metadata</saml:Issuer></samlp:AuthnRequest>`;
  const sig = new SignedXml({ privateKey: keys.sp.privateKey, signatureAlgorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", canonicalizationAlgorithm: EXC });
  sig.addReference({ xpath: "/*", transforms: ["http://www.w3.org/2000/09/xmldsig#enveloped-signature", EXC], digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256" });
  sig.computeSignature(xml, { prefix: "ds", location: { reference: "/*/*[local-name(.)='Issuer']", action: "after" } });
  return sig.getSignedXml();
}

const ORIGINAL = signed();
const SIG = /<ds:Signature[\s\S]*<\/ds:Signature>/.exec(ORIGINAL)![0];

/** Does `xml` verify as a signed root element? A parse failure counts as "no". */
function verifies(xml: string): boolean {
  let doc: ReturnType<typeof parseXmlStrict>;
  try {
    doc = parseXmlStrict(xml);
  } catch {
    return false;
  }
  return verifyEnvelopedSignature(xml, doc, doc.documentElement, [keys.sp.certificate], { allowSha1: false }).valid === true;
}

// Characters that keep a document well-formed inside attribute values and text.
const safeChar = fc.stringMatching(/^[A-Za-z0-9_.:/ -]$/);
const idChars = fc.stringMatching(/^_[A-Za-z0-9]{1,12}$/);

describe("fuzz: the XML signature verifier", () => {
  it("sanity: the untouched signed request verifies", () => {
    expect(verifies(ORIGINAL)).toBe(true);
  });

  it("changing any character of any signed value (root attributes, Issuer) never verifies", () => {
    // Spans of signed content: every root attribute value, and the Issuer text.
    const root = /^<samlp:AuthnRequest [^>]*>/.exec(ORIGINAL)![0];
    const spans: [number, number][] = [];
    for (const m of root.matchAll(/="([^"]*)"/g)) spans.push([m.index! + 2, m.index! + 2 + m[1]!.length]);
    const issuer = /<saml:Issuer>([^<]*)<\/saml:Issuer>/.exec(ORIGINAL)!;
    spans.push([issuer.index! + "<saml:Issuer>".length, issuer.index! + "<saml:Issuer>".length + issuer[1]!.length]);
    fc.assert(
      fc.property(fc.integer({ min: 0, max: spans.length - 1 }), fc.nat(), safeChar, (s, offset, ch) => {
        const [a, b] = spans[s]!;
        if (b === a) return true;
        const at = a + (offset % (b - a));
        if (ORIGINAL[at] === ch) return true; // not a change
        const mutated = ORIGINAL.slice(0, at) + ch + ORIGINAL.slice(at + 1);
        return !verifies(mutated);
      }),
      { numRuns: RUNS },
    );
  });

  it("wrapping the signed request anywhere inside an attacker's request never verifies the outer one", () => {
    const inner = ORIGINAL.replace(SIG, "");
    fc.assert(
      fc.property(
        idChars,
        fc.constantFrom("samlp:Extensions", "x:w", "x:a"),
        fc.integer({ min: 0, max: 3 }),
        fc.boolean(),
        (outerId, wrapper, depth, keepOrigId) => {
          const id = keepOrigId ? "_orig" : outerId;
          let payload = inner;
          for (let i = 0; i < depth; i++) payload = `<x:d${i} xmlns:x="urn:x">${payload}</x:d${i}>`;
          const wrapped = wrapper.startsWith("samlp") ? `<${wrapper}><x:w xmlns:x="urn:x">${payload}</x:w></${wrapper}>` : `<${wrapper} xmlns:x="urn:x">${payload}</${wrapper}>`;
          const attack =
            `<samlp:AuthnRequest ${NS} ID="${id}" Version="2.0" IssueInstant="2026-09-26T00:00:00Z" ForceAuthn="true">` +
            `<saml:Issuer>https://sp.test/metadata</saml:Issuer>${SIG}${wrapped}</samlp:AuthnRequest>`;
          return !verifies(attack);
        },
      ),
      { numRuns: RUNS },
    );
  });

  it("adding an element carrying the signed ID (ID, Id or id, any namespace, any position) never verifies", () => {
    fc.assert(
      fc.property(fc.constantFrom("ID", "Id", "id", "x:ID", "x:Id"), fc.constantFrom("afterIssuer", "end", "inIssuer"), (attr, where) => {
        const el = `<x:c xmlns:x="urn:x" ${attr}="_orig"/>`;
        const xml =
          where === "afterIssuer"
            ? ORIGINAL.replace("</saml:Issuer>", `</saml:Issuer>${el}`)
            : where === "end"
              ? ORIGINAL.replace("</samlp:AuthnRequest>", `${el}</samlp:AuthnRequest>`)
              : ORIGINAL.replace("<saml:Issuer>", `<saml:Issuer>${el}`);
        return !verifies(xml);
      }),
      { numRuns: RUNS },
    );
  });

  it("moving, duplicating or re-parenting the Signature never verifies", () => {
    const withoutSig = ORIGINAL.replace(SIG, "");
    fc.assert(
      fc.property(fc.constantFrom("dup", "inIssuer", "end", "wrapped", "twiceNested"), (how) => {
        const xml =
          how === "dup"
            ? ORIGINAL.replace(SIG, SIG + SIG)
            : how === "inIssuer"
              ? withoutSig.replace("</saml:Issuer>", `${SIG}</saml:Issuer>`)
              : how === "end"
                ? withoutSig.replace("</samlp:AuthnRequest>", `<x:e xmlns:x="urn:x">${SIG}</x:e></samlp:AuthnRequest>`)
                : how === "wrapped"
                  ? withoutSig.replace("</saml:Issuer>", `</saml:Issuer><x:w xmlns:x="urn:x">${SIG}</x:w>`)
                  : ORIGINAL.replace(SIG, `${SIG}<x:w xmlns:x="urn:x"><x:v>${SIG}</x:v></x:w>`);
        return !verifies(xml);
      }),
      { numRuns: RUNS },
    );
  });

  it("any random byte flip anywhere never produces a verified *different* document", () => {
    // A flip may land in insignificant whitespace between attributes, or turn base64 padding in the
    // SignatureValue into whitespace (same signature bytes), and still verify; that's fine as long
    // as what the application reads (the signed content, outside the Signature) is unchanged.
    const canonical = (xml: string) => {
      const d = parseXmlStrict(xml).documentElement as any;
      const content = Array.from(d.childNodes as ArrayLike<any>)
        .filter((n) => n.localName !== "Signature")
        .map((n) => n.textContent)
        .join("");
      return [d.getAttribute("ID"), d.getAttribute("Destination"), d.getAttribute("AssertionConsumerServiceURL"), d.getAttribute("IssueInstant"), content].join("|");
    };
    const expected = canonical(ORIGINAL);
    fc.assert(
      fc.property(fc.nat({ max: ORIGINAL.length - 1 }), fc.integer({ min: 32, max: 126 }), (at, code) => {
        const mutated = ORIGINAL.slice(0, at) + String.fromCharCode(code) + ORIGINAL.slice(at + 1);
        if (!verifies(mutated)) return true;
        return canonical(mutated) === expected;
      }),
      { numRuns: RUNS * 4 },
    );
  });
});
