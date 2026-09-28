// Second review 4 report, R4-1: the duplicate-expanded-name scanner (R3-7, D-037) tokenises attributes on XML whitespace
// only, but xmldom tokenises on JavaScript `\s`. An attribute separated by a character that is
// `\s` but not XML whitespace (LINE/PARAGRAPH SEPARATOR, form feed, vertical tab, NEL) or by NUL
// is invisible to the scanner and visible to xmldom, so `parseXmlStrict` accepts a document in
// which xmldom 0.9 keeps one attribute and xml-crypto's xmldom 0.8 keeps both: exactly the
// divergence the scanner exists to refuse. libxml2 refuses all of these, so the protocol paths
// (which validate first) are covered; the CLI's `decode`, hosts with their own `schemaValidator`,
// and the "strict parse" promise itself are not.
import { describe, expect, it } from "vitest";
import { DOMParser as DOMParser09 } from "@xmldom/xmldom";
import { parseXmlStrict } from "../../src/saml/xml";
import { isWorkerd } from "../support/host";

const SEPARATORS: Record<string, string> = {
  "LINE SEPARATOR": "\u2028",
  "PARAGRAPH SEPARATOR": "\u2029",
  "form feed": "\u000c",
  "vertical tab": "\u000b",
  NEL: "\u0085",
  NUL: "\u0000",
};
const doc = (sep: string) => `<a xmlns:p="urn:u" xmlns:q="urn:u" p:x="1"${sep}q:x="2"/>`;
const attrNames = (root: any) => Array.from(root.attributes as ArrayLike<any>).map((a) => a.name);

describe("R4-1: duplicate expanded attribute names hidden by non-XML whitespace", () => {
  for (const [name, sep] of Object.entries(SEPARATORS)) {
    it(`refuses p:x and q:x (same expanded name) separated by ${name}`, () => {
      expect(() => parseXmlStrict(doc(sep))).toThrow(/duplicates another attribute's expanded name|attribute/);
    });
  }

  it.skipIf(isWorkerd)("context (passes today): the two xmldom versions read different attribute sets from such a document", async () => {
    // Documented so the next reviewer sees why the scanner must refuse it, not merely why xmldom does.
    // xml-crypto's own xmldom (0.8) is reached through its package (Node only).
    const { createRequire } = await import("node:module");
    const require = createRequire(import.meta.url);
    const xmldom08 = require(require.resolve("@xmldom/xmldom", { paths: [require.resolve("xml-crypto")] })) as typeof import("@xmldom/xmldom");
    const xml = doc("\u2028");
    const v09 = attrNames(new DOMParser09().parseFromString(xml, "text/xml").documentElement);
    const v08 = attrNames(new xmldom08.DOMParser().parseFromString(xml, "text/xml").documentElement);
    expect(v09).not.toEqual(v08); // 0.9 drops p:x; 0.8 keeps p:x and q:x
    expect(v08).toContain("p:x");
    expect(v09).not.toContain("p:x");
  });
});
