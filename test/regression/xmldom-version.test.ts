// R3-5: D-025 says "The verified document is the same string, parsed by the same xmldom, that the
// request pipeline reads." It is not: the plugin depends on @xmldom/xmldom ^0.9 while xml-crypto 6
// depends on ^0.8, and pnpm installs both. Every signature check therefore spans two parsers.
// The two DOMs differ on namespace-ill-formed input, which xmldom 0.9 "strict" mode accepts
// silently (src/saml/xml.ts promises that "any warning, error or fatal error rejects").
import { createRequire } from "node:module";
import { dirname } from "node:path";
import { describe, expect, it } from "vitest";
import { isWorkerd } from "../support/host";
import { parseXmlStrict } from "../../src/saml/xml";

describe("xmldsig: two xmldom versions can't disagree about a document we accept", () => {
  // xml-crypto 6 ships its own @xmldom/xmldom 0.8 while the plugin uses 0.9, and a consumer's
  // install keeps it that way, so pinning here would prove nothing. What must hold instead: the
  // one known divergence (duplicate expanded attribute names) never gets past our parse.
  it("the strict parse rejects namespace-ill-formed XML instead of silently dropping an attribute", () => {
    // Namespaces in XML §6.3 "Attributes Unique": two attributes with the same expanded name.
    // xmldom 0.9 keeps q:x, drops p:x and reports nothing; xmldom 0.8 (xml-crypto) keeps both.
    const xml = `<a xmlns:p="u" xmlns:q="u" p:x="1" q:x="2"/>`;
    expect(() => parseXmlStrict(xml)).toThrow();
  });

  it("…also when a prefix is declared on an ancestor", () => {
    expect(() => parseXmlStrict(`<r xmlns:p="u"><a xmlns:q="u" p:x="1" q:x="2"/></r>`)).toThrow();
  });

  it("still accepts what's legal: same local name in different namespaces, unprefixed + prefixed, sibling scopes", () => {
    expect(() => parseXmlStrict(`<a xmlns:p="u" xmlns:q="v" p:x="1" q:x="2" x="3"/>`)).not.toThrow();
    expect(() => parseXmlStrict(`<r><a xmlns:p="u" p:x="1"/><b xmlns:p="v" p:x="1"/></r>`)).not.toThrow();
    expect(() => parseXmlStrict(`<a xmlns="u" x="1" xmlns:p="u" p:x="2"/>`)).not.toThrow(); // default ns doesn't apply to attributes
  });

  it.skipIf(isWorkerd)("documents the two versions (update D-025 if this ever changes)", () => {
    const require = createRequire(import.meta.url);
    const plugin = require("@xmldom/xmldom/package.json").version as string;
    const xmlCryptoDir = dirname(require.resolve("xml-crypto/package.json"));
    const xmlCrypto = require(require.resolve("@xmldom/xmldom/package.json", { paths: [xmlCryptoDir] })).version as string;
    const minor = (v: string) => v.split(".").slice(0, 2).join(".");
    expect([minor(plugin), minor(xmlCrypto)]).toEqual(["0.9", "0.8"]);
  });
});
