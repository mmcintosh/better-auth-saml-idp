// D-037: the attribute-uniqueness scanner in parseXmlStrict runs on attacker-supplied XML before
// xmldom does. It must be linear in the input, cap nesting depth (xmldom is quadratic in nested
// namespace declarations), keep tracking namespace scopes correctly, and never refuse a
// well-formed document.
import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { MAX_XML_DEPTH, parseXmlStrict } from "../../src/saml/xml";

const MiB = 1024 * 1024;
const RUNS = Number(process.env.FUZZ_RUNS ?? 150);

/** Milliseconds to parse (or refuse) `xml`. */
function time(xml: string): number {
  const t = performance.now();
  try {
    parseXmlStrict(xml);
  } catch {}
  return performance.now() - t;
}

describe("xml scanner: bounded time on hostile input", () => {
  // 1 MiB is the SP-metadata limit, the largest input that reaches the parser. The regex scanner
  // took 2.5 s on 64 KiB of "</" and would take minutes on these; the bound leaves room for slow CI.
  const cases: Record<string, string> = {
    "unterminated comments": `<a>${"<!--".repeat(MiB / 4)}`,
    "unterminated CDATA": `<a>${"<![CDATA[".repeat(MiB / 9)}`,
    "unterminated PIs": `<a>${"<?".repeat(MiB / 2)}`,
    "unterminated declarations": `<a>${"<!X".repeat(MiB / 3)}`,
    "unterminated end tags": `<a>${"</".repeat(MiB / 2)}`,
    "a start tag that never closes": `<a${' x="1"'.repeat(MiB / 6)}`,
    "open quotes": `<a${' x="'.repeat(MiB / 4)}`,
    "bare <": `<a>${"<".repeat(MiB)}`,
    "deep nesting with namespace declarations": '<a xmlns:p="u">'.repeat(MiB / 16),
  };
  for (const [name, xml] of Object.entries(cases))
    it(name, () => {
      expect(time(xml)).toBeLessThan(2000);
    });
});

describe("xml scanner: depth limit", () => {
  const nested = (depth: number) => `${"<a>".repeat(depth)}${"</a>".repeat(depth)}`;
  it(`accepts ${MAX_XML_DEPTH} levels and refuses one more`, () => {
    expect(() => parseXmlStrict(nested(MAX_XML_DEPTH))).not.toThrow();
    expect(() => parseXmlStrict(nested(MAX_XML_DEPTH + 1))).toThrow(/nest deeper/);
  });
  it("self-closing elements and siblings don't count as depth", () => {
    expect(() => parseXmlStrict(`<r>${"<a/>".repeat(1000)}${"<b></b>".repeat(1000)}</r>`)).not.toThrow();
  });
});

describe("xml scanner: namespace scopes", () => {
  it("a prefix redeclared on a child reverts after the child closes", () => {
    // After </a>, p is "u" again, so p:x and q:x differ: legal.
    expect(() => parseXmlStrict(`<r xmlns:p="u"><a xmlns:p="v"></a><b xmlns:q="v" p:x="1" q:x="2"/></r>`)).not.toThrow();
    // Same shape, but p and q both mean "u" at <b>: a duplicate.
    expect(() => parseXmlStrict(`<r xmlns:p="u"><a xmlns:p="v"></a><b xmlns:q="u" p:x="1" q:x="2"/></r>`)).toThrow(/duplicates/);
  });
  it("a self-closing element's declarations don't leak to its siblings", () => {
    expect(() => parseXmlStrict(`<r xmlns:p="u"><a xmlns:p="v"/><b xmlns:q="u" p:x="1" q:x="2"/></r>`)).toThrow(/duplicates/);
  });
  it("'>' and '/' inside attribute values don't end the tag", () => {
    expect(() => parseXmlStrict(`<a x="1>2" y='a/>b' xmlns:p="u" xmlns:q="u" p:z="1"/>`)).not.toThrow();
    expect(() => parseXmlStrict(`<a x="1>2" xmlns:p="u" xmlns:q="u" p:z="1" q:z="2"/>`)).toThrow(/duplicates/);
  });
});

describe("xml scanner: never refuses a well-formed document", () => {
  const name = fc.stringMatching(/^[a-z][a-z0-9]{0,5}$/);
  // biome-ignore lint/suspicious/noControlCharactersInRegex: removing the characters XML can't carry (D-036)
  const text = fc.string({ maxLength: 20 }).map((s) => s.replace(/[<&\]\u0000-\u001f\ud800-\udfff\ufffd-\uffff]/g, ""));
  const value = text.map((s) => s.replace(/"/g, ""));
  type Node = string;
  const tree: fc.Arbitrary<Node> = fc.letrec<{ node: Node }>((tie) => ({
    node: fc.oneof(
      { depthSize: "small", withCrossShrink: true },
      text,
      text.map((t) => `<!--${t.replace(/-/g, "")}-->`),
      text.map((t) => `<![CDATA[${t}]]>`),
      fc
        .tuple(
          name,
          fc.uniqueArray(fc.tuple(name, value), { selector: ([n]) => n, maxLength: 3 }),
          fc.option(fc.tuple(fc.constantFrom("p", "q"), fc.constantFrom("urn:a", "urn:b"))),
          fc.array(tie("node"), { maxLength: 4 }),
          fc.constantFrom(" ", "\n", "\t", ""),
        )
        .map(([el, attrs, ns, children, ws]) => {
          const a = attrs.map(([k, v], i) => ` ${k}${i % 2 ? " = " : "="}${i % 2 ? `'${v.replace(/'/g, "")}'` : `"${v}"`}`).join("");
          const decl = ns ? ` xmlns:${ns[0]}="${ns[1]}" ${ns[0]}:only="1"` : "";
          return children.length ? `<${el}${a}${decl}${ws}>${children.join("")}</${el}>` : `<${el}${a}${decl}${ws}/>`;
        }),
    ),
  })).node;

  it("any generated well-formed tree parses", () => {
    fc.assert(
      fc.property(tree, (body) => {
        parseXmlStrict(`<?xml version="1.0"?><root>${body}</root>`);
      }),
      { numRuns: RUNS * 2 },
    );
  });
});

describe("xml scanner: tokenises tags as XML does (R4-L7)", () => {
  // xmldom treats these as attribute separators; the scanner used to read them as part of the
  // next name, so p:x and q:x (one namespace) escaped the duplicate check.
  for (const [name, sep] of [["NUL", "\u0000"], ["VT", "\u000b"], ["FF", "\u000c"], ["U+0080", "\u0080"], ["U+0085", "\u0085"], ["NBSP", " "]] as const)
    it(`${name} between attributes is refused`, () => {
      expect(() => parseXmlStrict(`<a xmlns:p="u" xmlns:q="u" p:x="1"${sep}q:x="2"/>`)).toThrow();
      expect(() => parseXmlStrict(`<a${sep}xmlns:p="u"/>`)).toThrow();
    });
  it("attributes need whitespace between them; none is needed before > or />", () => {
    expect(() => parseXmlStrict(`<a x="1"y="2"/>`)).toThrow(/whitespace between attributes/);
    expect(() => parseXmlStrict(`<a x="1"/>`)).not.toThrow();
    expect(() => parseXmlStrict(`<a x="1"></a>`)).not.toThrow();
    expect(() => parseXmlStrict(`<a x="1"\ty='2'\n/>`)).not.toThrow();
  });
});
