import { DOMParser } from "@xmldom/xmldom";

export class XmlParseError extends Error {}

/**
 * Namespaces in XML §6.3 ("Attributes Unique"): no element may carry two attributes with the same
 * expanded name, e.g. p:x and q:x with p and q bound to one URI. xmldom 0.9 silently keeps one;
 * xml-crypto's xmldom 0.8 keeps both, so the two would read different documents (review 3,
 * R3-7). Scan start tags, tracking namespace declarations through the element stack.
 */
function assertUniqueExpandedAttributes(xml: string): void {
  const scopes: Map<string, string>[] = [];
  const tag = /<!--[\s\S]*?-->|<!\[CDATA\[[\s\S]*?\]\]>|<\?[\s\S]*?\?>|<!DOCTYPE[^>]*>|<\/[^>]*>|<([^\s/>!?]+)((?:\s+[^\s=/>]+\s*=\s*(?:"[^"]*"|'[^']*'))*)\s*(\/?)>/g;
  const attr = /([^\s=/>]+)\s*=\s*(?:"([^"]*)"|'([^']*)')/g;
  for (let m = tag.exec(xml); m; m = tag.exec(xml)) {
    const text = m[0];
    if (text.startsWith("</")) {
      scopes.pop();
      continue;
    }
    if (m[1] === undefined) continue; // comment, CDATA, PI, DOCTYPE
    const attrs: [string, string][] = [];
    for (let a = attr.exec(m[2] ?? ""); a; a = attr.exec(m[2] ?? "")) attrs.push([a[1] as string, a[2] ?? a[3] ?? ""]);
    attr.lastIndex = 0;
    const decl = new Map<string, string>();
    for (const [name, value] of attrs) if (name.startsWith("xmlns:")) decl.set(name.slice(6), value);
    const resolve = (prefix: string) => {
      if (decl.has(prefix)) return decl.get(prefix);
      for (let i = scopes.length - 1; i >= 0; i--) if (scopes[i]?.has(prefix)) return scopes[i]?.get(prefix);
      return prefix === "xml" ? "http://www.w3.org/XML/1998/namespace" : undefined;
    };
    const seen = new Set<string>();
    for (const [name] of attrs) {
      if (name === "xmlns" || name.startsWith("xmlns:")) continue;
      const i = name.indexOf(":");
      const key = i < 0 ? `\u0000${name}` : `${resolve(name.slice(0, i)) ?? `?${name.slice(0, i)}`}\u0000${name.slice(i + 1)}`;
      if (seen.has(key)) throw new XmlParseError(`attribute ${name} duplicates another attribute's expanded name`);
      seen.add(key);
    }
    if (m[3] !== "/") scopes.push(decl);
  }
}

/**
 * Strict parse: duplicate expanded attribute names, and any warning, error or fatal error from
 * the parser, reject the document. Callers must run `precheckXml` first; this does not re-check
 * size or DOCTYPE.
 */
export function parseXmlStrict(xml: string) {
  assertUniqueExpandedAttributes(xml);
  // `onError` is the 0.9 runtime option; the bundled .d.ts only declares the deprecated
  // `errorHandler`, hence the cast.
  const parser = new DOMParser({
    onError(level: string, message: string) {
      throw new XmlParseError(`${level}: ${message}`);
    },
  } as ConstructorParameters<typeof DOMParser>[0]);
  try {
    const doc = parser.parseFromString(xml, "text/xml");
    if (!doc.documentElement) throw new XmlParseError("no document element");
    return doc;
  } catch (e) {
    if (e instanceof XmlParseError) throw e;
    throw new XmlParseError((e as Error)?.message ?? String(e));
  }
}
