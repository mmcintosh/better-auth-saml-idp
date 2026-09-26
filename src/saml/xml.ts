import { DOMParser } from "@xmldom/xmldom";

export class XmlParseError extends Error {}

/**
 * Deepest element nesting accepted. SAML messages nest about 10 deep, and federation metadata
 * a little more. xmldom copies namespace scopes per element, so without a limit deep nesting is
 * quadratic: 1 MiB of nested declarations took 27 s (D-037).
 */
export const MAX_XML_DEPTH = 100;

/**
 * Namespaces in XML §6.3 ("Attributes Unique"): no element may carry two attributes with the same
 * expanded name, e.g. p:x and q:x with p and q bound to one URI. xmldom 0.9 silently keeps one;
 * xml-crypto's xmldom 0.8 keeps both, so the two would read different documents (review 3,
 * R3-7). Scan start tags, tracking namespace declarations through the element stack.
 */
function assertUniqueExpandedAttributes(xml: string): void {
  // A hand-written scanner, linear in the input: each construct is found with indexOf from where
  // the last one ended, and unterminated markup is refused at once. (The regex this replaced
  // rescanned to the end from every "<", so 64 KiB of "</" took seconds: D-037.) Anything it
  // refuses, xmldom would refuse too.
  // Open elements' namespace declarations, and each prefix's bindings innermost-last, so a
  // lookup is O(1) however deep the nesting.
  const scopes: Map<string, string>[] = [];
  const bindings = new Map<string, string[]>();
  const n = xml.length;
  const isSpace = (c: number) => c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d;
  const skip = (from: number, close: string, what: string) => {
    const j = xml.indexOf(close, from);
    if (j < 0) throw new XmlParseError(`unterminated ${what}`);
    return j + close.length;
  };
  let pos = 0;
  for (let i = xml.indexOf("<", pos); i >= 0; i = xml.indexOf("<", pos)) {
    if (xml.startsWith("<!--", i)) pos = skip(i + 4, "-->", "comment");
    else if (xml.startsWith("<![CDATA[", i)) pos = skip(i + 9, "]]>", "CDATA section");
    else if (xml.startsWith("<?", i)) pos = skip(i + 2, "?>", "processing instruction");
    else if (xml.startsWith("<!", i)) pos = skip(i + 2, ">", "declaration");
    else if (xml.startsWith("</", i)) {
      pos = skip(i + 2, ">", "end tag");
      for (const prefix of scopes.pop()?.keys() ?? []) bindings.get(prefix)?.pop();
    } else {
      // Start tag: name, then name="value" / name='value' pairs, then ">" or "/>".
      let k = i + 1;
      while (k < n && !isSpace(xml.charCodeAt(k)) && xml[k] !== "/" && xml[k] !== ">") k++;
      if (k === i + 1) throw new XmlParseError("malformed start tag");
      const attrs: [string, string][] = [];
      let selfClosing = false;
      for (;;) {
        while (k < n && isSpace(xml.charCodeAt(k))) k++;
        if (k >= n) throw new XmlParseError("unterminated start tag");
        if (xml[k] === ">") break;
        if (xml.startsWith("/>", k)) {
          selfClosing = true;
          k++;
          break;
        }
        const nameStart = k;
        while (k < n && !isSpace(xml.charCodeAt(k)) && xml[k] !== "=" && xml[k] !== "/" && xml[k] !== ">" && xml[k] !== "<") k++;
        const name = xml.slice(nameStart, k);
        while (k < n && isSpace(xml.charCodeAt(k))) k++;
        if (name === "" || xml[k] !== "=") throw new XmlParseError("malformed attribute");
        k++;
        while (k < n && isSpace(xml.charCodeAt(k))) k++;
        const quote = xml[k];
        if (quote !== '"' && quote !== "'") throw new XmlParseError("unquoted attribute value");
        const close = xml.indexOf(quote, k + 1);
        if (close < 0) throw new XmlParseError("unterminated attribute value");
        attrs.push([name, xml.slice(k + 1, close)]);
        k = close + 1;
      }
      pos = k + 1;
      const decl = new Map<string, string>();
      for (const [name, value] of attrs) if (name.startsWith("xmlns:")) decl.set(name.slice(6), value);
      const resolve = (prefix: string) => {
        if (decl.has(prefix)) return decl.get(prefix);
        const bound = bindings.get(prefix);
        if (bound?.length) return bound[bound.length - 1];
        return prefix === "xml" ? "http://www.w3.org/XML/1998/namespace" : undefined;
      };
      const seen = new Set<string>();
      for (const [name] of attrs) {
        if (name === "xmlns" || name.startsWith("xmlns:")) continue;
        const c = name.indexOf(":");
        const key = c < 0 ? `\u0000${name}` : `${resolve(name.slice(0, c)) ?? `?${name.slice(0, c)}`}\u0000${name.slice(c + 1)}`;
        if (seen.has(key)) throw new XmlParseError(`attribute ${name} duplicates another attribute's expanded name`);
        seen.add(key);
      }
      if (!selfClosing) {
        if (scopes.length >= MAX_XML_DEPTH) throw new XmlParseError(`elements nest deeper than ${MAX_XML_DEPTH}`);
        scopes.push(decl);
        for (const [prefix, uri] of decl) {
          const bound = bindings.get(prefix);
          if (bound) bound.push(uri);
          else bindings.set(prefix, [uri]);
        }
      }
    }
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
