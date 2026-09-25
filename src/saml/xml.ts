import { DOMParser } from "@xmldom/xmldom";

export class XmlParseError extends Error {}

/**
 * Strict parse: any warning, error or fatal error from the parser rejects the document.
 * Callers must run `precheckXml` first; this does not re-check size or DOCTYPE.
 */
export function parseXmlStrict(xml: string) {
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
