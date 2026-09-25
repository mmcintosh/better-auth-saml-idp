// Prototype samlify schema validator backed by libxml2-wasm (libxml2 compiled to WASM).
// `lib` is injected so the same code runs on stock libxml2-wasm (Node) and the
// instantiateWasm-patched copy (workerd).
import protocolXsd from "@authenio/samlify-node-xmllint/build/schemas/saml-schema-protocol-2.0.xsd.js";
import assertionXsd from "@authenio/samlify-node-xmllint/build/schemas/saml-schema-assertion-2.0.xsd.js";
import xmldsigXsd from "@authenio/samlify-node-xmllint/build/schemas/xmldsig-core-schema.xsd.js";
import xencXsd from "@authenio/samlify-node-xmllint/build/schemas/xenc-schema.xsd.js";

type Lib = typeof import("libxml2-wasm");
const def = (m: any): string => (typeof m === "string" ? m : m.default);

export function createValidator(lib: Lib) {
  const enc = new TextEncoder();
  const files: Record<string, string> = {
    "saml-schema-protocol-2.0.xsd": def(protocolXsd),
    "saml-schema-assertion-2.0.xsd": def(assertionXsd),
    "xmldsig-core-schema.xsd": def(xmldsigXsd),
    "xenc-schema.xsd": def(xencXsd),
  };
  lib.xmlRegisterInputProvider(
    new lib.XmlBufferInputProvider(
      Object.fromEntries(Object.entries(files).map(([k, v]) => [k, enc.encode(v)])),
    ),
  );
  const xsdDoc = lib.XmlDocument.fromString(files["saml-schema-protocol-2.0.xsd"], {
    url: "saml-schema-protocol-2.0.xsd",
    option: lib.ParseOption.XML_PARSE_NONET,
  });
  const xsd = lib.XsdValidator.fromDoc(xsdDoc);

  return {
    async validate(xml: string) {
      // NONET: never fetch; no NOENT/DTDLOAD, so entities are not expanded and no DTD is loaded.
      const doc = lib.XmlDocument.fromString(xml, { option: lib.ParseOption.XML_PARSE_NONET });
      try {
        xsd.validate(doc);
        return "SUCCESS_VALIDATE_XML";
      } catch (e) {
        throw new Error(`ERR_EXCEPTION_VALIDATE_XML: ${(e as Error).message}`);
      } finally {
        doc.dispose();
      }
    },
  };
}
