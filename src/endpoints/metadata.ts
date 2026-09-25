import { createAuthEndpoint } from "better-auth/api";
import type { Idp } from "../saml/idp";
import { newSamlId, signElement } from "../saml/response";
import { parseXmlStrict } from "../saml/xml";
import type { ResolvedSamlIdpOptions } from "../types";
import { XMLSerializer } from "@xmldom/xmldom";

export const METADATA_PATH = "/saml2/idp/metadata";

const MD = "urn:oasis:names:tc:SAML:2.0:metadata";

/**
 * samlify emits SingleLogoutService after SingleSignOnService, but the metadata schema
 * (SSODescriptorType) puts it before NameIDFormat, ahead of IDPSSODescriptor's own elements.
 * Move it there so SLO-enabled metadata validates (D-028; caught by `inspect` on the live IdP).
 */
function schemaOrder(xml: string): string {
  if (!xml.includes("SingleLogoutService")) return xml;
  const doc = parseXmlStrict(xml);
  const idp = doc.getElementsByTagNameNS(MD, "IDPSSODescriptor")[0];
  if (!idp) return xml;
  const kids = Array.from(idp.childNodes as ArrayLike<any>).filter((n: any) => n.nodeType === 1 && n.namespaceURI === MD);
  const slo = kids.filter((n: any) => n.localName === "SingleLogoutService");
  const anchor = kids.find((n: any) => n.localName === "ManageNameIDService" || n.localName === "NameIDFormat" || n.localName === "SingleSignOnService");
  if (!slo.length || !anchor) return xml;
  for (const n of slo) idp.insertBefore(n, anchor);
  return new XMLSerializer().serializeToString(doc);
}

/** samlify rebuilds the XML on every call; an IdP's metadata never changes, so build it once. */
const metadataXml = new WeakMap<Idp, string>();

/**
 * Metadata XML for an IdP, optionally signed. The EntityDescriptor gets an ID to reference, and
 * the ds:Signature becomes its first child (SAML metadata schema: Signature precedes Extensions).
 */
export function renderMetadata(idp: Idp, options: ResolvedSamlIdpOptions): string {
  const xml = schemaOrder(idp.getMetadata());
  if (!options.signMetadata) return xml;
  const withId = xml.replace(/<((?:\w+:)?EntityDescriptor)\b/, `<$1 ID="${newSamlId()}"`);
  return signElement(
    withId,
    "/*[local-name(.)='EntityDescriptor']",
    { reference: "/*[local-name(.)='EntityDescriptor']", action: "prepend" },
    options.signing,
  );
}

export const metadataEndpoint = (getIdp: (baseURL: string) => Idp, options: ResolvedSamlIdpOptions) =>
  createAuthEndpoint(
    METADATA_PATH,
    {
      method: "GET",
      metadata: {
        openapi: {
          operationId: "getSamlIdpMetadata",
          summary: "SAML IdP metadata",
          description: "Returns the SAML 2.0 Identity Provider metadata document",
          responses: { "200": { description: "SAML metadata XML" } },
        },
      },
    },
    async (ctx) => {
      const idp = getIdp(ctx.context.baseURL);
      let xml = metadataXml.get(idp);
      if (xml === undefined) {
        xml = renderMetadata(idp, options);
        metadataXml.set(idp, xml);
      }
      return new Response(xml, {
        headers: {
          "Content-Type": "application/samlmetadata+xml; charset=utf-8",
          // Contents depend on the request's host unless `baseURL` is pinned: never let a
          // shared cache serve one host's metadata for another.
          "Cache-Control": "private, max-age=300",
          Vary: "Host, X-Forwarded-Host, X-Forwarded-Proto",
        },
      });
    },
  );
