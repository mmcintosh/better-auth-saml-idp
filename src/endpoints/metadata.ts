import { createAuthEndpoint } from "better-auth/api";
import { type IdpIdentity, rootIdentity } from "../saml/identity";
import { type Idp, idpBaseURL, METADATA_PATH } from "../saml/idp";
import { newSamlId, signElement } from "../saml/response";
import { TenantKeyError } from "../saml/tenant-keys";
import { type PluginState, routeIdentity } from "./issue";
import { parseXmlStrict } from "../saml/xml";
import type { ResolvedSamlIdpOptions } from "../types";
import { XMLSerializer } from "@xmldom/xmldom";

export { METADATA_PATH };

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
export function renderMetadata(idp: Idp, options: ResolvedSamlIdpOptions, identity: IdpIdentity): string {
  const xml = schemaOrder(idp.getMetadata());
  if (!options.signMetadata) return xml;
  const withId = xml.replace(/<((?:\w+:)?EntityDescriptor)\b/, `<$1 ID="${newSamlId()}"`);
  return signElement(
    withId,
    "/*[local-name(.)='EntityDescriptor']",
    { reference: "/*[local-name(.)='EntityDescriptor']", action: "prepend" },
    identity.signing,
  );
}

function metadataResponse(idp: Idp, options: ResolvedSamlIdpOptions, identity: IdpIdentity): Response {
  let xml = metadataXml.get(idp);
  if (xml === undefined) {
    xml = renderMetadata(idp, options, identity);
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
}

/**
 * A tenant's metadata (D-052): `/saml2/idp/metadata/<tenantKey>`. An unknown key, a disabled
 * tenant and an organization that isn't a tenant all get this same answer, so the URL can't be
 * used to learn which of them it is (multi-tenant design §5.2).
 */
const notFound = () => new Response("Not Found", { status: 404, headers: { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store" } });

export const tenantMetadataEndpoint = (state: PluginState, getIdp: (identity: IdpIdentity) => Idp) =>
  createAuthEndpoint(
    `${METADATA_PATH}/:tenant`,
    {
      method: "GET",
      metadata: {
        isAction: false,
        openapi: {
          operationId: "getSamlIdpTenantMetadata",
          summary: "SAML IdP metadata of a tenant",
          description: "Returns the SAML 2.0 Identity Provider metadata document of one tenant (an organization's own IdP identity)",
          responses: { "200": { description: "SAML metadata XML" }, "404": { description: "No such tenant" } },
        },
      },
    },
    async (ctx) => {
      let identity: IdpIdentity | undefined;
      try {
        identity = await routeIdentity(ctx, state, String(ctx.params?.tenant ?? ""));
      } catch (e) {
        // Its own key can't be used (D-058): publish nothing rather than another key's certificate.
        if (!(e instanceof TenantKeyError)) throw e;
        ctx.context.logger.error(`[saml-idp] tenant metadata: ${e.message}`);
        return new Response("Internal Server Error", { status: 500, headers: { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store" } });
      }
      if (!identity) return notFound();
      return metadataResponse(getIdp(identity), state.options, identity);
    },
  );

export const metadataEndpoint = (getIdp: (baseURL: string) => Idp, options: ResolvedSamlIdpOptions) =>
  createAuthEndpoint(
    METADATA_PATH,
    {
      method: "GET",
      metadata: {
        // A browser navigation (or an SP's POST), not something to call from the client (API decision 2).
        isAction: false,
        openapi: {
          operationId: "getSamlIdpMetadata",
          summary: "SAML IdP metadata",
          description: "Returns the SAML 2.0 Identity Provider metadata document",
          responses: { "200": { description: "SAML metadata XML" } },
        },
      },
    },
    async (ctx) => metadataResponse(getIdp(ctx.context.baseURL), options, rootIdentity(options, idpBaseURL(options, ctx.context.baseURL))),
  );
