import { createAuthEndpoint } from "better-auth/api";
import type { Idp } from "../saml/idp";

export const METADATA_PATH = "/saml2/idp/metadata";

export const metadataEndpoint = (getIdp: (baseURL: string) => Idp) =>
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
      const xml = getIdp(ctx.context.baseURL).getMetadata();
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
