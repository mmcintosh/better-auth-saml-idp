import type { GenericEndpointContext } from "better-auth";
import { createAuthEndpoint, getAuthoritativeSessionFromCtx } from "better-auth/api";
import * as z from "zod";
import { idpBaseURL } from "../saml/idp";
import { confirmPage } from "../saml/post-form";
import { sweepExpired } from "../storage/sweep";
import type { ValidatedRequest } from "../storage/pending";
import type { ResolvedServiceProvider } from "../types";
import { fail, issueResponse, type PluginState, spById } from "./issue";
import { parkForLogin } from "./sso";

export const INIT_PATH = "/saml2/idp/init";

/**
 * The RelayState sent with an IdP-initiated Response. A caller-supplied value is used only if
 * it exactly matches the SP's allow-list; anything else is ignored in favour of the SP's
 * default. RelayState in IdP-initiated SSO is conventionally the SP-side target URL, so
 * forwarding arbitrary values would turn every launcher link into an open redirect at the SP
 * (DECISIONS.md D-021).
 */
export function idpInitiatedRelayState(sp: ResolvedServiceProvider, requested: string | undefined): string | undefined {
  if (requested !== undefined && sp.allowedRelayStates.includes(requested)) return requested;
  return sp.idpInitiatedRelayState;
}

/**
 * Login- and logout-CSRF mitigation: a cross-site navigation that the user did not trigger (no
 * `Sec-Fetch-User: ?1`) gets a confirmation page instead of an assertion. Clicked links from a
 * portal, bookmarks and typed URLs pass. Browsers without Fetch Metadata send neither header
 * and pass, so this narrows the attack, it does not close it (docs/security.md).
 */
export function isDriveByCrossSite(ctx: GenericEndpointContext, opts: { sameSiteToo?: boolean } = {}): boolean {
  const headers = ctx.request?.headers ?? ctx.headers;
  // `sameSiteToo` (sign-out everywhere, R4-L4): a sibling subdomain, such as another app or user
  // content on one, must not end every session without a click. IdP-initiated sign-in keeps
  // same-site navigations: host apps redirect there, and the worst a drive-by can do is sign the
  // user in as themselves.
  const site = headers?.get("sec-fetch-site");
  return (site === "cross-site" || (opts.sameSiteToo === true && site === "same-site")) && headers?.get("sec-fetch-user") !== "?1";
}

export const initEndpoint = (state: PluginState) =>
  createAuthEndpoint(
    INIT_PATH,
    {
      // GET only: launcher links and bookmarks are GETs. A POST from another site would carry no
      // SameSite=Lax cookies (no session, no binding cookie) and adds nothing but surface.
      method: "GET",
      query: z.object({ sp: z.string().max(64).optional(), RelayState: z.string().max(4096).optional() }).optional(),
      metadata: {
        openapi: {
          operationId: "samlIdpInitiatedSignOn",
          summary: "IdP-initiated SAML SSO",
          description: "Sends an unsolicited SAML Response to a service provider that has opted in (allowIdpInitiated).",
        },
      },
    },
    async (ctx) => {
      const { options } = state;
      await sweepExpired(ctx.context.adapter as any, (what, e) => ctx.context.logger.warn(`[saml-idp] cleanup of expired ${what} failed`, e), Date.now(), { auditLog: state.options.auditLog !== undefined });
      const spId = ctx.query?.sp;
      const sp = spId === undefined ? undefined : await spById(ctx, state, spId);
      if (!sp) return fail(ctx, state, "UNKNOWN_SERVICE_PROVIDER", `init: unknown sp (${spId?.length ?? 0} chars)`);
      if (!sp.allowIdpInitiated) return fail(ctx, state, "IDP_INITIATED_NOT_ALLOWED", `SP ${sp.id}`, { spId: sp.id });

      const requestedRelayState = ctx.query?.RelayState;
      const relayState = idpInitiatedRelayState(sp, requestedRelayState);
      if (requestedRelayState !== undefined && relayState !== requestedRelayState)
        ctx.context.logger.debug(`[saml-idp] init: RelayState not on the allow-list for SP ${sp.id}; using the default`);

      if (isDriveByCrossSite(ctx)) {
        const href = new URL(`${idpBaseURL(options, ctx.context.baseURL)}${INIT_PATH}`);
        href.searchParams.set("sp", sp.id);
        if (relayState !== undefined && relayState !== sp.idpInitiatedRelayState) href.searchParams.set("RelayState", relayState);
        return confirmPage(href.toString(), sp.id);
      }

      // Unsolicited: no request ID, so no InResponseTo. Always the SP's first ACS URL.
      const req: ValidatedRequest = {
        spId: sp.id,
        requestId: undefined,
        acsUrl: sp.acsUrls[0],
        relayState,
        forceAuthn: false,
        isPassive: false,
        subject: undefined,
        createdAt: Date.now(),
      };
      // The session store, not the cookie cache: a revoked session must not get an assertion (R4-2).
      const session = await getAuthoritativeSessionFromCtx(ctx);
      if (session) return issueResponse(ctx, state, sp, session as any, req);
      return parkForLogin(ctx, state, req);
    },
  );
