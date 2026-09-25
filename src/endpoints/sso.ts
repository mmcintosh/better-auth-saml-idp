import type { GenericEndpointContext } from "better-auth";
import { createAuthEndpoint, getSessionFromCtx } from "better-auth/api";
import * as z from "zod";
import { idpBaseURL, SSO_PATH } from "../saml/idp";
import {
  authnContextStatus,
  checkRelayState,
  checkRequestSignature,
  decodeAuthnRequest,
  nameIdPolicyStatus,
  parseAuthnRequest,
  parseRedirectQuery,
  REQUEST_MAX_AGE_SECONDS,
  SamlRequestError,
  type RawAuthnRequest,
} from "../saml/request";
import { resolveAcsUrl } from "../saml/sp-registry";
import {
  consumeContinuation,
  newOpaqueToken,
  sha256b64url,
  storeContinuation,
  storePending,
  type ValidatedRequest,
} from "../storage/pending";
import { recordRequestId } from "../storage/seen";
import { sweepExpired } from "../storage/sweep";
import type { ResolvedServiceProvider } from "../types";
import { fail, issueResponse, samlError, type PluginState } from "./issue";

export const RESUME_PATH = "/saml2/idp/resume";
export const BINDING_COOKIE = "saml_idp_binding";
/** How long an HTTP-POST binding request may take to re-enter via the same-site GET. */
const CONTINUE_TTL_SECONDS = 120;

const params = z.object({
  SAMLRequest: z.string().optional(),
  RelayState: z.string().optional(),
  SigAlg: z.string().optional(),
  Signature: z.string().optional(),
  cid: z.string().max(128).optional(),
});

/** Where the browser goes to sign in, carrying the resume URL as `callbackURL`. */
export function loginRedirectUrl(ctx: GenericEndpointContext, state: PluginState, rid: string): string {
  const base = idpBaseURL(state.options, ctx.context.baseURL);
  const login = new URL(state.options.loginPage, new URL(base).origin);
  login.searchParams.set("callbackURL", `${base}${RESUME_PATH}?rid=${rid}`);
  return login.toString();
}

/**
 * A per-browser random value in a signed cookie; pending requests store its hash, so a leaked
 * resume link can't be completed in another browser. Only ever read or created on same-site
 * GETs: the SP's cross-site POST carries no SameSite=Lax cookies.
 */
export async function bindingValue(ctx: GenericEndpointContext, create: boolean): Promise<string | null> {
  const cookie = ctx.context.createAuthCookie(BINDING_COOKIE);
  const existing = await ctx.getSignedCookie(cookie.name, ctx.context.secret);
  if (existing) return existing;
  if (!create) return null;
  const value = newOpaqueToken();
  await ctx.setSignedCookie(cookie.name, value, ctx.context.secret, { ...cookie.attributes, maxAge: 60 * 60 * 24 });
  return value;
}

/** Session check, IsPassive, or park the request and send the user to sign in. */
async function proceed(ctx: GenericEndpointContext, state: PluginState, sp: ResolvedServiceProvider, req: ValidatedRequest) {
  const session = await getSessionFromCtx(ctx);
  if (session && !req.forceAuthn) return issueResponse(ctx, state, sp, session as any, req);
  if (req.isPassive)
    return samlError(ctx, state, req, { code: "Responder", subCode: "NoPassive", message: "The user is not signed in at the identity provider" });
  return parkForLogin(ctx, state, req);
}

/**
 * Store the request as a single-use pending value bound to this browser, and send the user to
 * the login page; `/resume?rid=` picks it up afterwards (R1). Shared with IdP-initiated SSO.
 */
export async function parkForLogin(ctx: GenericEndpointContext, state: PluginState, req: ValidatedRequest): Promise<never> {
  const binding = (await bindingValue(ctx, true))!;
  const rid = await storePending(
    ctx.context.internalAdapter,
    { ...req, bindingHash: await sha256b64url(binding) },
    state.options.pendingRequestTtlSeconds,
  );
  throw ctx.redirect(loginRedirectUrl(ctx, state, rid));
}

export const ssoEndpoint = (state: PluginState) =>
  createAuthEndpoint(
    SSO_PATH,
    {
      method: ["GET", "POST"],
      query: params.optional(),
      body: params.optional(),
      metadata: {
        allowedMediaTypes: ["application/x-www-form-urlencoded"],
        openapi: {
          operationId: "samlIdpSingleSignOn",
          summary: "SAML SSO endpoint (HTTP-Redirect and HTTP-POST bindings)",
          description: "Receives an AuthnRequest from a registered service provider.",
        },
      },
    },
    async (ctx) => {
      const { options, registry } = state;
      await sweepExpired(ctx.context.adapter as any, (what, e) => ctx.context.logger.warn(`[saml-idp] cleanup of expired ${what} failed`, e));
      const isPost = ctx.request?.method === "POST";

      // HTTP-POST binding, second leg: the same-site GET re-entry (see the 303 below).
      if (!isPost && ctx.query?.cid !== undefined) {
        const req = await consumeContinuation(ctx.context.internalAdapter, ctx.query.cid);
        if (!req) return fail(ctx, "PENDING_REQUEST_NOT_FOUND", "unknown or used continuation");
        if (req.requestId === undefined) return fail(ctx, "PENDING_REQUEST_NOT_FOUND", "continuation without a request ID");
        const sp = registry.byId(req.spId);
        if (!sp || resolveAcsUrl(sp, req.acsUrl) !== req.acsUrl) return fail(ctx, "UNKNOWN_SERVICE_PROVIDER", "SP changed");
        return proceed(ctx, state, sp, req);
      }

      const now = new Date();
      const ssoUrl = `${idpBaseURL(options, ctx.context.baseURL)}${SSO_PATH}`;
      let raw: RawAuthnRequest;
      let sp: ResolvedServiceProvider | undefined;
      let req: ValidatedRequest;
      let info;
      try {
        raw = isPost
          ? { binding: "post", samlRequest: ctx.body?.SAMLRequest ?? "", relayState: ctx.body?.RelayState }
          : parseRedirectQuery(ctx.request ? new URL(ctx.request.url).search.slice(1) : "");
        checkRelayState(raw.relayState, options.relayStateMaxBytes);
        const xml = await decodeAuthnRequest(raw);
        info = await parseAuthnRequest(xml, options.schemaValidator, { now, clockSkewSeconds: options.clockSkewSeconds, ssoUrl });
        sp = registry.byEntityId(info.issuer);
        if (!sp) return fail(ctx, "UNKNOWN_SERVICE_PROVIDER", `issuer not registered (${info.issuer.length} chars)`);
        checkRequestSignature(raw, sp, { allowInsecureSha1: options.signing.allowInsecureSha1 });
        const acsUrl = resolveAcsUrl(sp, info.acsUrl);
        if (!acsUrl) return fail(ctx, "ACS_URL_NOT_ALLOWED", `SP ${sp.id}`);
        req = {
          spId: sp.id,
          requestId: info.id,
          acsUrl,
          relayState: raw.relayState,
          forceAuthn: info.forceAuthn,
          isPassive: info.isPassive,
          subject: info.subject,
          createdAt: now.getTime(),
        };
      } catch (e) {
        if (e instanceof SamlRequestError) return fail(ctx, e.code, e.detail);
        throw e;
      }

      // R2: first sight of (SP, request ID) wins; every later sighting is a replay.
      const expiresAt = new Date(now.getTime() + (REQUEST_MAX_AGE_SECONDS + 2 * options.clockSkewSeconds) * 1000);
      if (!(await recordRequestId(ctx.context.adapter as any, sp.id, info.id, expiresAt)))
        return fail(ctx, "DUPLICATE_REQUEST_ID", `SP ${sp.id}`);

      // The SP and ACS URL are trusted from here on: unsatisfiable requests get a SAML status.
      const status = nameIdPolicyStatus(info, sp) ?? authnContextStatus(info, options.authnContextClassRef);
      if (status) return samlError(ctx, state, req, status);

      if (isPost) {
        // The SP's cross-site POST carries no SameSite=Lax cookies (no session, no binding
        // cookie; review finding #6). Park the validated request and re-enter with a
        // top-level same-site GET, which does carry them.
        const cid = await storeContinuation(ctx.context.internalAdapter, req, CONTINUE_TTL_SECONDS);
        return new Response(null, {
          status: 303,
          headers: { Location: `${idpBaseURL(options, ctx.context.baseURL)}${SSO_PATH}?cid=${cid}`, "Cache-Control": "no-store" },
        });
      }
      return proceed(ctx, state, sp, req);
    },
  );
