import type { GenericEndpointContext } from "better-auth";
import { createAuthEndpoint, getAuthoritativeSessionFromCtx } from "better-auth/api";
import * as z from "zod";
import type { IdpIdentity } from "../saml/identity";
import { idpBaseURL, SSO_PATH } from "../saml/idp";
import {
  authnContextStatus,
  stepUpTarget,
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
import { fail, issueResponse, lookupLog, type PluginState, prepareSp, routeIdentity, samlError, spById, tenantOf } from "./issue";

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
export function loginRedirectUrl(ctx: GenericEndpointContext, state: PluginState, rid: string, opts: { reauthenticate?: boolean; acr?: string; tenant?: string } = {}): string {
  const base = idpBaseURL(state.options, ctx.context.baseURL);
  const login = new URL(state.options.loginPage, new URL(base).origin);
  login.searchParams.set("callbackURL", `${base}${RESUME_PATH}?rid=${rid}`);
  // ForceAuthn: the page must ask for credentials even if the user is signed in, or the resume
  // step refuses the old session with REAUTHENTICATION_REQUIRED. `prompt=login`, as in OpenID
  // Connect, so the host's page can tell (R4-L5).
  if (opts.reauthenticate) login.searchParams.set("prompt", "login");
  // Step-up (D-047): the authentication class needed, as OpenID Connect's acr_values names it.
  if (opts.acr) login.searchParams.set("acr_values", opts.acr);
  // A tenant's request (D-052): its key, so the page can show the organization's branding.
  // Informational only: the tenant is bound to the stored request, not to this parameter.
  if (opts.tenant) login.searchParams.set("tenant", opts.tenant);
  return login.toString();
}

/**
 * A per-browser random value in a signed cookie; pending requests store its hash, so a leaked
 * resume link can't be completed in another browser. Only ever read or created on same-site
 * GETs: the SP's cross-site POST carries no SameSite=Lax cookies.
 */
export async function bindingValue(ctx: GenericEndpointContext, create: true): Promise<string>;
export async function bindingValue(ctx: GenericEndpointContext, create: boolean): Promise<string | null>;
export async function bindingValue(ctx: GenericEndpointContext, create: boolean): Promise<string | null> {
  const cookie = ctx.context.createAuthCookie(BINDING_COOKIE);
  const existing = await ctx.getSignedCookie(cookie.name, ctx.context.secret);
  if (existing) return existing;
  if (!create) return null;
  const value = newOpaqueToken();
  await ctx.setSignedCookie(cookie.name, value, ctx.context.secret, { ...cookie.attributes, maxAge: 60 * 60 * 24 });
  return value;
}

/** Session check, IsPassive, or park the request and send the user to sign in. `identity`: the route's, which is the SP's. */
async function proceed(ctx: GenericEndpointContext, state: PluginState, identity: IdpIdentity, sp: ResolvedServiceProvider, req: ValidatedRequest) {
  // The session store, not the cookie cache: a revoked session must not get an assertion (R4-2).
  const session = await getAuthoritativeSessionFromCtx(ctx);
  if (session && !req.forceAuthn) return issueResponse(ctx, state, sp, session as any, req);
  if (req.isPassive)
    return samlError(ctx, state, identity, req, { code: "Responder", subCode: "NoPassive", message: "The user is not signed in at the identity provider" });
  return parkForLogin(ctx, state, req);
}

type SsoContext = GenericEndpointContext & { query?: z.infer<typeof params>; body?: z.infer<typeof params> };

const ssoMetadata = (operationId: string, summary: string) => ({
  // A browser navigation (or an SP's POST), not something to call from the client (API decision 2).
  isAction: false as const,
  allowedMediaTypes: ["application/x-www-form-urlencoded"],
  openapi: {
    operationId,
    summary,
    description: "Receives an AuthnRequest from a registered service provider.",
  },
});

/**
 * Store the request as a single-use pending value bound to this browser, and send the user to
 * the login page; `/resume?rid=` picks it up afterwards (R1). Shared with IdP-initiated SSO.
 */
export async function parkForLogin(ctx: GenericEndpointContext, state: PluginState, req: ValidatedRequest, opts: { acr?: string } = {}): Promise<never> {
  // Step-up (D-047, review 5 R5-1/R5-2): every park of a request with a RequestedAuthnContext
  // tells the login page the level to deliver, whatever sent the user there (no session yet,
  // the SP's ForceAuthn, authorize()'s reauthenticate, or step-up itself). One round is then
  // always enough for a page that honours acr_values, which keeps the loop guard fair.
  const levels = state.options.authnContext?.levels;
  const acr = opts.acr ?? (levels && req.authnContext ? stepUpTarget(req.authnContext, levels) : undefined);
  const binding = await bindingValue(ctx, true);
  const rid = await storePending(
    ctx.context.internalAdapter,
    { ...req, bindingHash: await sha256b64url(binding) },
    state.options.pendingRequestTtlSeconds,
  );
  const tenant = req.tenantId !== undefined && state.tenants ? (await state.tenants.byOrganization(ctx.context.adapter as any, req.tenantId))?.tenantKey : undefined;
  throw ctx.redirect(loginRedirectUrl(ctx, state, rid, { reauthenticate: req.forceAuthn, acr, tenant }));
}

/**
 * An AuthnRequest at the root SSO URL (`tenantKey` undefined) or a tenant's (D-052). The URL
 * decides the identity, and the SP is looked up in that identity's tenant only: tenant B's URL
 * never finds tenant A's SP, whatever Issuer the request names, so isolation doesn't rest on the
 * SP checking the assertion's Issuer.
 */
async function handleSso(ctx: SsoContext, state: PluginState, tenantKey?: string) {
  const { options } = state;
  await sweepExpired(ctx.context.adapter as any, (what, e) => ctx.context.logger.warn(`[saml-idp] cleanup of expired ${what} failed`, e), Date.now(), { participants: state.options.sessionTracking, auditLog: state.options.auditLog !== undefined });
  const isPost = ctx.request?.method === "POST";
  // An unknown or disabled tenant looks like an unknown SP: the URL doesn't say which it was.
  const route = await routeIdentity(ctx, state, tenantKey);
  if (!route) return fail(ctx, state, "UNKNOWN_SERVICE_PROVIDER", "unknown tenant");
  const routeTenant = route.tenantId ?? "";

  // HTTP-POST binding, second leg: the same-site GET re-entry (see the 303 below).
  if (!isPost && ctx.query?.cid !== undefined) {
    const req = await consumeContinuation(ctx.context.internalAdapter, ctx.query.cid);
    if (!req) return fail(ctx, state, "PENDING_REQUEST_NOT_FOUND", "unknown or used continuation");
    if (req.requestId === undefined) return fail(ctx, state, "PENDING_REQUEST_NOT_FOUND", "continuation without a request ID");
    const sp = await spById(ctx, state, req.spId);
    if (!sp || resolveAcsUrl(sp, req.acsUrl) !== req.acsUrl) return fail(ctx, state, "UNKNOWN_SERVICE_PROVIDER", "SP changed");
    // Re-entry comes back to the URL the request was sent to, which must still be the SP's tenant.
    if ((sp.tenantId ?? "") !== routeTenant || (req.tenantId ?? "") !== routeTenant) return fail(ctx, state, "UNKNOWN_SERVICE_PROVIDER", "SP changed tenant", { spId: sp.id, ...tenantOf(sp) });
    return proceed(ctx, state, route, sp, req);
  }

  const now = new Date();
  let raw: RawAuthnRequest;
  let sp: ResolvedServiceProvider | undefined;
  let req: ValidatedRequest;
  let info: Awaited<ReturnType<typeof parseAuthnRequest>>;
  try {
    raw = isPost
      ? { binding: "post", samlRequest: ctx.body?.SAMLRequest ?? "", relayState: ctx.body?.RelayState }
      : parseRedirectQuery(ctx.request ? new URL(ctx.request.url).search.slice(1) : "");
    checkRelayState(raw.relayState, options.relayStateMaxBytes);
    const xml = await decodeAuthnRequest(raw);
    // Destination must be this URL: a request signed for tenant A's URL can't be replayed to B's.
    info = await parseAuthnRequest(xml, options.schemaValidator, { now, clockSkewSeconds: options.clockSkewSeconds, ssoUrl: route.ssoUrl });
    sp = await state.directory.byEntityId(ctx.context.adapter as any, info.issuer, lookupLog(ctx), routeTenant);
    if (!sp) return fail(ctx, state, "UNKNOWN_SERVICE_PROVIDER", `issuer not registered (${info.issuer.length} chars)`);
    sp = await prepareSp(ctx, state, sp); // the SP's signing certificates may come from metadata
    const signed = checkRequestSignature(raw, sp, { allowInsecureSha1: options.signing.allowInsecureSha1 }, xml);
    // A signed request must say where it was meant to go, or it can be replayed to another
    // endpoint (Bindings §3.4.5.2 / §3.5.5.2; SLO already required it). R4-L1.
    if (signed && info.destination === undefined) throw new SamlRequestError("INVALID_SAML_REQUEST", "a signed AuthnRequest must carry Destination");
    const acsUrl = resolveAcsUrl(sp, info.acsUrl);
    if (!acsUrl) return fail(ctx, state, "ACS_URL_NOT_ALLOWED", `SP ${sp.id}`, { spId: sp.id, ...tenantOf(sp) });
    req = {
      spId: sp.id,
      requestId: info.id,
      acsUrl,
      relayState: raw.relayState,
      forceAuthn: info.forceAuthn,
      isPassive: info.isPassive,
      subject: info.subject,
      createdAt: now.getTime(),
      ...(info.requestedAuthnContext ? { authnContext: info.requestedAuthnContext } : {}),
      // The URL's tenant, not the SP's: issuance refuses the two differing, so a lookup that ever
      // crossed tenants would still get nothing.
      ...(route.tenantId ? { tenantId: route.tenantId } : {}),
    };
  } catch (e) {
    if (e instanceof SamlRequestError) return fail(ctx, state, e.code, e.detail);
    throw e;
  }

  // R2: first sight of (SP, request ID) wins; every later sighting is a replay.
  const expiresAt = new Date(now.getTime() + (REQUEST_MAX_AGE_SECONDS + 2 * options.clockSkewSeconds) * 1000);
  if (!(await recordRequestId(ctx.context.adapter as any, sp.id, info.id, expiresAt)))
    return fail(ctx, state, "DUPLICATE_REQUEST_ID", `SP ${sp.id}`, { spId: sp.id, ...tenantOf(sp) });

  // The SP and ACS URL are trusted from here on: unsatisfiable requests get a SAML status.
  // With step-up levels (D-047), only a request no level could ever satisfy is refused here;
  // whether this session meets it is judged at issuance.
  const status =
    nameIdPolicyStatus(info, sp) ??
    (options.authnContext
      ? info.requestedAuthnContext && !stepUpTarget(info.requestedAuthnContext, options.authnContext.levels)
        ? { code: "Responder" as const, subCode: "NoAuthnContext" as const, message: "The requested authentication context is not available" }
        : undefined
      : authnContextStatus(info, options.authnContextClassRef));
  if (status) return samlError(ctx, state, route, req, status);

  if (isPost) {
    // The SP's cross-site POST carries no SameSite=Lax cookies (no session, no binding
    // cookie; review finding #6). Park the validated request and re-enter with a
    // top-level same-site GET, which does carry them.
    const cid = await storeContinuation(ctx.context.internalAdapter, req, CONTINUE_TTL_SECONDS);
    return new Response(null, {
      status: 303,
      headers: { Location: `${route.ssoUrl}?cid=${cid}`, "Cache-Control": "no-store" },
    });
  }
  return proceed(ctx, state, route, sp, req);
}

export const ssoEndpoint = (state: PluginState) =>
  createAuthEndpoint(
    SSO_PATH,
    {
      method: ["GET", "POST"],
      query: params.optional(),
      body: params.optional(),
      metadata: ssoMetadata("samlIdpSingleSignOn", "SAML SSO endpoint (HTTP-Redirect and HTTP-POST bindings)"),
    },
    async (ctx) => handleSso(ctx, state),
  );

/** A tenant's SSO URL (D-052): `/saml2/idp/sso/<tenantKey>`. */
export const tenantSsoEndpoint = (state: PluginState) =>
  createAuthEndpoint(
    `${SSO_PATH}/:tenant`,
    {
      method: ["GET", "POST"],
      query: params.optional(),
      body: params.optional(),
      metadata: ssoMetadata("samlIdpTenantSingleSignOn", "SAML SSO endpoint of a tenant (HTTP-Redirect and HTTP-POST bindings)"),
    },
    async (ctx) => handleSso(ctx, state, String(ctx.params?.tenant ?? "")),
  );
