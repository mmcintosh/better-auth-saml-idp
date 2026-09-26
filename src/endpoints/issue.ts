import { createHmac } from "node:crypto";
import type { GenericEndpointContext } from "better-auth";
import { ERROR_STATUS, SAML_IDP_ERROR_CODES, type SamlIdpErrorCode } from "../errors";
import { autoPostResponse, errorPage } from "../saml/post-form";
import { logSafe, type SamlStatus } from "../saml/request";
import { buildSignedErrorResponse, buildSignedResponse, hasNonXmlChars, newSamlId } from "../saml/response";
import type { SpMetadataCache } from "../saml/sp-metadata-refresh";
import type { SpDirectory } from "../saml/sp-directory";
import { hasOrganizationPlugin, loadMemberships, matchOrganization } from "../organizations";
import { recordParticipant, sessionIndexOf } from "../storage/participants";
import { base64url, type ValidatedRequest } from "../storage/pending";
import { NAMEID_FORMAT, type OrganizationMembership, type ResolvedSamlIdpOptions, type ResolvedServiceProvider, type SamlIdpUser } from "../types";

/** A mapped field the user object lacks: warn once per SP and field (typo, or a field not in the schema). */
const warnedMissing = new Set<string>();
function warnMissingField(ctx: GenericEndpointContext, sp: ResolvedServiceProvider, field: string) {
  const key = `${sp.id}\u0000${field}`;
  if (warnedMissing.has(key)) return;
  if (warnedMissing.size < 1000) warnedMissing.add(key);
  ctx.context.logger.warn(`[saml-idp] attributes for SP ${sp.id}: the user has no field "${field}"; the attribute is left out`);
}

export interface PluginState {
  options: ResolvedSamlIdpOptions;
  directory: SpDirectory;
  metadata: SpMetadataCache;
}

/** Log sink for SP lookups (a stored SP that no longer validates is logged, not thrown). */
export const lookupLog = (ctx: GenericEndpointContext) => ({ error: (m: string) => ctx.context.logger.error(m) });

/** Find an SP by id: code first, then the database registry. */
export function spById(ctx: GenericEndpointContext, state: PluginState, id: string) {
  return state.directory.byId(ctx.context.adapter as any, id, lookupLog(ctx));
}

/** The SP with certificates from its metadata URL merged in (D-026); unchanged without one. */
export function prepareSp(ctx: GenericEndpointContext, state: PluginState, sp: ResolvedServiceProvider): Promise<ResolvedServiceProvider> {
  return state.metadata.prepare(
    sp,
    { info: (m) => ctx.context.logger.info(m), warn: (m) => ctx.context.logger.warn(m) },
    (p) => ctx.context.runInBackground(p),
  );
}

type SessionWithUser = {
  session: { id: string; token: string; createdAt: Date; expiresAt: Date; impersonatedBy?: unknown };
  user: { id: string };
};

/** Error page for a plugin error code; the detail goes to the debug log only. */
export function fail(ctx: GenericEndpointContext, code: SamlIdpErrorCode, detail?: string): Response {
  ctx.context.logger.debug(`[saml-idp] ${code}${detail ? `: ${logSafe(detail, 300)}` : ""}`);
  const logout = code === "LOGOUT_NOT_SUPPORTED" || code === "LOGOUT_STATE_NOT_FOUND" || code === "INVALID_RETURN_TO";
  return errorPage(ERROR_STATUS[code], code, SAML_IDP_ERROR_CODES[code].message, logout ? "Sign-out could not be completed" : undefined);
}

/**
 * A SAML error Response to the (already validated) ACS URL. Used when the SP should learn the
 * outcome in-protocol: NoPassive, NoAuthnContext, InvalidNameIDPolicy, UnknownPrincipal.
 */
export function samlError(
  ctx: GenericEndpointContext,
  state: PluginState,
  req: Pick<ValidatedRequest, "requestId" | "acsUrl" | "relayState" | "spId">,
  status: SamlStatus,
): Response {
  ctx.context.logger.debug(`[saml-idp] SAML status ${status.code}/${status.subCode ?? "-"} for SP ${req.spId}`);
  const res = buildSignedErrorResponse(state.options, { requestId: req.requestId, acsUrl: req.acsUrl, status, now: new Date() });
  return autoPostResponse(req.acsUrl, res.base64, req.relayState);
}

/** Truthy like Better Auth's admin plugin: some adapters return 1 for a boolean column. */
const truthy = (v: unknown) => v === true || v === 1 || v === "1" || v === "true";

export function isBanned(user: Record<string, unknown>, now: Date): boolean {
  if (!truthy(user.banned)) return false;
  const exp = user.banExpires;
  if (exp === null || exp === undefined) return true;
  const t = exp instanceof Date ? exp.getTime() : new Date(exp as string | number).getTime();
  return Number.isNaN(t) || t > now.getTime();
}

type Refusal = { code: SamlIdpErrorCode; detail: string };

/**
 * Immediately before signing: re-read the user (and, where the database holds sessions, the
 * session) from the database (ADDENDUM-01 R3), then apply the account policy. A session served
 * from a KV cache can outlive revocation (better-auth-cloudflare #61); the database is the
 * source of truth. An IdP vouches for identities, so the defaults are strict: unverified email,
 * impersonation and anonymous users are refused (review finding #1).
 */
async function eligiblePrincipal(
  ctx: GenericEndpointContext,
  state: PluginState,
  session: SessionWithUser,
  now: Date,
): Promise<{ user: SamlIdpUser } | Refusal> {
  const user = (await ctx.context.internalAdapter.findUserById(session.user.id)) as SamlIdpUser | null;
  if (!user) return { code: "ACCOUNT_INACTIVE", detail: "user no longer exists" };
  if (isBanned(user, now)) return { code: "ACCOUNT_INACTIVE", detail: "user is banned" };

  const opts = ctx.context.options as { secondaryStorage?: unknown; session?: { storeSessionInDatabase?: boolean } };
  const sessionsInDatabase = !opts.secondaryStorage || opts.session?.storeSessionInDatabase === true;
  let impersonatedBy = session.session.impersonatedBy;
  if (sessionsInDatabase) {
    const row = (await ctx.context.adapter.findOne({
      model: "session",
      where: [{ field: "token", value: session.session.token }],
    })) as { expiresAt: Date | string; impersonatedBy?: unknown } | null;
    if (!row) return { code: "ACCOUNT_INACTIVE", detail: "session no longer exists" };
    if (new Date(row.expiresAt).getTime() <= now.getTime()) return { code: "ACCOUNT_INACTIVE", detail: "session expired" };
    impersonatedBy = row.impersonatedBy;
  }

  const policy = state.options.accountPolicy;
  if (policy.requireEmailVerified && !truthy(user.emailVerified)) return { code: "EMAIL_NOT_VERIFIED", detail: `user ${user.id}` };
  if (!policy.allowImpersonatedSessions && impersonatedBy) return { code: "SESSION_NOT_ALLOWED", detail: "impersonated session" };
  if (!policy.allowAnonymousUsers && truthy(user.isAnonymous)) return { code: "SESSION_NOT_ALLOWED", detail: "anonymous user" };
  return { user };
}

/**
 * NameID per format when the host supplies no `nameId` function (review finding #11):
 * persistent → opaque, stable, per-SP, never re-assigned (HMAC of user id, keyed with the
 * Better Auth secret); transient → one-time random; otherwise the (verified) email.
 */
function defaultNameId(ctx: GenericEndpointContext, sp: ResolvedServiceProvider, user: SamlIdpUser): string {
  if (sp.nameIdFormat === NAMEID_FORMAT.persistent) {
    const mac = createHmac("sha256", ctx.context.secret).update(`saml-idp:persistent\u0000${sp.entityId}\u0000${user.id}`).digest();
    return base64url(new Uint8Array(mac));
  }
  if (sp.nameIdFormat === NAMEID_FORMAT.transient) return newSamlId();
  return user.email;
}

export async function issueResponse(
  ctx: GenericEndpointContext,
  state: PluginState,
  sp: ResolvedServiceProvider,
  session: SessionWithUser,
  request: ValidatedRequest,
): Promise<Response> {
  sp = await prepareSp(ctx, state, sp); // the encryption certificate may come from metadata
  const now = new Date();
  const principal = await eligiblePrincipal(ctx, state, session, now);
  if ("code" in principal) return fail(ctx, principal.code, principal.detail);
  const user = principal.user;

  // Organization plugin (D-031): memberships for the SP's organization rule, attributes and
  // authorize(). An SP that requires an organization fails closed without the plugin.
  const orgPlugin = hasOrganizationPlugin(ctx.context.options.plugins as { id: string }[] | undefined);
  if (sp.organization && !orgPlugin) return fail(ctx, "ACCESS_DENIED", `SP ${sp.id} requires an organization, but the organization plugin isn't installed`);
  let organizations: OrganizationMembership[] = [];
  if (orgPlugin) {
    try {
      organizations = await loadMemberships(ctx.context.adapter as any, user.id);
    } catch (e) {
      ctx.context.logger.error(`[saml-idp] could not load organization memberships for SP ${sp.id}`, e);
      return fail(ctx, "INTERNAL_ERROR");
    }
  }
  const organization = sp.organization ? matchOrganization(organizations, sp.organization) : undefined;
  if (sp.organization && !organization) return fail(ctx, "ACCESS_DENIED", `user ${user.id} is not a member of SP ${sp.id}'s organization (with an allowed role)`);

  let allowed = false;
  try {
    allowed = await sp.authorize({ user, session: session.session as any, serviceProvider: sp, organizations });
  } catch (e) {
    ctx.context.logger.error(`[saml-idp] authorize() threw for SP ${sp.id}`, e);
    allowed = false;
  }
  if (allowed !== true) return fail(ctx, "ACCESS_DENIED", `authorize() denied user ${user.id} for SP ${sp.id}`);

  let nameId: unknown;
  let attributes: ReturnType<ResolvedServiceProvider["attributes"]>;
  try {
    nameId = sp.nameId ? sp.nameId(user) : defaultNameId(ctx, sp, user);
    attributes = sp.attributes(user, { organizations, organization }, (field) => warnMissingField(ctx, sp, field));
  } catch (e) {
    ctx.context.logger.error(`[saml-idp] nameId()/attributes() threw for SP ${sp.id}`, e);
    return fail(ctx, "INTERNAL_ERROR");
  }
  if (typeof nameId !== "string" || nameId.length === 0) {
    ctx.context.logger.error(`[saml-idp] nameId() returned an empty value for SP ${sp.id}`);
    return fail(ctx, "INTERNAL_ERROR");
  }
  // An identifier is never altered: one XML can't carry is refused (D-036).
  if (hasNonXmlChars(nameId)) {
    ctx.context.logger.error(`[saml-idp] the NameID for SP ${sp.id} contains characters XML can't carry; not issuing`);
    return fail(ctx, "INTERNAL_ERROR");
  }

  // The SP asked about a specific principal: answer only for that one (Core §3.4.1.4).
  if (request.subject) {
    const formatOk = !request.subject.format || request.subject.format === sp.nameIdFormat || request.subject.format === NAMEID_FORMAT.unspecified;
    if (!formatOk || request.subject.nameId !== nameId)
      return samlError(ctx, state, request, { code: "Responder", subCode: "UnknownPrincipal", message: "The signed-in user is not the requested subject" });
  }

  const sessionIndex = sessionIndexOf(ctx.context.secret, session.session.id, sp.id);
  const signed = buildSignedResponse(state.options, {
    requestId: request.requestId,
    acsUrl: request.acsUrl,
    audience: sp.entityId,
    nameId,
    nameIdFormat: sp.nameIdFormat,
    attributes,
    authnInstant: new Date(session.session.createdAt),
    sessionIndex,
    now,
  }, { response: sp.signResponse, assertion: sp.signAssertion }, sp.encryption);
  ctx.context.logger.info(
    `[saml-idp] issued ${signed.encrypted ? "encrypted " : ""}assertion ${signed.assertionId} for SP ${sp.id} (user ${user.id})`,
  );
  if (state.options.singleLogout) {
    // Logout must be able to reach this SP later (D-028). If it can't be recorded, don't issue:
    // a later logout would skip this SP and still report Success (review 3, R3-2).
    try {
      await recordParticipant(ctx.context.adapter as any, session.session.id, { spId: sp.id, nameId, nameIdFormat: sp.nameIdFormat, sessionIndex }, new Date(session.session.expiresAt));
    } catch (e) {
      ctx.context.logger.error(`[saml-idp] could not record SP ${sp.id} as a logout participant; not issuing`, e);
      return fail(ctx, "INTERNAL_ERROR", "logout participant not recorded");
    }
  }
  return autoPostResponse(request.acsUrl, signed.base64, request.relayState);
}
