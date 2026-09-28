import { createHmac } from "node:crypto";
import type { GenericEndpointContext } from "better-auth";
import { isStateful } from "better-auth/api";
import { ERROR_STATUS, SAML_IDP_ERROR_CODES, type SamlIdpErrorCode } from "../errors";
import { warnUserWritableFields } from "../attributes";
import { emit } from "../events";
import { autoPostResponse, errorPage } from "../saml/post-form";
import { logSafe, type SamlStatus, satisfiesAuthnContext, stepUpTarget } from "../saml/request";
import { buildSignedErrorResponse, buildSignedResponse, hasNonXmlChars, newSamlId } from "../saml/response";
import type { SpMetadataCache } from "../saml/sp-metadata-refresh";
import type { SpDirectory } from "../saml/sp-directory";
import { hasOrganizationPlugin, loadMemberships, matchOrganization, warnClaimableOrganizations } from "../organizations";
import { recordParticipant, sessionIndexOf } from "../storage/participants";
import { base64url, type ValidatedRequest } from "../storage/pending";
import { type AuthorizeResult, NAMEID_FORMAT, type OrganizationMembership, type ResolvedSamlIdpOptions, type ResolvedServiceProvider, type SamlIdpUser, type ServiceProviderInfo } from "../types";
// A cycle (sso imports this module), fine for functions used at call time.
import { parkForLogin } from "./sso";
import { nameIdFieldProblem } from "../nameid";

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
export function fail(
  ctx: GenericEndpointContext,
  state: Pick<PluginState, "options">,
  code: SamlIdpErrorCode,
  detail?: string,
  who: { spId?: string; userId?: string } = {},
): Response {
  const safe = detail ? logSafe(detail, 300) : undefined;
  ctx.context.logger.debug(`[saml-idp] ${code}${safe ? `: ${safe}` : ""}`);
  emit(ctx, state.options, { type: "denied", code, ...(who.spId ? { spId: who.spId } : {}), ...(who.userId ? { userId: who.userId } : {}), ...(safe ? { detail: safe } : {}) });
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
  userId?: string,
): Response {
  ctx.context.logger.debug(`[saml-idp] SAML status ${status.code}/${status.subCode ?? "-"} for SP ${req.spId}`);
  emit(ctx, state.options, {
    type: "denied",
    code: "SAML_STATUS",
    status: { code: status.code, ...(status.subCode ? { subCode: status.subCode } : {}) },
    spId: req.spId,
    ...(userId ? { userId } : {}),
    ...(status.message ? { detail: logSafe(status.message, 300) } : {}),
  });
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
): Promise<{ user: SamlIdpUser; session: Record<string, unknown> } | Refusal> {
  const user = (await ctx.context.internalAdapter.findUserById(session.user.id)) as SamlIdpUser | null;
  if (!user) return { code: "ACCOUNT_INACTIVE", detail: "user no longer exists" };
  if (isBanned(user, now)) return { code: "ACCOUNT_INACTIVE", detail: "user is banned" };

  // Re-read the session from its authoritative store right before signing:
  // - the database whenever it holds sessions, even with secondary storage in front: KV is
  //   eventually consistent, so a revocation elsewhere may not have reached this location's copy;
  // - otherwise secondary storage, the only record (R4-2: this case used to be skipped).
  // Stateless hosts have no server-side record; their signed cookie is the session.
  const opts = ctx.context.options as { secondaryStorage?: unknown; session?: { storeSessionInDatabase?: boolean } };
  const sessionsInDatabase = !opts.secondaryStorage || opts.session?.storeSessionInDatabase === true;
  let impersonatedBy = session.session.impersonatedBy;
  let current: ({ expiresAt: Date | string; impersonatedBy?: unknown } & Record<string, unknown>) | null | undefined;
  if (sessionsInDatabase) {
    current = (await ctx.context.adapter.findOne({ model: "session", where: [{ field: "token", value: session.session.token }] })) as typeof current;
  } else if (isStateful(ctx)) {
    current = ((await ctx.context.internalAdapter.findSession(session.session.token)) as { session: NonNullable<typeof current> } | null)?.session ?? null;
  }
  if (current !== undefined) {
    if (!current) return { code: "ACCOUNT_INACTIVE", detail: "session no longer exists" };
    if (new Date(current.expiresAt).getTime() <= now.getTime()) return { code: "ACCOUNT_INACTIVE", detail: "session expired" };
    impersonatedBy = current.impersonatedBy;
  }

  const policy = state.options.accountPolicy;
  if (policy.requireEmailVerified && !truthy(user.emailVerified)) return { code: "EMAIL_NOT_VERIFIED", detail: `user ${user.id}` };
  if (!policy.allowImpersonatedSessions && impersonatedBy) return { code: "SESSION_NOT_ALLOWED", detail: "impersonated session" };
  if (!policy.allowAnonymousUsers && truthy(user.isAnonymous)) return { code: "SESSION_NOT_ALLOWED", detail: "anonymous user" };
  // authorize() sees the row this read just proved exists (with host fields such as an MFA time),
  // not the copy from the start of the request.
  return { user, session: (current ?? session.session) as Record<string, unknown> };
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

/** `SessionNotOnOrAfter` for this SP (D-043): never past the IdP session's own expiry. */
export function sessionEnd(limit: ResolvedServiceProvider["sessionNotOnOrAfter"], sessionExpiresAt: Date, now: Date): Date | undefined {
  if (limit === false) return undefined;
  if (limit === "idp-session") return sessionExpiresAt;
  return new Date(Math.min(sessionExpiresAt.getTime(), now.getTime() + limit.maxSeconds * 1000));
}

/** The public, read-only view of an SP that callbacks receive (not the internal resolved form). */
export function serviceProviderInfo(sp: ResolvedServiceProvider): ServiceProviderInfo {
  return Object.freeze({
    id: sp.id,
    entityId: sp.entityId,
    acsUrls: Object.freeze([...sp.acsUrls]),
    nameIdFormat: sp.nameIdFormat,
    organization: sp.organization ? Object.freeze({ ...sp.organization, ...(sp.organization.roles ? { roles: Object.freeze([...sp.organization.roles]) } : {}) }) : undefined,
  });
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
  if ("code" in principal) return fail(ctx, state, principal.code, principal.detail, { spId: sp.id, userId: session.user.id });
  const user = principal.user;
  const who = { spId: sp.id, userId: user.id };

  // Organization plugin (D-031): memberships for the SP's organization rule, attributes and
  // authorize(). An SP that requires an organization fails closed without the plugin.
  const orgPlugin = hasOrganizationPlugin(ctx.context.options.plugins as { id: string }[] | undefined);
  if (orgPlugin) warnClaimableOrganizations(ctx.context.logger, ctx.context.options.plugins as any, sp);
  warnUserWritableFields(ctx.context.logger, ctx.context.options.user as any, sp);
  if (sp.organization && !orgPlugin) return fail(ctx, state, "ACCESS_DENIED", `SP ${sp.id} requires an organization, but the organization plugin isn't installed`, who);
  let organizations: OrganizationMembership[] = [];
  if (orgPlugin) {
    try {
      organizations = await loadMemberships(ctx.context.adapter as any, user.id);
    } catch (e) {
      ctx.context.logger.error(`[saml-idp] could not load organization memberships for SP ${sp.id}`, e);
      return fail(ctx, state, "INTERNAL_ERROR", undefined, who);
    }
  }
  const organization = sp.organization ? matchOrganization(organizations, sp.organization) : undefined;
  if (sp.organization && !organization) return fail(ctx, state, "ACCESS_DENIED", `user ${user.id} is not a member of SP ${sp.id}'s organization (with an allowed role)`, who);

  let verdict: AuthorizeResult = false;
  try {
    verdict = await sp.authorize({ user, session: principal.session as any, serviceProvider: serviceProviderInfo(sp), organizations });
  } catch (e) {
    ctx.context.logger.error(`[saml-idp] authorize() threw for SP ${sp.id}`, e);
    verdict = false;
  }
  const allowed = verdict === true || (typeof verdict === "object" && verdict !== null && verdict.allow === true);
  if (!allowed) {
    const denial = typeof verdict === "object" && verdict !== null && verdict.allow === false ? verdict : undefined;
    const why = `authorize() denied user ${user.id} for SP ${sp.id}${denial?.reason ? `: ${logSafe(String(denial.reason), 200)}` : ""}`;
    if (denial?.reauthenticate === true) {
      if (request.isPassive)
        return samlError(ctx, state, request, { code: "Responder", subCode: "NoPassive", message: "The identity provider requires the user to sign in again" }, user.id);
      // Loop guard: this request already made the user sign in again, and the fresh session
      // is still refused. Deny instead of sending them round once more.
      const freshForThis = request.forceAuthn && new Date(session.session.createdAt).getTime() >= request.createdAt;
      if (freshForThis) return fail(ctx, state, "ACCESS_DENIED", `${why} (still after signing in again)`, who);
      ctx.context.logger.info(`[saml-idp] ${why}; asking the user to sign in again`);
      // Park the request as a ForceAuthn one: resume only accepts a session created after now.
      return parkForLogin(ctx, state, { ...request, forceAuthn: true, createdAt: now.getTime() });
    }
    return fail(ctx, state, "ACCESS_DENIED", why, who);
  }

  // Step-up (D-047): which authentication class did this session achieve, and is it enough?
  let achievedClass: string | undefined;
  const levels = state.options.authnContext;
  if (levels) {
    try {
      achievedClass = await levels.current({ user, session: principal.session as any });
    } catch (e) {
      ctx.context.logger.error(`[saml-idp] authnContext.current() threw for SP ${sp.id}`, e);
      return fail(ctx, state, "INTERNAL_ERROR", undefined, who);
    }
    if (typeof achievedClass !== "string" || !levels.levels.includes(achievedClass)) {
      ctx.context.logger.error(`[saml-idp] authnContext.current() returned a class that isn't in levels, for SP ${sp.id}`);
      return fail(ctx, state, "INTERNAL_ERROR", undefined, who);
    }
    const requested = request.authnContext;
    if (requested && !satisfiesAuthnContext(requested, achievedClass, levels.levels)) {
      const target = stepUpTarget(requested, levels.levels);
      const noContext = { code: "Responder" as const, subCode: "NoAuthnContext" as const, message: "The requested authentication context is not available" };
      // "maximum": the session is already stronger than asked, and signing in again can't lower
      // what current() reports, so a round would be a dead end (review 5 R5-4).
      if (!target || requested.comparison === "maximum") return samlError(ctx, state, request, noContext, user.id);
      if (request.isPassive)
        return samlError(ctx, state, request, { code: "Responder", subCode: "NoPassive", message: "Stepping up authentication needs the user" }, user.id);
      // Loop guard: this request already made the user sign in again, and it still isn't enough.
      if (request.forceAuthn && new Date(session.session.createdAt).getTime() >= request.createdAt) return samlError(ctx, state, request, noContext, user.id);
      ctx.context.logger.info(`[saml-idp] SP ${sp.id} needs ${logSafe(target, 200)}; session has ${logSafe(achievedClass, 200)}: asking the user to sign in again`);
      return parkForLogin(ctx, state, { ...request, forceAuthn: true, createdAt: now.getTime() }, { acr: target });
    }
  }

  // Re-checked here, not only at startup/registry save: a field can become user-writable later.
  const fieldProblem = sp.nameIdField === undefined ? undefined : nameIdFieldProblem(sp.nameIdField, ctx.context.options as any);
  if (fieldProblem) {
    ctx.context.logger.error(`[saml-idp] SP ${sp.id}: ${fieldProblem}; not issuing`);
    return fail(ctx, state, "INTERNAL_ERROR", undefined, who);
  }
  let nameId: unknown;
  let attributes: ReturnType<ResolvedServiceProvider["attributes"]>;
  try {
    nameId = sp.nameId ? sp.nameId(user) : defaultNameId(ctx, sp, user);
    attributes = sp.attributes(user, { organizations, organization }, (field) => warnMissingField(ctx, sp, field));
  } catch (e) {
    ctx.context.logger.error(`[saml-idp] nameId()/attributes() threw for SP ${sp.id}`, e);
    return fail(ctx, state, "INTERNAL_ERROR", undefined, who);
  }
  if (sp.nameIdField !== undefined && nameId === "")
    return fail(ctx, state, "ACCESS_DENIED", `user ${user.id} has no value in ${sp.nameIdField}, SP ${sp.id}'s NameID field`, who);
  if (typeof nameId !== "string" || nameId.length === 0) {
    ctx.context.logger.error(`[saml-idp] nameId() returned an empty value for SP ${sp.id}`);
    return fail(ctx, state, "INTERNAL_ERROR", undefined, who);
  }
  // An identifier is never altered: one XML can't carry is refused (D-036).
  if (hasNonXmlChars(nameId)) {
    ctx.context.logger.error(`[saml-idp] the NameID for SP ${sp.id} contains characters XML can't carry; not issuing`);
    return fail(ctx, state, "INTERNAL_ERROR", undefined, who);
  }

  // The SP asked about a specific principal: answer only for that one (Core §3.4.1.4).
  if (request.subject) {
    const formatOk = !request.subject.format || request.subject.format === sp.nameIdFormat || request.subject.format === NAMEID_FORMAT.unspecified;
    if (!formatOk || request.subject.nameId !== nameId)
      return samlError(ctx, state, request, { code: "Responder", subCode: "UnknownPrincipal", message: "The signed-in user is not the requested subject" }, user.id);
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
    sessionNotOnOrAfter: sessionEnd(sp.sessionNotOnOrAfter, new Date(session.session.expiresAt), now),
    ...(achievedClass ? { authnContextClassRef: achievedClass } : {}),
    now,
  }, sp.sign, sp.encryption);
  ctx.context.logger.info(
    `[saml-idp] issued ${signed.encrypted ? "encrypted " : ""}assertion ${signed.assertionId} for SP ${sp.id} (user ${user.id})`,
  );
  if (state.options.sessionTracking) {
    // Logout must be able to reach this SP later (D-028), and a session that ends without it
    // must be able to name it (D-043). If it can't be recorded, don't issue: a later logout
    // would skip this SP and still report Success (review 3, R3-2).
    try {
      await recordParticipant(ctx.context.adapter as any, session.session.id, user.id, { spId: sp.id, nameId, nameIdFormat: sp.nameIdFormat, sessionIndex }, new Date(session.session.expiresAt));
    } catch (e) {
      ctx.context.logger.error(`[saml-idp] could not record SP ${sp.id} as a logout participant; not issuing`, e);
      return fail(ctx, state, "INTERNAL_ERROR", "logout participant not recorded", who);
    }
  }
  emit(ctx, state.options, {
    type: "assertion.issued",
    spId: sp.id,
    entityId: sp.entityId,
    userId: user.id,
    sessionId: session.session.id,
    assertionId: signed.assertionId,
    initiatedBy: request.requestId === undefined ? "idp" : "sp",
    ...(request.requestId !== undefined ? { inResponseTo: request.requestId } : {}),
    acsUrl: request.acsUrl,
    nameIdFormat: sp.nameIdFormat,
    nameId,
    attributes: Object.keys(attributes),
    encrypted: signed.encrypted,
  });
  return autoPostResponse(request.acsUrl, signed.base64, request.relayState);
}
