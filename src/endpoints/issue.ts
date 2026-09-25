import type { GenericEndpointContext } from "better-auth";
import { ERROR_STATUS, SAML_IDP_ERROR_CODES, type SamlIdpErrorCode } from "../errors";
import { autoPostResponse, errorPage } from "../saml/post-form";
import { buildSignedResponse } from "../saml/response";
import type { SpRegistry } from "../saml/sp-registry";
import { sha256b64url } from "../storage/pending";
import type { ResolvedSamlIdpOptions, ResolvedServiceProvider, SamlIdpUser } from "../types";

export interface PluginState {
  options: ResolvedSamlIdpOptions;
  registry: SpRegistry;
}

type SessionWithUser = { session: { id: string; token: string; createdAt: Date; expiresAt: Date }; user: { id: string } };

/** Error page for a plugin error code; the detail goes to the debug log only. */
export function fail(ctx: GenericEndpointContext, code: SamlIdpErrorCode, detail?: string): Response {
  ctx.context.logger.debug(`[saml-idp] ${code}${detail ? `: ${detail}` : ""}`);
  return errorPage(ERROR_STATUS[code], code, SAML_IDP_ERROR_CODES[code].message);
}

function isBanned(user: Record<string, unknown>, now: Date): boolean {
  if (user.banned !== true) return false;
  const exp = user.banExpires;
  if (exp === null || exp === undefined) return true;
  const t = exp instanceof Date ? exp.getTime() : new Date(exp as string | number).getTime();
  return Number.isNaN(t) || t > now.getTime();
}

/**
 * ADDENDUM-01 R3: re-read the user (and, where the database holds sessions, the session)
 * straight from the database immediately before signing. A session served from a KV cache
 * can outlive revocation (better-auth-cloudflare #61); the database is the source of truth.
 */
async function freshPrincipal(ctx: GenericEndpointContext, session: SessionWithUser, now: Date) {
  const user = (await ctx.context.internalAdapter.findUserById(session.user.id)) as SamlIdpUser | null;
  if (!user) return { error: "user no longer exists" as const };
  if (isBanned(user, now)) return { error: "user is banned" as const };

  const opts = ctx.context.options as { secondaryStorage?: unknown; session?: { storeSessionInDatabase?: boolean } };
  const sessionsInDatabase = !opts.secondaryStorage || opts.session?.storeSessionInDatabase === true;
  if (sessionsInDatabase) {
    const row = (await ctx.context.adapter.findOne({
      model: "session",
      where: [{ field: "token", value: session.session.token }],
    })) as { expiresAt: Date | string } | null;
    if (!row) return { error: "session no longer exists" as const };
    if (new Date(row.expiresAt).getTime() <= now.getTime()) return { error: "session expired" as const };
  }
  return { user };
}

export interface IssueRequest {
  requestId: string;
  acsUrl: string;
  relayState: string | undefined;
}

export async function issueResponse(
  ctx: GenericEndpointContext,
  state: PluginState,
  sp: ResolvedServiceProvider,
  session: SessionWithUser,
  request: IssueRequest,
): Promise<Response> {
  const now = new Date();
  const principal = await freshPrincipal(ctx, session, now);
  if ("error" in principal) return fail(ctx, "ACCOUNT_INACTIVE", principal.error);
  const user = principal.user;

  let allowed = false;
  try {
    allowed = await sp.authorize({ user, session: session.session as any, serviceProvider: sp });
  } catch (e) {
    ctx.context.logger.error(`[saml-idp] authorize() threw for SP ${sp.id}`, e);
    allowed = false;
  }
  if (allowed !== true) return fail(ctx, "ACCESS_DENIED", `authorize() denied user ${user.id} for SP ${sp.id}`);

  let nameId: unknown;
  let attributes: ReturnType<ResolvedServiceProvider["attributes"]>;
  try {
    nameId = sp.nameId(user);
    attributes = sp.attributes(user);
  } catch (e) {
    ctx.context.logger.error(`[saml-idp] nameId()/attributes() threw for SP ${sp.id}`, e);
    return fail(ctx, "INTERNAL_ERROR");
  }
  if (typeof nameId !== "string" || nameId.length === 0) {
    ctx.context.logger.error(`[saml-idp] nameId() returned an empty value for SP ${sp.id}`);
    return fail(ctx, "INTERNAL_ERROR");
  }

  const sessionIndex = `_${(await sha256b64url(`saml-idp:session\u0000${session.session.id}`)).slice(0, 32)}`;
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
  });
  ctx.context.logger.info(`[saml-idp] issued assertion ${signed.assertionId} for SP ${sp.id} (user ${user.id})`);
  return autoPostResponse(request.acsUrl, signed.base64, request.relayState);
}
