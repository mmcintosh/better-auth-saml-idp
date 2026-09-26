// SAML Single Logout (D-028), front-channel:
//  - /saml2/idp/slo receives an SP's LogoutRequest (SP-initiated) and the LogoutResponses of the
//    SPs we propagate to; /saml2/idp/logout starts an IdP-initiated logout.
//  - The IdP session ends FIRST; then each other participating SP gets a signed LogoutRequest
//    through the browser, one hop at a time (state in a single-use verification value named by
//    the RelayState); finally the originator gets a LogoutResponse (or the browser returnTo).
import { emit } from "../events";
import type { GenericEndpointContext } from "better-auth";
import { createAuthEndpoint, getSessionFromCtx } from "better-auth/api";
import { deleteSessionCookie } from "better-auth/cookies";
import * as z from "zod";
import { idpBaseURL } from "../saml/idp";
import { buildLogoutRequest, buildLogoutResponse, parseLogoutRequest, parseLogoutResponse, redirectBindingUrl, signedPostMessage, SLO_PATH } from "../saml/logout";
import { autoPostResponse, confirmPage } from "../saml/post-form";
import { checkRelayState, decodeAuthnRequest, isSigned, parseRedirectQuery, type RawAuthnRequest, SamlRequestError, verifyMessageSignature } from "../saml/request";
import { forgetParticipants, listParticipants, type Participant, sessionIndexOf } from "../storage/participants";
import { newOpaqueToken } from "../storage/pending";
import { recordRequestId } from "../storage/seen";
import { sweepExpired } from "../storage/sweep";
import type { ResolvedServiceProvider } from "../types";
import { isDriveByCrossSite } from "./init";
import { fail, lookupLog, type PluginState, prepareSp, spById } from "./issue";

export const LOGOUT_PATH = "/saml2/idp/logout";
const STATE_PREFIX = "saml-idp-logout:";
const CONTINUE_PREFIX = "saml-idp-logout-continue:";
const HOP_TTL_SECONDS = 300;
const TOKEN = /^[A-Za-z0-9_-]{43}$/;

type Origin = { kind: "sp"; spId: string; requestId: string; relayState?: string } | { kind: "idp"; returnTo: string };
interface LogoutState {
  origin: Origin;
  remaining: Participant[];
  current?: { spId: string; requestId: string };
  partial: boolean;
}
interface PendingLogoutRequest {
  spId: string;
  requestId: string;
  relayState?: string;
  nameId: string;
  sessionIndexes: string[];
  signed: boolean;
}

const params = z.object({
  SAMLRequest: z.string().optional(),
  SAMLResponse: z.string().optional(),
  RelayState: z.string().optional(),
  SigAlg: z.string().optional(),
  Signature: z.string().optional(),
  cid: z.string().max(128).optional(),
});

type Adapter = GenericEndpointContext["context"]["internalAdapter"];

async function store(adapter: Adapter, prefix: string, value: unknown): Promise<string> {
  const id = newOpaqueToken();
  await adapter.createVerificationValue({ identifier: prefix + id, value: JSON.stringify(value), expiresAt: new Date(Date.now() + HOP_TTL_SECONDS * 1000) });
  return id;
}
async function consume<T>(adapter: Adapter, prefix: string, id: string | undefined): Promise<T | null> {
  if (!id || !TOKEN.test(id)) return null;
  const row = await adapter.consumeVerificationValue(prefix + id);
  if (!row) return null;
  try {
    return JSON.parse(row.value) as T;
  } catch {
    return null;
  }
}

/**
 * Must this SP's logout messages be signed? When it has certificates, requires signed
 * AuthnRequests, or gets its certificates from metadata (which may have failed to load).
 */
const mustSign = (sp: ResolvedServiceProvider) => sp.spCertificates.length > 0 || sp.requireSignedAuthnRequests || sp.metadata !== undefined;

const sloUrl = (ctx: GenericEndpointContext, state: PluginState) => `${idpBaseURL(state.options, ctx.context.baseURL)}${SLO_PATH}`;

/** End the IdP session: the Better Auth session row, its cookies, and its participant list. */
/** Participants of a session; `partial` when they couldn't all be listed (so logout can't claim Success). */
async function participantsOf(ctx: GenericEndpointContext, sessionId: string): Promise<{ participants: Participant[]; partial: boolean }> {
  try {
    const r = await listParticipants(ctx.context.adapter as any, sessionId);
    if (r.truncated) ctx.context.logger.warn("[saml-idp] logout: more participants than can be notified; reporting PartialLogout");
    return { participants: r.participants, partial: r.truncated };
  } catch (e) {
    ctx.context.logger.error("[saml-idp] logout: could not list participants; reporting PartialLogout", e);
    return { participants: [], partial: true };
  }
}

async function endSession(ctx: GenericEndpointContext, session: { session: { id: string; token: string } }): Promise<{ participants: Participant[]; partial: boolean }> {
  const adapter = ctx.context.adapter as any;
  const { participants, partial } = await participantsOf(ctx, session.session.id);
  await ctx.context.internalAdapter.deleteSession(session.session.token);
  deleteSessionCookie(ctx);
  await forgetParticipants(adapter, session.session.id).catch((e) => ctx.context.logger.warn("[saml-idp] could not clear logout participants", e));
  ctx.context.logger.info(`[saml-idp] logout: ended IdP session; ${participants.length} SP(s) to notify`);
  return { participants, partial };
}

/** Send the browser to the next SP, or finish with the originator. */
async function nextHop(ctx: GenericEndpointContext, state: PluginState, ls: LogoutState): Promise<Response | never> {
  while (ls.remaining.length) {
    const p = ls.remaining.shift() as Participant;
    const sp = await spById(ctx, state, p.spId);
    if (!sp?.singleLogoutService) {
      ls.partial = true; // can't reach it: the originator is told it was partial
      continue;
    }
    const { id, xml } = buildLogoutRequest({
      issuer: state.options.entityId,
      destination: sp.singleLogoutService.url,
      nameId: p.nameId,
      nameIdFormat: p.nameIdFormat,
      sessionIndex: p.sessionIndex,
      now: new Date(),
      lifetimeSeconds: HOP_TTL_SECONDS,
    });
    ls.current = { spId: sp.id, requestId: id };
    const sid = await store(ctx.context.internalAdapter, STATE_PREFIX, ls);
    // The reply needs no cookies (its state is in RelayState), so either binding works.
    if (sp.singleLogoutService.binding === "post")
      return autoPostResponse(sp.singleLogoutService.url, signedPostMessage(xml, "LogoutRequest", state.options.signing), sid, "SAMLRequest");
    throw ctx.redirect(redirectBindingUrl(sp.singleLogoutService.url, "SAMLRequest", xml, sid, state.options.signing));
  }
  return finish(ctx, state, ls);
}

async function finish(ctx: GenericEndpointContext, state: PluginState, ls: LogoutState): Promise<Response | never> {
  if (ls.origin.kind === "idp") throw ctx.redirect(ls.origin.returnTo);
  const sp = await spById(ctx, state, ls.origin.spId);
  if (!sp?.singleLogoutService) return fail(ctx, state, "LOGOUT_NOT_SUPPORTED", `originating SP ${ls.origin.spId} has no SLO endpoint any more`, { spId: ls.origin.spId });
  // Metadata's ResponseLocation, when the SP has one, is where responses go (Metadata §2.2.2).
  const responseUrl = sp.singleLogoutService.responseUrl ?? sp.singleLogoutService.url;
  const xml = buildLogoutResponse({
    issuer: state.options.entityId,
    destination: responseUrl,
    inResponseTo: ls.origin.requestId,
    status: ls.partial ? ["Success", "PartialLogout"] : ["Success"],
    now: new Date(),
  });
  ctx.context.logger.info(`[saml-idp] logout: answering SP ${sp.id}${ls.partial ? " (partial)" : ""}`);
  if (sp.singleLogoutService.binding === "post")
    return autoPostResponse(responseUrl, signedPostMessage(xml, "LogoutResponse", state.options.signing), ls.origin.relayState);
  throw ctx.redirect(redirectBindingUrl(responseUrl, "SAMLResponse", xml, ls.origin.relayState, state.options.signing));
}

/**
 * An authenticated SP LogoutRequest, now on a same-site GET (so the session cookie is here).
 * The session ends only if the request is about THIS browser's session: its SessionIndex (an
 * unguessable hash of the session id) must match; a signed request without SessionIndex must
 * name the NameID this SP was given in this session.
 */
async function handleLogoutRequest(ctx: GenericEndpointContext, state: PluginState, sp: ResolvedServiceProvider, req: PendingLogoutRequest) {
  const origin: Origin = { kind: "sp", spId: sp.id, requestId: req.requestId, relayState: req.relayState };
  const session = await getSessionFromCtx(ctx);
  if (!session) return finish(ctx, state, { origin, remaining: [], partial: false }); // nothing to end here
  // The value issued to THIS SP (the Issuer) for this session; no other SP knows it.
  const expectedIndex = sessionIndexOf(ctx.context.secret, session.session.id, sp.id);
  const { participants } = await participantsOf(ctx, session.session.id);
  const mine = participants.find((p) => p.spId === sp.id);
  const byIndex = req.sessionIndexes.includes(expectedIndex);
  const byNameId = req.signed && req.sessionIndexes.length === 0 && mine !== undefined && mine.nameId === req.nameId;
  if (!byIndex && !byNameId) {
    ctx.context.logger.info(`[saml-idp] logout from SP ${sp.id} doesn't match this browser's session; nothing ended`);
    return finish(ctx, state, { origin, remaining: [], partial: false });
  }
  const ended = await endSession(ctx, session);
  const remaining = ended.participants.filter((p) => p.spId !== sp.id);
  emit(ctx, state.options, { type: "logout", initiatedBy: "sp", spId: sp.id, userId: session.user.id, sessionId: session.session.id, notifying: remaining.map((p) => p.spId) });
  return nextHop(ctx, state, { origin, remaining, partial: ended.partial });
}

function rawFrom(ctx: GenericEndpointContext, isPost: boolean, param: "SAMLRequest" | "SAMLResponse"): RawAuthnRequest {
  if (isPost) {
    const body = (ctx.body ?? {}) as Record<string, string | undefined>;
    return { binding: "post", samlRequest: body[param] ?? "", relayState: body.RelayState };
  }
  return parseRedirectQuery(ctx.request ? new URL(ctx.request.url).search.slice(1) : "", param);
}

export const sloEndpoint = (state: PluginState) =>
  createAuthEndpoint(
    SLO_PATH,
    {
      method: ["GET", "POST"],
      query: params.optional(),
      body: params.optional(),
      metadata: {
        allowedMediaTypes: ["application/x-www-form-urlencoded"],
        openapi: { operationId: "samlIdpSingleLogout", summary: "SAML Single Logout endpoint (HTTP-Redirect and HTTP-POST bindings)" },
      },
    },
    async (ctx) => {
      const { options } = state;
      await sweepExpired(ctx.context.adapter as any, (what, e) => ctx.context.logger.warn(`[saml-idp] cleanup of expired ${what} failed`, e), Date.now(), { participants: true, auditLog: state.options.auditLog !== undefined });
      const isPost = ctx.request?.method === "POST";
      const input = ((isPost ? ctx.body : ctx.query) ?? {}) as z.infer<typeof params>;
      const now = new Date();
      const parseOpts = { now, clockSkewSeconds: options.clockSkewSeconds, sloUrl: sloUrl(ctx, state) };
      const sigOpts = { allowInsecureSha1: options.signing.allowInsecureSha1 };

      try {
        // Re-entry of an HTTP-POST LogoutRequest on a same-site GET (cookies now present).
        if (!isPost && input.cid !== undefined) {
          const req = await consume<PendingLogoutRequest>(ctx.context.internalAdapter, CONTINUE_PREFIX, input.cid);
          if (!req) return fail(ctx, state, "LOGOUT_STATE_NOT_FOUND", "unknown or used logout continuation");
          const sp = await spById(ctx, state, req.spId);
          if (!sp?.singleLogoutService) return fail(ctx, state, "LOGOUT_NOT_SUPPORTED", `SP ${req.spId}`, { spId: req.spId });
          return await handleLogoutRequest(ctx, state, sp, req);
        }

        // A participant's answer to our LogoutRequest: continue the chain whatever it says.
        if (input.SAMLResponse !== undefined) {
          const raw = rawFrom(ctx, isPost, "SAMLResponse");
          const ls = await consume<LogoutState>(ctx.context.internalAdapter, STATE_PREFIX, raw.relayState);
          if (!ls?.current) return fail(ctx, state, "LOGOUT_STATE_NOT_FOUND", "unknown or used logout state");
          const sp = await spById(ctx, state, ls.current.spId);
          try {
            const xml = await decodeAuthnRequest(raw);
            const info = await parseLogoutResponse(xml, options.schemaValidator, parseOpts);
            if (!sp || info.issuer !== sp.entityId || info.inResponseTo !== ls.current.requestId) throw new Error("not the answer we're waiting for");
            const ready = await prepareSp(ctx, state, sp);
            if (mustSign(ready)) {
              if (ready.spCertificates.length === 0) throw new Error("no certificate available to verify it");
              verifyMessageSignature(raw, xml, ready.spCertificates, sigOpts);
            }
            if (isSigned(raw, xml) && info.destination === undefined) throw new Error("signed without Destination");
            if (info.status[0] !== "Success" || info.status[1] === "PartialLogout") ls.partial = true;
          } catch (e) {
            ls.partial = true;
            ctx.context.logger.warn(`[saml-idp] logout: SP ${ls.current.spId} answered badly (${(e as Error).message}); continuing`);
          }
          ls.current = undefined;
          return await nextHop(ctx, state, ls);
        }

        // An SP's LogoutRequest.
        const raw = rawFrom(ctx, isPost, "SAMLRequest");
        checkRelayState(raw.relayState, options.relayStateMaxBytes);
        const xml = await decodeAuthnRequest(raw);
        const info = await parseLogoutRequest(xml, options.schemaValidator, parseOpts);
        const found = await state.directory.byEntityId(ctx.context.adapter as any, info.issuer, lookupLog(ctx));
        if (!found) return fail(ctx, state, "UNKNOWN_SERVICE_PROVIDER", `logout: issuer not registered (${info.issuer.length} chars)`);
        const sp = await prepareSp(ctx, state, found);
        if (!sp.singleLogoutService) return fail(ctx, state, "LOGOUT_NOT_SUPPORTED", `SP ${sp.id} has no singleLogoutService`, { spId: sp.id });
        // Profiles §4.4.4.1: a LogoutRequest must be authenticated. With SP certificates: a valid
        // signature. Without: only the session binding in handleLogoutRequest (SessionIndex).
        const signed = isSigned(raw, xml);
        if (mustSign(sp)) {
          if (!signed) throw new SamlRequestError("UNSIGNED_SAML_REQUEST", "LogoutRequest must be signed");
          // Certificates from a metadata URL that failed to load: fail closed, as for AuthnRequests.
          if (sp.spCertificates.length === 0) throw new SamlRequestError("UNSIGNED_SAML_REQUEST", "no SP certificate available to verify the LogoutRequest");
          verifyMessageSignature(raw, xml, sp.spCertificates, sigOpts);
        }
        // Bindings §3.4.5.2 / §3.5.5.2: a signed message must say where it's going.
        if (signed && info.destination === undefined) throw new SamlRequestError("INVALID_SAML_REQUEST", "a signed LogoutRequest needs a Destination");
        const expiresAt = new Date(now.getTime() + (300 + 2 * options.clockSkewSeconds) * 1000);
        if (!(await recordRequestId(ctx.context.adapter as any, sp.id, `logout:${info.id}`, expiresAt))) return fail(ctx, state, "DUPLICATE_REQUEST_ID", `SP ${sp.id}`, { spId: sp.id });
        const req: PendingLogoutRequest = {
          spId: sp.id,
          requestId: info.id,
          relayState: raw.relayState,
          nameId: info.nameId,
          sessionIndexes: info.sessionIndexes,
          signed: mustSign(sp) && signed,
        };
        if (isPost) {
          const cid = await store(ctx.context.internalAdapter, CONTINUE_PREFIX, req);
          return new Response(null, { status: 303, headers: { Location: `${sloUrl(ctx, state)}?cid=${cid}`, "Cache-Control": "no-store" } });
        }
        return await handleLogoutRequest(ctx, state, sp, req);
      } catch (e) {
        if (e instanceof SamlRequestError) return fail(ctx, state, e.code, e.detail);
        throw e;
      }
    },
  );

/** Where IdP-initiated logout may send the browser afterwards: a same-origin path or a trusted origin. */
function safeReturnTo(ctx: GenericEndpointContext, state: PluginState, returnTo: string | undefined): string | undefined {
  const base = new URL(idpBaseURL(state.options, ctx.context.baseURL));
  if (returnTo === undefined || returnTo === "") return `${base.origin}/`;
  // biome-ignore lint/suspicious/noControlCharactersInRegex: rejecting control characters is the point
  if (/[\\\s\u0000-\u001f\u007f]/.test(returnTo)) return undefined;
  if (returnTo.startsWith("/") && !returnTo.startsWith("//")) return `${base.origin}${returnTo}`;
  return ctx.context.isTrustedOrigin(returnTo) ? returnTo : undefined;
}

export const logoutEndpoint = (state: PluginState) =>
  createAuthEndpoint(
    LOGOUT_PATH,
    {
      method: "GET",
      query: z.object({ returnTo: z.string().max(2048).optional() }).optional(),
      metadata: { openapi: { operationId: "samlIdpLogout", summary: "Log out of the IdP and every SP that got an assertion in this session" } },
    },
    async (ctx) => {
      const returnTo = safeReturnTo(ctx, state, ctx.query?.returnTo);
      if (!returnTo) return fail(ctx, state, "INVALID_RETURN_TO", "returnTo is not a same-origin path or a trusted origin");
      const session = await getSessionFromCtx(ctx);
      if (!session) throw ctx.redirect(returnTo);
      // Logout CSRF: another site can't silently log the user out everywhere.
      if (isDriveByCrossSite(ctx)) return confirmPage(ctx.request?.url ?? `${idpBaseURL(state.options, ctx.context.baseURL)}${LOGOUT_PATH}`, "", "sign-out");
      const ended = await endSession(ctx, session);
      emit(ctx, state.options, { type: "logout", initiatedBy: "idp", userId: session.user.id, sessionId: session.session.id, notifying: ended.participants.map((p) => p.spId) });
      return nextHop(ctx, state, { origin: { kind: "idp", returnTo }, remaining: ended.participants, partial: ended.partial });
    },
  );
