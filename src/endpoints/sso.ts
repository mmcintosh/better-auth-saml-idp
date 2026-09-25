import type { GenericEndpointContext } from "better-auth";
import { createAuthEndpoint, getSessionFromCtx } from "better-auth/api";
import * as z from "zod";
import { SSO_PATH } from "../saml/idp";
import {
  checkNameIdPolicy,
  checkRelayState,
  checkRequestSignature,
  decodeAuthnRequest,
  parseAuthnRequest,
  REQUEST_MAX_AGE_SECONDS,
  SamlRequestError,
  type RawAuthnRequest,
} from "../saml/request";
import { resolveAcsUrl } from "../saml/sp-registry";
import { newOpaqueToken, sha256b64url, storePending } from "../storage/pending";
import { recordRequestId } from "../storage/seen";
import { fail, issueResponse, type PluginState } from "./issue";

export const RESUME_PATH = "/saml2/idp/resume";
export const BINDING_COOKIE = "saml_idp_binding";

const params = z.object({
  SAMLRequest: z.string().optional(),
  RelayState: z.string().optional(),
  SigAlg: z.string().optional(),
  Signature: z.string().optional(),
});

/** Where the browser goes to sign in, carrying the resume URL as `callbackURL`. */
export function loginRedirectUrl(ctx: GenericEndpointContext, loginPage: string, rid: string): string {
  const base = ctx.context.baseURL.replace(/\/+$/, "");
  const login = new URL(loginPage, new URL(base).origin);
  login.searchParams.set("callbackURL", `${base}${RESUME_PATH}?rid=${rid}`);
  return login.toString();
}

/** A per-browser random value in a signed cookie; pending requests store its hash (R1 hygiene). */
export async function bindingValue(ctx: GenericEndpointContext, create: boolean): Promise<string | null> {
  const cookie = ctx.context.createAuthCookie(BINDING_COOKIE);
  const existing = await ctx.getSignedCookie(cookie.name, ctx.context.secret);
  if (existing) return existing;
  if (!create) return null;
  const value = newOpaqueToken();
  await ctx.setSignedCookie(cookie.name, value, ctx.context.secret, { ...cookie.attributes, maxAge: 60 * 60 * 24 });
  return value;
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
      const isPost = ctx.request?.method === "POST";
      const src = (isPost ? ctx.body : ctx.query) ?? {};
      const raw: RawAuthnRequest = {
        binding: isPost ? "post" : "redirect",
        samlRequest: src.SAMLRequest ?? "",
        relayState: src.RelayState,
        rawQuery: !isPost && ctx.request ? new URL(ctx.request.url).search.slice(1) : undefined,
        sigAlg: isPost ? undefined : src.SigAlg,
        signature: isPost ? undefined : src.Signature,
      };
      const now = new Date();
      const ssoUrl = `${ctx.context.baseURL.replace(/\/+$/, "")}${SSO_PATH}`;

      let requestId: string, acsUrl: string, forceAuthn: boolean, isPassive: boolean;
      let sp;
      try {
        checkRelayState(raw.relayState, options.relayStateMaxBytes);
        const xml = await decodeAuthnRequest(raw);
        const info = await parseAuthnRequest(xml, options.schemaValidator, {
          now,
          clockSkewSeconds: options.clockSkewSeconds,
          ssoUrl,
        });
        sp = registry.byEntityId(info.issuer);
        if (!sp) return fail(ctx, "UNKNOWN_SERVICE_PROVIDER", `issuer not registered (${info.issuer.length} chars)`);
        checkNameIdPolicy(info, sp);
        checkRequestSignature(raw, sp, { allowInsecureSha1: options.signing.allowInsecureSha1 });
        const resolved = resolveAcsUrl(sp, info.acsUrl);
        if (!resolved) return fail(ctx, "ACS_URL_NOT_ALLOWED", `SP ${sp.id}`);
        ({ id: requestId, forceAuthn, isPassive } = info);
        acsUrl = resolved;
      } catch (e) {
        if (e instanceof SamlRequestError) return fail(ctx, e.code, e.detail);
        throw e;
      }

      // R2: first sight of (SP, request ID) wins; every later sighting is a replay.
      const expiresAt = new Date(now.getTime() + (REQUEST_MAX_AGE_SECONDS + 2 * options.clockSkewSeconds) * 1000);
      const fresh = await recordRequestId(ctx.context.adapter as any, sp.id, requestId, expiresAt, (err) =>
        ctx.context.logger.warn("[saml-idp] expired seen-request cleanup failed", err),
      );
      if (!fresh) return fail(ctx, "DUPLICATE_REQUEST_ID", `SP ${sp.id}`);

      const session = await getSessionFromCtx(ctx);
      if (session && !forceAuthn) {
        return issueResponse(ctx, state, sp, session as any, { requestId, acsUrl, relayState: raw.relayState });
      }
      if (isPassive) return fail(ctx, "PASSIVE_SIGN_IN_NOT_POSSIBLE", `SP ${sp.id}`);

      const binding = (await bindingValue(ctx, true))!;
      const rid = await storePending(
        ctx.context.internalAdapter,
        {
          spId: sp.id,
          requestId,
          acsUrl,
          relayState: raw.relayState,
          forceAuthn,
          createdAt: now.getTime(),
          bindingHash: await sha256b64url(binding),
        },
        options.pendingRequestTtlSeconds,
      );
      throw ctx.redirect(loginRedirectUrl(ctx, options.loginPage, rid));
    },
  );
