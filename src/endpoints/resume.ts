import { createAuthEndpoint, getAuthoritativeSessionFromCtx } from "better-auth/api";
import * as z from "zod";
import { resolveAcsUrl } from "../saml/sp-registry";
import { consumePending, sha256b64url } from "../storage/pending";
import { fail, issueResponse, type PluginState, spById } from "./issue";
import { bindingValue, loginRedirectUrl, RESUME_PATH } from "./sso";

export const resumeEndpoint = (state: PluginState) =>
  createAuthEndpoint(
    RESUME_PATH,
    {
      method: "GET",
      query: z.object({ rid: z.string().max(128) }),
      metadata: {
        openapi: {
          operationId: "samlIdpResume",
          summary: "Resume a pending SAML sign-in after the user has authenticated",
        },
      },
    },
    async (ctx) => {
      if (!/^[A-Za-z0-9_-]{43}$/.test(ctx.query.rid)) return fail(ctx, state, "PENDING_REQUEST_NOT_FOUND", "malformed rid");
      // The session store, not the cookie cache: a revoked session must not get an assertion (R4-2).
      const session = await getAuthoritativeSessionFromCtx(ctx);
      if (!session) {
        // Not consumed: the user can sign in and come back to the same URL.
        throw ctx.redirect(loginRedirectUrl(ctx, state, ctx.query.rid));
      }

      // R1: single-use consume through Better Auth's consume path. Everything below runs only
      // for the one caller that won the consume.
      const pending = await consumePending(ctx.context.internalAdapter, ctx.query.rid);
      if (!pending) return fail(ctx, state, "PENDING_REQUEST_NOT_FOUND");

      const binding = await bindingValue(ctx, false);
      if (!binding || (await sha256b64url(binding)) !== pending.bindingHash)
        return fail(ctx, state, "PENDING_REQUEST_NOT_FOUND", "browser binding mismatch");

      const sp = await spById(ctx, state, pending.spId);
      if (!sp) return fail(ctx, state, "UNKNOWN_SERVICE_PROVIDER", "SP removed since the request was stored");
      // IdP-initiated (no request ID): the SP must still have opted in.
      if (pending.requestId === undefined && !sp.allowIdpInitiated)
        return fail(ctx, state, "IDP_INITIATED_NOT_ALLOWED", `SP ${sp.id}: opt-in removed since the request was stored`, { spId: sp.id });
      // Configuration may have changed while the user was signing in: re-check the allow-list.
      if (resolveAcsUrl(sp, pending.acsUrl) !== pending.acsUrl) return fail(ctx, state, "ACS_URL_NOT_ALLOWED", `SP ${sp.id}`, { spId: sp.id });

      if (pending.forceAuthn && new Date(session.session.createdAt).getTime() < pending.createdAt)
        return fail(ctx, state, "REAUTHENTICATION_REQUIRED", `SP ${sp.id}`, { spId: sp.id });

      return issueResponse(ctx, state, sp, session as any, pending);
    },
  );
