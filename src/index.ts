/// <reference path="./saml/wasm/wasm.d.ts" />
import type { BetterAuthPlugin } from "better-auth";
import { mergeSchema } from "better-auth/db";
import { initEndpoint } from "./endpoints/init";
import { warnUserWritableFields } from "./attributes";
import { warnClaimableOrganizations } from "./organizations";
import { metadataEndpoint } from "./endpoints/metadata";
import { resumeEndpoint } from "./endpoints/resume";
import { ssoEndpoint } from "./endpoints/sso";
import { SAML_IDP_ERROR_CODES } from "./errors";
import { nameIdFieldProblem } from "./nameid";
import { resolveOptions, SamlIdpConfigError } from "./options";
import { idpCache, SSO_PATH, withBasePath } from "./saml/idp";
import { samlIdpSchema } from "./schema";
import { SpMetadataCache } from "./saml/sp-metadata-refresh";
import { SpDirectory } from "./saml/sp-directory";
import { registryEndpoints } from "./endpoints/registry";
import { logoutEndpoint, sloEndpoint } from "./endpoints/slo";
import { SLO_PATH } from "./saml/logout";
import { consumeEndingBySlo, endParticipants, extendParticipants, forgetUserParticipants } from "./storage/participants";
import { emitWithoutRequest } from "./events";
import { listSessionParticipantsEndpoint } from "./endpoints/participants";
import type { SamlIdpOptions } from "./types";

export { SAML_IDP_ERROR_CODES } from "./errors";
export { NAMEID_FORMAT } from "./types";
export { SamlIdpConfigError } from "./options";
export { libxml2Validator } from "./saml/validator";
export { serviceProviderFromMetadata, SpMetadataError } from "./saml/sp-metadata";
export { samlIdpStatements, type SamlServiceProviderAction } from "./access";
export type { SpFromMetadataOptions, SpFromMetadataResult } from "./saml/sp-metadata";
// An explicit list (API decision 1, before 1.0): what's here is supported; the plugin's resolved
// internals (ResolvedSamlIdpOptions, ResolvedServiceProvider) are not exported and may change.
export type {
  AttributeContext,
  AttributeMap,
  AttributeSource,
  AuthorizeContext,
  AuthorizeResult,
  AuthnContextOptions,
  DigestAlgorithm,
  NameIdSource,
  OrganizationMembership,
  RequestSignaturePolicy,
  SamlAttributeValue,
  SamlIdpOptions,
  SamlIdpUser,
  SessionLimit,
  SchemaKind,
  SchemaValidationResult,
  SchemaValidator,
  ServiceProviderConfig,
  ServiceProviderEncryptionConfig,
  ServiceProviderInfo,
  ServiceProviderRecord,
  SignatureAlgorithm,
  SignedParts,
  SigningConfig,
} from "./types";
export type { SamlIdpErrorCode } from "./errors";
export type { StoredServiceProviderConfig } from "./options";
export type { AssertionIssuedEvent, AuditLogOptions, DeniedEvent, LogoutEvent, SamlIdpEvent, SamlIdpEventHandlers, SessionEndedEvent } from "./events";

export const samlIdp = (options: SamlIdpOptions) => {
  const resolved = resolveOptions(options);
  const directory = new SpDirectory(resolved.serviceProviders, resolved);
  const getIdp = idpCache(resolved);
  const state = { options: resolved, directory, metadata: new SpMetadataCache(resolved.schemaValidator) };

  return {
    id: "saml-idp",
    init(ctx) {
      for (const w of resolved.warnings) ctx.logger.warn(`[saml-idp] ${w}`);
      for (const sp of resolved.serviceProviders) {
        warnClaimableOrganizations(ctx.logger, ctx.options.plugins as any, sp);
        warnUserWritableFields(ctx.logger, ctx.options.user as any, sp);
      }
      // Stored SPs are checked when saved and again at issuance.
      const nameIdIssues = resolved.serviceProviders.flatMap((sp) => {
        const problem = sp.nameIdField === undefined ? undefined : nameIdFieldProblem(sp.nameIdField, ctx.options as any);
        return problem ? [`serviceProviders (${sp.id}): ${problem}`] : [];
      });
      if (nameIdIssues.length) throw new SamlIdpConfigError(nameIdIssues);
      if (resolved.baseURL) {
        // Same rule as Better Auth's own baseURL, so the same value can go in both (decision 6).
        resolved.baseURL = withBasePath(resolved.baseURL, ctx.options.basePath);
        if (typeof ctx.baseURL === "string" && ctx.baseURL && ctx.baseURL.replace(/\/+$/, "") !== resolved.baseURL)
          ctx.logger.warn(
            `[saml-idp] samlIdp baseURL resolves to ${resolved.baseURL} but Better Auth's is ${ctx.baseURL}: the IdP's metadata and Destination check use ${resolved.baseURL}. Usually both should be the same; or leave samlIdp's unset.`,
          );
      }
      if (!resolved.baseURL && !ctx.options.baseURL)
        ctx.logger.warn(
          "[saml-idp] no baseURL: the IdP's SSO URL (metadata, Destination check, resume links) follows the request's Host header. Set samlIdp({ baseURL }) or Better Auth's baseURL.",
        );
      // Session hooks use this init context, never the hook's: a host deleting sessions from its
      // own code (an admin page) runs them outside any endpoint, where the hook context is
      // undefined (D-043).
      if (resolved.sessionTracking && ctx.options.secondaryStorage && !ctx.options.session?.storeSessionInDatabase)
        ctx.logger.warn(
          "[saml-idp] sessions live only in secondaryStorage, so Better Auth deletes them without database hooks: events.onSessionEnded won't fire. Set session.storeSessionInDatabase: true to get it.",
        );
      const sink = { logger: ctx.logger, adapter: ctx.adapter as any, runInBackground: (p: Promise<unknown>) => ctx.runInBackground(p) };
      const options = resolved.sessionTracking
        ? {
            databaseHooks: {
              // A deleted user's participant rows (NameID included) are removed with the user, after
              // the session hook below has reported them (review 5 R5-3). Never blocks the delete.
              user: {
                delete: {
                  after: async (user: { id?: string }) => {
                    if (!user?.id) return;
                    await forgetUserParticipants(ctx.adapter as any, user.id).catch((e) =>
                      ctx.logger.error("[saml-idp] could not remove a deleted user's SAML participant rows", e),
                    );
                  },
                },
              },
              session: {
                // Participants live as long as the session: when Better Auth extends a session,
                // extend its participant rows, so the expiry sweep can't drop SPs a later logout
                // must reach (review 2, R2-SLO-1).
                update: {
                  after: async (session: { id?: string; expiresAt?: Date | string }) => {
                    if (!session?.id || !session.expiresAt) return;
                    await extendParticipants(ctx.adapter as any, session.id, new Date(session.expiresAt)).catch((e) =>
                      ctx.logger.warn("[saml-idp] could not extend logout participants with the session", e),
                    );
                  },
                },
                // A session ended without our Single Logout (D-043): keep its participants (as
                // ended) and say which SPs weren't told. An observer: nothing here can stop or
                // fail the delete.
                delete: {
                  after: async (session: { id?: string; userId?: string; expiresAt?: Date | string }, hookCtx: { path?: string } | null | undefined) => {
                    try {
                      if (!session?.id || consumeEndingBySlo(session.id)) return;
                      const now = new Date();
                      const { participants: ended, truncated } = await endParticipants(ctx.adapter as any, session.id, now);
                      if (ended.length === 0) return;
                      const reason =
                        session.expiresAt && new Date(session.expiresAt).getTime() <= now.getTime() ? "expired" : hookCtx?.path === "/sign-out" ? "signed-out" : "revoked";
                      const log = { error: (m: string) => ctx.logger.error(m) };
                      const participants = await Promise.all(
                        ended.map(async (p) => ({ ...p, entityId: (await directory.byId(ctx.adapter as any, p.spId, log))?.entityId })),
                      );
                      emitWithoutRequest(sink, resolved, { type: "session.ended", userId: String(session.userId ?? ""), sessionId: session.id, reason, participants, truncated });
                    } catch (e) {
                      ctx.logger.error("[saml-idp] could not record the end of a session's SAML participants", e);
                    }
                  },
                },
              },
            },
          }
        : undefined;
      // SPs POST AuthnRequests cross-origin (HTTP-POST binding), like @better-auth/sso's ACS.
      const existing = ctx.skipOriginCheck;
      if (existing === true) return options ? { options } : {};
      // /slo too: SPs POST LogoutRequests and LogoutResponses cross-origin (D-028).
      return {
        context: { skipOriginCheck: [...(Array.isArray(existing) ? existing : []), SSO_PATH, ...(resolved.singleLogout ? [SLO_PATH] : [])] },
        ...(options ? { options } : {}),
      };
    },
    endpoints: {
      getSamlIdpMetadata: metadataEndpoint(getIdp, resolved),
      samlIdpSingleSignOn: ssoEndpoint(state),
      samlIdpResume: resumeEndpoint(state),
      samlIdpInitiatedSignOn: initEndpoint(state),
      ...(resolved.registry?.canManage || resolved.registry?.permissions ? registryEndpoints(state) : {}),
      ...(resolved.singleLogout ? { samlIdpSingleLogout: sloEndpoint(state), samlIdpLogout: logoutEndpoint(state) } : {}),
      ...(resolved.sessionTracking ? { samlIdpListSessionParticipants: listSessionParticipantsEndpoint(state) } : {}),
    },
    // A fresh schema object per plugin: mergeSchema mutates its first argument, so a shared
    // module-level object would leak one instance's renames into every other (finding #10).
    schema: mergeSchema(samlIdpSchema({ registry: resolved.registry !== undefined, sessionTracking: resolved.sessionTracking, auditLog: resolved.auditLog !== undefined }), resolved.schema),
    $ERROR_CODES: SAML_IDP_ERROR_CODES,
    // No `options` (API decision 3): by convention it holds a plugin's configuration, and ours
    // includes the signing key; the internal SP directory isn't public either.
  } satisfies BetterAuthPlugin;
};
