// The root IdP's managed signing key (D-080): the three-step rotation of tenants' keys (D-058), for
// the root. `rotate` publishes a next key; `activate` makes it sign once it has been published for
// `signing.minPublishedSeconds` (or with `force`, for a leaked key); `retire` stops publishing the
// old one. Mounted with the registry API, under the same checks, on `samlSigningKey`.
import type { GenericEndpointContext } from "better-auth";
import { createAuthEndpoint, sensitiveSessionMiddleware } from "better-auth/api";
import * as z from "zod";
import { emit } from "../events";
import { managedKeyPolicy } from "../saml/identity";
import { expiryWarning, generateSigningKey, newKid, ROOT_KEY_OWNER, TenantKeyError, type TenantKeyRow } from "../saml/tenant-keys";
import type { TenantSigningKeyInfo } from "../types";
import { keySecrets, type PluginState } from "./issue";
import { keyInfo, keyRows, moveKeyRow, pruneRetiredRows, writeKeyRow } from "./key-rows";
import { access, adapterOf, fail, manager } from "./registry";

const date = (v: unknown) => new Date(v as string | number | Date);

/** Mounted only with a managed key (`state.rootKeys`). */
export function signingKeyEndpoints(state: PluginState) {
  const store = state.rootKeys;
  const policy = managedKeyPolicy(state.options);
  if (!store || !policy) throw new Error("[saml-idp] signing key routes without a managed signing key");
  const owner = ROOT_KEY_OWNER;

  /** The keys as the API shows them, and the certificates that expire soon (or have). */
  const view = async (ctx: GenericEndpointContext): Promise<{ keys: TenantSigningKeyInfo[]; warnings: string[] }> => {
    const rows = await keyRows(ctx, owner);
    return { keys: keyInfo(rows, policy.minPublishedMs), warnings: rows.flatMap((k) => (k.state !== "retired" ? (expiryWarning(k) ?? []) : [])) };
  };
  /** The first key, if the IdP hasn't needed one yet: every route works on a key that exists. */
  const ensure = (ctx: GenericEndpointContext) => store.ensureFirstKey(adapterOf(ctx) as any, keySecrets(ctx, state).root, owner, policy.first);
  const changed = () => store.invalidate();
  /** Logged, and a `signing-key.changed` event (its handler and the audit log). */
  const changedBy = (ctx: GenericEndpointContext, userId: string, action: "key.rotated" | "key.activated" | "key.retired", kid: string, what: string, forced = false) => {
    ctx.context.logger.info(`[saml-idp] signing keys: user ${userId} ${what}`);
    emit(ctx, state.options, { type: "signing-key.changed", action, userId, kid, ...(forced ? { forced: true } : {}) });
  };

  return {
    samlIdpListSigningKeys: createAuthEndpoint("/saml-idp/signing-keys", { method: "GET", use: [sensitiveSessionMiddleware] }, async (ctx) => {
      await access(ctx, state, "read", "samlSigningKey");
      await ensure(ctx);
      return ctx.json(await view(ctx));
    }),

    /** A next key, generated (RSA 3072) or uploaded, published next to the active one. */
    samlIdpRotateSigningKey: createAuthEndpoint(
      "/saml-idp/signing-keys/rotate",
      {
        method: "POST",
        use: [sensitiveSessionMiddleware],
        body: z.object({ privateKey: z.string().max(20_000).optional(), certificate: z.string().max(20_000).optional() }).strict(),
      },
      async (ctx) => {
        const user = await manager(ctx, state, "update", "samlSigningKey");
        const { privateKey, certificate } = ctx.body;
        if ((privateKey === undefined) !== (certificate === undefined))
          throw fail("BAD_REQUEST", "INVALID_SIGNING_KEY", { issues: ["privateKey and certificate: give both, or neither to generate a key"] });
        await ensure(ctx);
        // Before generating: an RSA 3072 key costs real CPU, which a refused request shouldn't spend.
        if ((await keyRows(ctx, owner)).some((k) => k.state === "next")) throw fail("CONFLICT", "SIGNING_KEY_EXISTS");
        const pair = privateKey !== undefined && certificate !== undefined ? { privateKeyPem: privateKey, certificate } : generateSigningKey(policy.first.commonName);
        let created: TenantKeyRow;
        try {
          created = await writeKeyRow(ctx, keySecrets(ctx, state).root, owner, "next", newKid(), pair.privateKeyPem, pair.certificate, user.id);
        } catch (e) {
          if (e instanceof TenantKeyError) throw fail("BAD_REQUEST", "INVALID_SIGNING_KEY", { issues: [e.message] });
          // The UNIQUE state key decides between two concurrent rotations.
          if ((await keyRows(ctx, owner)).some((k) => k.state === "next")) throw fail("CONFLICT", "SIGNING_KEY_EXISTS");
          throw e;
        }
        changed();
        changedBy(ctx, user.id, "key.rotated", created.kid, `published next key ${created.kid}`);
        return ctx.json(await view(ctx));
      },
    ),

    /** The next key signs; the active one stays published as previous, and an older previous is retired. */
    samlIdpActivateSigningKey: createAuthEndpoint(
      "/saml-idp/signing-keys/activate",
      { method: "POST", use: [sensitiveSessionMiddleware], body: z.object({ force: z.boolean().optional() }).strict() },
      async (ctx) => {
        const user = await manager(ctx, state, "update", "samlSigningKey");
        const keys = await keyRows(ctx, owner);
        const next = keys.find((k) => k.state === "next");
        if (!next) throw fail("CONFLICT", "SIGNING_KEY_NOT_FOUND", { state: "next" });
        const now = new Date();
        const activatableAt = new Date(date(next.createdAt).getTime() + policy.minPublishedMs);
        const forced = ctx.body.force === true && activatableAt > now;
        if (activatableAt > now && !forced) throw fail("CONFLICT", "SIGNING_KEY_TOO_NEW", { activatableAt });
        const active = keys.find((k) => k.state === "active");
        if (active) {
          for (const old of keys.filter((k) => k.state === "previous")) await moveKeyRow(ctx, old, "retired", { encryptedPrivateKey: "" });
          await moveKeyRow(ctx, active, "previous");
        }
        // No active key: an activation cut short after the active key moved to previous. Finish it;
        // that previous key is what was signing, so it stays published (as for tenants, D-065).
        await moveKeyRow(ctx, next, "active", { activatedAt: now, updatedBy: user.id });
        await pruneRetiredRows(ctx, owner);
        changed();
        changedBy(ctx, user.id, "key.activated", next.kid, `activated key ${next.kid}${forced ? " (forced, before minPublishedSeconds)" : ""}`, forced);
        return ctx.json(await view(ctx));
      },
    ),

    /** Stop publishing the previous key, and erase its private key. */
    samlIdpRetireSigningKey: createAuthEndpoint(
      "/saml-idp/signing-keys/retire",
      { method: "POST", use: [sensitiveSessionMiddleware], body: z.object({}).strict() },
      async (ctx) => {
        const user = await manager(ctx, state, "update", "samlSigningKey");
        const previous = (await keyRows(ctx, owner)).filter((k) => k.state === "previous");
        if (previous.length === 0) throw fail("CONFLICT", "SIGNING_KEY_NOT_FOUND", { state: "previous" });
        for (const k of previous) await moveKeyRow(ctx, k, "retired", { encryptedPrivateKey: "", updatedBy: user.id });
        await pruneRetiredRows(ctx, owner);
        changed();
        const kids = previous.map((k) => k.kid).join(", ");
        changedBy(ctx, user.id, "key.retired", kids, `retired key ${kids}`);
        return ctx.json(await view(ctx));
      },
    ),
  };
}
