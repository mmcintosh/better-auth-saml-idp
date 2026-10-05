// Tenant API (D-052): the host's administrators turn an organization into a tenant (its own IdP
// identity), switch it off and on, and remove it. Mounted with the registry API, under the same
// manager check (`samlTenant` in `samlIdpStatements` with `registry.permissions`). Nothing makes
// a tenant automatically (maintainer decision 1), and an organization's own administrators can't
// manage one while tenants share the signing key (multi-tenant design §5.1).
import { X509Certificate } from "node:crypto";
import type { GenericEndpointContext } from "better-auth";
import { createAuthEndpoint, createAuthMiddleware, sensitiveSessionMiddleware } from "better-auth/api";
import * as z from "zod";
import { rootIdentity, tenantIdentity } from "../saml/identity";
import { idpBaseURL } from "../saml/idp";
import { lookupKeyOf, SP_MODEL, type StoredSpRow, isEnabled } from "../saml/sp-directory";
import { instant, RETIRED_KEY_MODEL, TENANT_KEY, TENANT_MODEL, type TenantRow } from "../saml/tenant-directory";
import {
  checkKeyPair,
  encryptTenantKey,
  generateTenantKey,
  SHARED_KID,
  stateKeyOf,
  expiryWarning,
  KEEP_RETIRED,
  TENANT_KEY_MODEL,
  TenantKeyError,
  type TenantKeyRow,
  type TenantKeyState,
} from "../saml/tenant-keys";
import { emit } from "../events";
import { findManyIn } from "../storage/find-in";
import type { TenantRecord, TenantSigningKeyInfo } from "../types";
import { keySecret, type PluginState } from "./issue";
import { access, adapterOf, fail, inScope, manager } from "./registry";

const MAX_LIST = 1000;
const orgIdSchema = z.string().min(1).max(256);

const date = (v: unknown) => new Date(v as string | number | Date);
const ORDER: Record<TenantKeyState, number> = { next: 0, active: 1, previous: 2, retired: 3 };

/** A tenant's key rows as the API shows them: no private material, next first. */
function keyInfo(state: PluginState, rows: TenantKeyRow[]): TenantSigningKeyInfo[] {
  const minMs = state.options.tenants?.minPublishedMs ?? 0;
  return [...rows]
    .sort((a, b) => ORDER[a.state] - ORDER[b.state] || date(b.createdAt).getTime() - date(a.createdAt).getTime())
    .map((r) => ({
      kid: r.kid,
      state: r.state,
      certificate: r.certificate,
      notAfter: date(r.notAfter),
      createdAt: date(r.createdAt),
      activatedAt: r.activatedAt ? date(r.activatedAt) : null,
      ...(r.state === "next" ? { activatableAt: new Date(date(r.createdAt).getTime() + minMs) } : {}),
    }));
}

function record(ctx: GenericEndpointContext, state: PluginState, row: TenantRow, keys?: TenantKeyRow[]): TenantRecord {
  const identity = tenantIdentity(state.options, idpBaseURL(state.options, ctx.context.baseURL), row);
  return {
    organizationId: row.organizationId,
    tenantKey: row.tenantKey,
    entityId: identity.entityId,
    metadataUrl: identity.metadataUrl,
    ssoUrl: identity.ssoUrl,
    sloUrl: state.options.singleLogout ? identity.sloUrl : null,
    enabled: isEnabled(row.enabled),
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
    updatedBy: row.updatedBy ?? null,
    ...(state.tenantKeys && keys
      ? {
          signing: keys.some((k) => k.state === "active") ? ("own" as const) : ("shared" as const),
          keys: keyInfo(state, keys),
          // Its own keys only: the shared key's "previous" row is the root's, warned about at startup.
          warnings: keys.flatMap((k) => (k.state !== "retired" && k.kid !== SHARED_KID ? (expiryWarning(k) ?? []) : [])),
        }
      : {}),
  };
}

/** A tenant's key rows, read now (not the per-isolate cache): exactly its own, whatever the collation. */
async function keyRows(ctx: GenericEndpointContext, tenantId: string): Promise<TenantKeyRow[]> {
  const rows = (await adapterOf(ctx).findMany({ model: TENANT_KEY_MODEL, where: [{ field: "tenantId", value: tenantId }], limit: 100, sortBy: { field: "createdAt", direction: "desc" } })) as TenantKeyRow[];
  return rows.filter((r) => r.tenantId === tenantId);
}

/** A new key row's id in URLs and logs: short, random, never reused. */
const newKid = () => btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(9)))).replace(/\+/g, "-").replace(/\//g, "_");

/** The tenant row of exactly this organization (a case-insensitive collation must not widen it, R4-L8). */
async function findTenant(ctx: GenericEndpointContext, organizationId: string): Promise<TenantRow | null> {
  const row = (await adapterOf(ctx).findOne({ model: TENANT_MODEL, where: [{ field: "organizationId", value: organizationId }] })) as TenantRow | null;
  return row && row.organizationId === organizationId ? row : null;
}

/** Was this key a deleted tenant's? Exact match, whatever the collation (R4-L8). */
async function retired(ctx: GenericEndpointContext, tenantKey: string): Promise<boolean> {
  const row = (await adapterOf(ctx).findOne({ model: RETIRED_KEY_MODEL, where: [{ field: "tenantKey", value: tenantKey }] })) as { tenantKey?: string } | null;
  return row?.tenantKey === tenantKey;
}

export function tenantEndpoints(state: PluginState) {
  const audit = (ctx: GenericEndpointContext, what: string) => ctx.context.logger.info(`[saml-idp] tenants: ${what}`);
  /** Logged, and a `tenant.changed` event (its handler and the audit log, review 6 I-2). */
  const changedBy = (
    ctx: GenericEndpointContext,
    userId: string,
    row: Pick<TenantRow, "organizationId" | "tenantKey">,
    action: "created" | "enabled" | "disabled" | "deleted" | "key.rotated" | "key.activated" | "key.retired",
    what: string,
    extra: { kid?: string; forced?: boolean } = {},
  ) => {
    audit(ctx, `user ${userId} ${what}`);
    emit(ctx, state.options, { type: "tenant.changed", action, userId, tenantId: row.organizationId, tenantKey: row.tenantKey, ...extra });
  };
  const changed = () => {
    state.tenants?.invalidate();
    state.tenantKeys?.invalidate();
    state.directory.invalidate();
  };
  /** A key row, its private key sealed to this tenant and kid (D-058). The pair is checked first. */
  const writeKey = async (ctx: GenericEndpointContext, tenantId: string, keyState: TenantKeyState, kid: string, privateKeyPem: string, certificate: string, userId: string, now = new Date()) => {
    const { notAfter } = checkKeyPair(privateKeyPem, certificate);
    const data = {
      tenantId,
      kid,
      state: keyState,
      stateKey: stateKeyOf(tenantId, keyState),
      encryptedPrivateKey: await encryptTenantKey(keySecret(ctx, state), tenantId, kid, privateKeyPem),
      certificate,
      notAfter,
      createdAt: now,
      activatedAt: keyState === "active" ? now : null,
      updatedBy: userId,
    };
    const created = (await adapterOf(ctx).create({ model: TENANT_KEY_MODEL, data })) as { id?: unknown } | null;
    return { id: String(created?.id), ...data } as TenantKeyRow;
  };
  /** Move a row to another state; `next`/`active` take the tenant's UNIQUE slot, others free it. */
  const moveKey = (ctx: GenericEndpointContext, row: TenantKeyRow, to: TenantKeyState, update: Record<string, unknown> = {}) =>
    adapterOf(ctx).update({ model: TENANT_KEY_MODEL, where: [{ field: "id", value: row.id }], update: { state: to, stateKey: stateKeyOf(row.tenantId, to), ...update } });
  /** Keep the newest KEEP_RETIRED retired rows of a tenant (R7-1); the audit log has the rest. */
  const pruneRetired = async (ctx: GenericEndpointContext, tenantId: string) => {
    const retiredRows = (await keyRows(ctx, tenantId)).filter((k) => k.state === "retired").sort((a, b) => date(b.createdAt).getTime() - date(a.createdAt).getTime());
    for (const old of retiredRows.slice(KEEP_RETIRED)) await adapterOf(ctx).delete({ model: TENANT_KEY_MODEL, where: [{ field: "id", value: old.id }] });
  };
  /** The tenant of a key request, as the manager reads it. */
  const tenantFor = async (ctx: GenericEndpointContext, organizationId: string) => {
    const row = await findTenant(ctx, organizationId);
    if (!row) throw fail("NOT_FOUND", "TENANT_NOT_FOUND");
    return row;
  };

  /** Every key row of the listed tenants in one read, grouped by tenant. */
  const keysOf = async (ctx: GenericEndpointContext, tenantIds: string[]) => {
    const by = new Map<string, TenantKeyRow[]>();
    if (!state.tenantKeys || tenantIds.length === 0) return by;
    // The listed tenants' rows only, in the query (R7-3), in batches for D1; a tenant has at most nine (R7-1).
    const rows = (await findManyIn(adapterOf(ctx), TENANT_KEY_MODEL, "tenantId", tenantIds, 10)) as TenantKeyRow[];
    for (const r of rows) by.set(r.tenantId, [...(by.get(r.tenantId) ?? []), r]);
    return by;
  };

  return {
    samlIdpListTenants: createAuthEndpoint(
      "/saml-idp/tenants",
      { method: "GET", use: [sensitiveSessionMiddleware], metadata: { openapi: { operationId: "samlIdpListTenants" } } },
      async (ctx) => {
        await manager(ctx, state, "list", "samlTenant");
        const rows = (await adapterOf(ctx).findMany({ model: TENANT_MODEL, limit: MAX_LIST, sortBy: { field: "organizationId", direction: "asc" } })) as TenantRow[];
        const keys = await keysOf(ctx, rows.map((r) => r.organizationId));
        return ctx.json({ tenants: rows.map((r) => record(ctx, state, r, keys.get(r.organizationId) ?? [])) });
      },
    ),

    samlIdpGetTenant: createAuthEndpoint(
      "/saml-idp/tenants/get",
      { method: "GET", use: [sensitiveSessionMiddleware], query: z.object({ organizationId: orgIdSchema }) },
      async (ctx) => {
        // A tenant's administrator may read its own tenant (URLs, certificates), nothing else (D-059).
        const actor = await access(ctx, state, "read", "samlTenant", { delegated: true });
        const row = inScope(actor, ctx.query.organizationId) ? await findTenant(ctx, ctx.query.organizationId) : null;
        if (!row) throw fail("NOT_FOUND", "TENANT_NOT_FOUND");
        return ctx.json({ tenant: record(ctx, state, row, state.tenantKeys ? await keyRows(ctx, row.organizationId) : undefined) });
      },
    ),

    samlIdpCreateTenant: createAuthEndpoint(
      "/saml-idp/tenants/create",
      {
        method: "POST",
        use: [sensitiveSessionMiddleware],
        body: z.object({ organizationId: orgIdSchema, tenantKey: z.string().max(256).optional(), enabled: z.boolean().optional() }).strict(),
      },
      async (ctx) => {
        const user = await manager(ctx, state, "create", "samlTenant");
        const { organizationId } = ctx.body;
        const org = (await adapterOf(ctx).findOne({ model: "organization", where: [{ field: "id", value: organizationId }] })) as { id?: unknown; createdAt?: unknown } | null;
        if (org == null || String(org.id) !== organizationId) throw fail("BAD_REQUEST", "INVALID_TENANT", { issues: [`organizationId: no organization "${organizationId}"`] });
        // The tenant is bound to this organization, not just its id, which a database may hand
        // out again after a delete (R6-1): its creation time is kept with the tenant.
        const organizationCreatedAt = instant(org.createdAt);
        if (Number.isNaN(organizationCreatedAt)) throw fail("BAD_REQUEST", "INVALID_TENANT", { issues: [`organizationId: organization "${organizationId}" has no createdAt`] });
        // The key names the tenant in its URLs and entity ID, which SPs pin: by default the
        // organization's id, which never changes (a slug can, and can be claimed; design §1).
        const tenantKey = ctx.body.tenantKey ?? organizationId;
        if (!TENANT_KEY.test(tenantKey))
          throw fail("BAD_REQUEST", "INVALID_TENANT", {
            issues: [`tenantKey: must be 1-64 characters of A-Z a-z 0-9 _ -${ctx.body.tenantKey === undefined ? " (the organization id isn't; choose a tenantKey)" : ""}`],
          });
        // A key names another organization's URLs by default: taking it would make a URL that
        // looks like that organization's name this one (review 6 I-3).
        if (tenantKey !== organizationId) {
          // A key that can't be an id here (text in a serial id column) makes some databases throw: no such organization.
          const other = (await adapterOf(ctx)
            .findOne({ model: "organization", where: [{ field: "id", value: tenantKey }] })
            .catch(() => null)) as { id?: unknown } | null;
          if (other != null && String(other.id) === tenantKey) throw fail("BAD_REQUEST", "INVALID_TENANT", { issues: ["tenantKey: is another organization's id"] });
        }
        // A deleted tenant's key is never used again: its SPs still trust its entity ID (R6-2).
        if (await retired(ctx, tenantKey)) throw fail("CONFLICT", "TENANT_KEY_RETIRED");
        // With per-tenant keys a new tenant signs with its own key from the start (D-058): made
        // before the tenant, so a failure leaves nothing behind. No SP trusts it yet, so it is
        // active at once.
        const generated = state.tenantKeys ? generateTenantKey(tenantKey) : undefined;
        const now = new Date();
        const data = { organizationId, tenantKey, organizationCreatedAt: new Date(organizationCreatedAt), enabled: ctx.body.enabled ?? true, createdAt: now, updatedAt: now, updatedBy: user.id };
        let created: { id?: unknown } | null;
        try {
          created = (await adapterOf(ctx).create({ model: TENANT_MODEL, data })) as { id?: unknown } | null;
        } catch (e) {
          // The UNIQUE columns decide; the reads only classify the failure.
          const taken = (await findTenant(ctx, organizationId)) ?? (await adapterOf(ctx).findOne({ model: TENANT_MODEL, where: [{ field: "tenantKey", value: tenantKey }] }));
          if (taken) throw fail("CONFLICT", "TENANT_EXISTS");
          throw e;
        }
        // A delete of the key's previous tenant may have retired it between the check and the
        // insert (it retires before it deletes): look again, and undo.
        if (await retired(ctx, tenantKey)) {
          await adapterOf(ctx).delete({ model: TENANT_MODEL, where: [{ field: "id", value: String(created?.id) }] });
          throw fail("CONFLICT", "TENANT_KEY_RETIRED");
        }
        let keys: TenantKeyRow[] | undefined;
        if (generated) {
          try {
            keys = [await writeKey(ctx, organizationId, "active", newKid(), generated.privateKeyPem, generated.certificate, user.id, now)];
          } catch (e) {
            await adapterOf(ctx).delete({ model: TENANT_MODEL, where: [{ field: "id", value: String(created?.id) }] });
            throw e;
          }
        }
        changed();
        changedBy(ctx, user.id, data, "created", `created tenant ${tenantKey} for organization ${organizationId}${data.enabled ? "" : ", disabled"}${keys ? `, with key ${keys[0]?.kid}` : ""}`);
        return ctx.json({ tenant: record(ctx, state, { id: "", ...data }, keys) });
      },
    ),

    /** Only `enabled` can change: the key and organization are in URLs and entity IDs SPs pin. */
    samlIdpUpdateTenant: createAuthEndpoint(
      "/saml-idp/tenants/update",
      { method: "POST", use: [sensitiveSessionMiddleware], body: z.object({ organizationId: orgIdSchema, enabled: z.boolean() }).strict() },
      async (ctx) => {
        const user = await manager(ctx, state, "update", "samlTenant");
        const row = await findTenant(ctx, ctx.body.organizationId);
        if (!row) throw fail("NOT_FOUND", "TENANT_NOT_FOUND");
        const update = { enabled: ctx.body.enabled, updatedAt: new Date(), updatedBy: user.id };
        await adapterOf(ctx).update({ model: TENANT_MODEL, where: [{ field: "id", value: row.id }], update });
        changed();
        changedBy(ctx, user.id, row, update.enabled ? "enabled" : "disabled", `${update.enabled ? "enabled" : "disabled"} tenant ${row.tenantKey}`);
        return ctx.json({ tenant: record(ctx, state, { ...row, ...update }, state.tenantKeys ? await keyRows(ctx, row.organizationId) : undefined) });
      },
    ),

    /** Refused while the tenant has SPs, in code or stored: they would be left without an identity. */
    samlIdpDeleteTenant: createAuthEndpoint(
      "/saml-idp/tenants/delete",
      { method: "POST", use: [sensitiveSessionMiddleware], body: z.object({ organizationId: orgIdSchema }).strict() },
      async (ctx) => {
        const user = await manager(ctx, state, "delete", "samlTenant");
        const row = await findTenant(ctx, ctx.body.organizationId);
        if (!row) throw fail("NOT_FOUND", "TENANT_NOT_FOUND");
        const inCode = state.directory.codeSps().some((sp) => sp.tenantId === row.organizationId);
        const stored = (await adapterOf(ctx).findMany({ model: SP_MODEL, where: [{ field: "tenantId", value: row.organizationId }], limit: 1 })) as StoredSpRow[];
        if (inCode || stored.length > 0) throw fail("CONFLICT", "TENANT_HAS_SERVICE_PROVIDERS");
        // Retire the key first (R6-2): SPs configured for this tenant still trust its entity ID,
        // so no other tenant may ever have it. Already retired: an earlier delete stopped here.
        if (!(await retired(ctx, row.tenantKey)))
          await adapterOf(ctx).create({ model: RETIRED_KEY_MODEL, data: { tenantKey: row.tenantKey, organizationId: row.organizationId, retiredAt: new Date(), retiredBy: user.id } });
        await adapterOf(ctx).delete({ model: TENANT_MODEL, where: [{ field: "id", value: row.id }] });
        // Its signing keys go with it (D-058): nothing can sign as a deleted tenant.
        if (state.tenantKeys) await adapterOf(ctx).deleteMany({ model: TENANT_KEY_MODEL, where: [{ field: "tenantId", value: row.organizationId }] });
        changed();
        changedBy(ctx, user.id, row, "deleted", `deleted tenant ${row.tenantKey} (organization ${row.organizationId}); the key is retired`);
        return ctx.json({ deleted: row.organizationId });
      },
    ),

    // Per-tenant signing keys (D-058): the three-step rotation of D-019, per tenant. `rotate`
    // publishes a next key; `activate` makes it sign once it has been published for
    // `minPublishedSeconds` (or with `force`, for a leaked key); `retire` stops publishing the old one.
    ...(state.tenantKeys
      ? {
          samlIdpListTenantKeys: createAuthEndpoint(
            "/saml-idp/tenants/keys",
            { method: "GET", use: [sensitiveSessionMiddleware], query: z.object({ organizationId: orgIdSchema }) },
            async (ctx) => {
              const actor = await access(ctx, state, "read", "samlTenant", { delegated: true });
              if (!inScope(actor, ctx.query.organizationId)) throw fail("NOT_FOUND", "TENANT_NOT_FOUND");
              const row = await tenantFor(ctx, ctx.query.organizationId);
              return ctx.json({ tenant: record(ctx, state, row, await keyRows(ctx, row.organizationId)) });
            },
          ),

          /** A next key, generated (RSA 3072) or uploaded, published next to the active one. */
          samlIdpRotateTenantKey: createAuthEndpoint(
            "/saml-idp/tenants/keys/rotate",
            {
              method: "POST",
              use: [sensitiveSessionMiddleware],
              body: z.object({ organizationId: orgIdSchema, privateKey: z.string().max(20_000).optional(), certificate: z.string().max(20_000).optional() }).strict(),
            },
            async (ctx) => {
              const user = await manager(ctx, state, "update", "samlTenant");
              const row = await tenantFor(ctx, ctx.body.organizationId);
              const { privateKey, certificate } = ctx.body;
              if ((privateKey === undefined) !== (certificate === undefined))
                throw fail("BAD_REQUEST", "INVALID_TENANT_SIGNING_KEY", { issues: ["privateKey and certificate: give both, or neither to generate a key"] });
              // Before generating: an RSA 3072 key costs real CPU, which a refused request shouldn't spend.
              if ((await keyRows(ctx, row.organizationId)).some((k) => k.state === "next")) throw fail("CONFLICT", "TENANT_SIGNING_KEY_EXISTS");
              const pair = privateKey !== undefined && certificate !== undefined ? { privateKeyPem: privateKey, certificate } : generateTenantKey(row.tenantKey);
              let created: TenantKeyRow;
              try {
                created = await writeKey(ctx, row.organizationId, "next", newKid(), pair.privateKeyPem, pair.certificate, user.id);
              } catch (e) {
                if (e instanceof TenantKeyError) throw fail("BAD_REQUEST", "INVALID_TENANT_SIGNING_KEY", { issues: [e.message] });
                // The UNIQUE state key decides between two concurrent rotations.
                if ((await keyRows(ctx, row.organizationId)).some((k) => k.state === "next")) throw fail("CONFLICT", "TENANT_SIGNING_KEY_EXISTS");
                throw e;
              }
              changed();
              changedBy(ctx, user.id, row, "key.rotated", `published next key ${created.kid} for tenant ${row.tenantKey}`, { kid: created.kid });
              return ctx.json({ tenant: record(ctx, state, row, await keyRows(ctx, row.organizationId)) });
            },
          ),

          /**
           * The next key signs; the active one (or, for a tenant's first key, the shared one) stays
           * published as previous, and an older previous is retired.
           */
          samlIdpActivateTenantKey: createAuthEndpoint(
            "/saml-idp/tenants/keys/activate",
            { method: "POST", use: [sensitiveSessionMiddleware], body: z.object({ organizationId: orgIdSchema, force: z.boolean().optional() }).strict() },
            async (ctx) => {
              const user = await manager(ctx, state, "update", "samlTenant");
              const row = await tenantFor(ctx, ctx.body.organizationId);
              const keys = await keyRows(ctx, row.organizationId);
              const next = keys.find((k) => k.state === "next");
              if (!next) throw fail("CONFLICT", "TENANT_SIGNING_KEY_NOT_FOUND", { state: "next" });
              const now = new Date();
              const activatableAt = new Date(date(next.createdAt).getTime() + (state.options.tenants?.minPublishedMs ?? 0));
              const forced = ctx.body.force === true && activatableAt > now;
              if (activatableAt > now && !forced) throw fail("CONFLICT", "TENANT_SIGNING_KEY_TOO_NEW", { activatableAt });
              const active = keys.find((k) => k.state === "active");
              const previous = keys.filter((k) => k.state === "previous");
              if (active) {
                for (const old of previous) await moveKey(ctx, old, "retired", { encryptedPrivateKey: "" });
                await moveKey(ctx, active, "previous");
              } else if (previous.length) {
                // An activation cut short after the active key moved to previous: finish it. That
                // previous key is what was signing; retiring it, or adding the shared one, would
                // publish the wrong certificates (D-065).
              } else {
                // The tenant's first own key: the shared certificate stays published as its previous,
                // so SPs that haven't fetched the new one yet still verify (a normal rotation, D-058).
                const shared = rootIdentity(state.options, idpBaseURL(state.options, ctx.context.baseURL)).signing.certificate;
                await adapterOf(ctx).create({
                  model: TENANT_KEY_MODEL,
                  data: {
                    tenantId: row.organizationId,
                    kid: SHARED_KID,
                    state: "previous",
                    stateKey: stateKeyOf(row.organizationId, "previous"),
                    encryptedPrivateKey: "",
                    certificate: shared,
                    notAfter: new Date(new X509Certificate(shared).validTo),
                    createdAt: now,
                    activatedAt: null,
                    updatedBy: user.id,
                  },
                });
              }
              await moveKey(ctx, next, "active", { activatedAt: now, updatedBy: user.id });
              await pruneRetired(ctx, row.organizationId);
              changed();
              changedBy(ctx, user.id, row, "key.activated", `activated key ${next.kid} for tenant ${row.tenantKey}${forced ? " (forced, before minPublishedSeconds)" : ""}`, {
                kid: next.kid,
                ...(forced ? { forced: true } : {}),
              });
              return ctx.json({ tenant: record(ctx, state, row, await keyRows(ctx, row.organizationId)) });
            },
          ),

          /** Stop publishing the previous key, and erase its private key. */
          samlIdpRetireTenantKey: createAuthEndpoint(
            "/saml-idp/tenants/keys/retire",
            { method: "POST", use: [sensitiveSessionMiddleware], body: z.object({ organizationId: orgIdSchema }).strict() },
            async (ctx) => {
              const user = await manager(ctx, state, "update", "samlTenant");
              const row = await tenantFor(ctx, ctx.body.organizationId);
              const previous = (await keyRows(ctx, row.organizationId)).filter((k) => k.state === "previous");
              if (previous.length === 0) throw fail("CONFLICT", "TENANT_SIGNING_KEY_NOT_FOUND", { state: "previous" });
              for (const k of previous) await moveKey(ctx, k, "retired", { encryptedPrivateKey: "", updatedBy: user.id });
              await pruneRetired(ctx, row.organizationId);
              changed();
              const kids = previous.map((k) => k.kid).join(", ");
              changedBy(ctx, user.id, row, "key.retired", `retired key ${kids} of tenant ${row.tenantKey}`, { kid: kids });
              return ctx.json({ tenant: record(ctx, state, row, await keyRows(ctx, row.organizationId)) });
            },
          ),
        }
      : {}),
  };
}

/** A row's tenant and lookup key, from its own config; undefined when the config can't say. */
async function keysOf(row: { config: unknown; entityId: unknown }): Promise<{ tenantId: string; lookupKey: string } | undefined> {
  let tenant: unknown;
  try {
    tenant = (JSON.parse(String(row.config)) as { tenant?: unknown }).tenant;
  } catch {
    return undefined;
  }
  if ((tenant !== undefined && typeof tenant !== "string") || typeof row.entityId !== "string") return undefined;
  const tenantId = tenant ?? "";
  return { tenantId, lookupKey: await lookupKeyOf(tenantId, row.entityId) };
}

const BACKFILL_PAGE = 500;

/**
 * One-time step when tenants are enabled on an existing registry (D-052): fill in `tenantId`
 * and `lookupKey` on rows saved before, which no lookup finds until then. Server-only (no URL):
 * call `auth.api.samlIdpBackfillServiceProviderKeys()` once from a script or a deploy step.
 * Each row's key comes from its own config; rows whose config doesn't parse are skipped, and rows
 * whose write fails are listed in `failed` (and logged): one bad row doesn't stop the rest
 * (review 6 I-1). Reads the table in pages, however large. Safe to run again: rows that already
 * have a key are left alone. On MongoDB, use `backfillMongoServiceProviderKeys` (R6-4).
 */
export const backfillEndpoint = (state: PluginState) =>
  createAuthEndpoint.serverOnly({ method: "POST" }, async (ctx) => {
    let updated = 0;
    const skipped: string[] = [];
    const failed: string[] = [];
    let mongoIndex = false;
    for (let offset = 0; ; offset += BACKFILL_PAGE) {
      const rows = (await adapterOf(ctx).findMany({ model: SP_MODEL, limit: BACKFILL_PAGE, offset, sortBy: { field: "spId", direction: "asc" } })) as StoredSpRow[];
      for (const row of rows) {
        if (row.lookupKey) continue;
        const keys = await keysOf(row);
        if (!keys) {
          skipped.push(row.spId);
          continue;
        }
        try {
          await adapterOf(ctx).update({ model: SP_MODEL, where: [{ field: "id", value: row.id }], update: keys });
          updated++;
        } catch (e) {
          failed.push(row.spId);
          // MongoDB builds the UNIQUE lookupKey index before any write, and can't while two
          // documents lack the key (R6-4).
          mongoIndex ||= (e as { code?: unknown })?.code === 11000;
          ctx.context.logger.error(`[saml-idp] backfill: SP ${row.spId} could not be given a lookup key`, e);
        }
      }
      if (rows.length < BACKFILL_PAGE) break;
    }
    state.directory.invalidate();
    ctx.context.logger.info(
      `[saml-idp] backfill: ${updated} SP row(s) given a lookup key${skipped.length ? `; skipped (config isn't valid JSON): ${skipped.join(", ")}` : ""}${failed.length ? `; failed: ${failed.join(", ")}` : ""}`,
    );
    if (mongoIndex)
      ctx.context.logger.error(
        "[saml-idp] backfill: on MongoDB, run backfillMongoServiceProviderKeys(db) from better-auth-saml-idp first (docs/guide/multi-tenant.md#database)",
      );
    return ctx.json({ updated, skipped, failed });
  });

/** The part of a MongoDB `Db` (the `mongodb` driver's) that the MongoDB backfill uses. */
export interface MongoDbLike {
  collection(name: string): {
    find(filter: Record<string, unknown>): { toArray(): Promise<Record<string, unknown>[]> };
    updateOne(filter: Record<string, unknown>, update: Record<string, unknown>): Promise<unknown>;
  };
}

/**
 * The registry upgrade's backfill on MongoDB (review 6 R6-4). Better Auth's MongoDB adapter builds
 * a model's indexes before its first write, and the UNIQUE index on `lookupKey` can't be built
 * while two or more documents lack the key, so `samlIdpBackfillServiceProviderKeys` can't write
 * there. This writes the same keys through the driver itself, with the `Db` you gave
 * `mongodbAdapter`. Run it once, before turning tenants on (or after: then the index is built on
 * the next write). Safe to run again. `collection`: the model's collection name, if you renamed it
 * (`samlIdpServiceProviders` with `usePlural`).
 */
export async function backfillMongoServiceProviderKeys(
  db: MongoDbLike,
  options: { collection?: string } = {},
): Promise<{ updated: number; skipped: string[]; failed: string[] }> {
  const collection = db.collection(options.collection ?? SP_MODEL);
  // `lookupKey: null` matches documents without the field too.
  const docs = await collection.find({ lookupKey: null }).toArray();
  let updated = 0;
  const skipped: string[] = [];
  const failed: string[] = [];
  for (const doc of docs) {
    const keys = await keysOf({ config: doc.config, entityId: doc.entityId });
    if (!keys) {
      skipped.push(String(doc.spId));
      continue;
    }
    try {
      await collection.updateOne({ _id: doc._id, lookupKey: null }, { $set: keys });
      updated++;
    } catch {
      failed.push(String(doc.spId));
    }
  }
  return { updated, skipped, failed };
}

/**
 * When an organization is deleted through Better Auth (`/organization/delete`), its tenant is
 * switched off, so the tenant list shows it (review 6 R6-1). Its SPs and key stay: the host's
 * administrators decide what to remove. Routing and issuance don't depend on this: they check
 * the organization themselves, so a delete made straight in the database is covered too.
 */
export const organizationDeletedHook = (state: PluginState) => ({
  matcher: (ctx: { path?: string }) => ctx.path === "/organization/delete",
  handler: createAuthMiddleware(async (ctx) => {
    const returned = (ctx.context as { returned?: unknown }).returned;
    const organizationId = (ctx.body as { organizationId?: unknown } | undefined)?.organizationId;
    if (typeof organizationId !== "string" || returned instanceof Error) return;
    try {
      const row = await findTenant(ctx as unknown as GenericEndpointContext, organizationId);
      if (!row || !isEnabled(row.enabled)) return;
      const userId = (ctx.context as { session?: { user?: { id?: string } } | null }).session?.user?.id ?? null;
      await adapterOf(ctx as unknown as GenericEndpointContext).update({
        model: TENANT_MODEL,
        where: [{ field: "id", value: row.id }],
        update: { enabled: false, updatedAt: new Date(), updatedBy: userId },
      });
      state.tenants?.invalidate();
      state.directory.invalidate();
      ctx.context.logger.info(`[saml-idp] tenants: organization ${organizationId} was deleted; its tenant ${row.tenantKey} is disabled`);
    } catch (e) {
      ctx.context.logger.error(`[saml-idp] could not disable the tenant of deleted organization ${organizationId}`, e);
    }
  }),
});
