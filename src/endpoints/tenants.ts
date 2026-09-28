// Tenant API (D-052): the host's administrators turn an organization into a tenant (its own IdP
// identity), switch it off and on, and remove it. Mounted with the registry API, under the same
// manager check (`samlTenant` in `samlIdpStatements` with `registry.permissions`). Nothing makes
// a tenant automatically (maintainer decision 1), and an organization's own administrators can't
// manage one while tenants share the signing key (multi-tenant design §5.1).
import type { GenericEndpointContext } from "better-auth";
import { createAuthEndpoint, createAuthMiddleware, sensitiveSessionMiddleware } from "better-auth/api";
import * as z from "zod";
import { tenantIdentity } from "../saml/identity";
import { idpBaseURL } from "../saml/idp";
import { lookupKeyOf, SP_MODEL, type StoredSpRow, isEnabled } from "../saml/sp-directory";
import { instant, RETIRED_KEY_MODEL, TENANT_KEY, TENANT_MODEL, type TenantRow } from "../saml/tenant-directory";
import type { TenantRecord } from "../types";
import type { PluginState } from "./issue";
import { adapterOf, fail, manager } from "./registry";

const MAX_LIST = 1000;
const orgIdSchema = z.string().min(1).max(256);

function record(ctx: GenericEndpointContext, state: PluginState, row: TenantRow): TenantRecord {
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
  };
}

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
  const changed = () => {
    state.tenants?.invalidate();
    state.directory.invalidate();
  };

  return {
    samlIdpListTenants: createAuthEndpoint(
      "/saml-idp/tenants",
      { method: "GET", use: [sensitiveSessionMiddleware], metadata: { openapi: { operationId: "samlIdpListTenants" } } },
      async (ctx) => {
        await manager(ctx, state, "list", "samlTenant");
        const rows = (await adapterOf(ctx).findMany({ model: TENANT_MODEL, limit: MAX_LIST, sortBy: { field: "organizationId", direction: "asc" } })) as TenantRow[];
        return ctx.json({ tenants: rows.map((r) => record(ctx, state, r)) });
      },
    ),

    samlIdpGetTenant: createAuthEndpoint(
      "/saml-idp/tenants/get",
      { method: "GET", use: [sensitiveSessionMiddleware], query: z.object({ organizationId: orgIdSchema }) },
      async (ctx) => {
        await manager(ctx, state, "read", "samlTenant");
        const row = await findTenant(ctx, ctx.query.organizationId);
        if (!row) throw fail("NOT_FOUND", "TENANT_NOT_FOUND");
        return ctx.json({ tenant: record(ctx, state, row) });
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
        changed();
        audit(ctx, `user ${user.id} created tenant ${tenantKey} for organization ${organizationId}${data.enabled ? "" : ", disabled"}`);
        return ctx.json({ tenant: record(ctx, state, { id: "", ...data }) });
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
        audit(ctx, `user ${user.id} ${update.enabled ? "enabled" : "disabled"} tenant ${row.tenantKey}`);
        return ctx.json({ tenant: record(ctx, state, { ...row, ...update }) });
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
        changed();
        audit(ctx, `user ${user.id} deleted tenant ${row.tenantKey} (organization ${row.organizationId}); the key is retired`);
        return ctx.json({ deleted: row.organizationId });
      },
    ),
  };
}

/**
 * One-time step when tenants are enabled on an existing registry (D-052): fill in `tenantId`
 * and `lookupKey` on rows saved before, which no lookup finds until then. Server-only (no URL):
 * call `auth.api.samlIdpBackfillServiceProviderKeys()` once from a script or a deploy step.
 * Each row's key comes from its own config; rows whose config doesn't parse are skipped and
 * reported. Safe to run again: rows that already have a key are left alone.
 */
export const backfillEndpoint = (state: PluginState) =>
  createAuthEndpoint.serverOnly({ method: "POST" }, async (ctx) => {
    const rows = (await adapterOf(ctx).findMany({ model: SP_MODEL, limit: 10_000 })) as StoredSpRow[];
    let updated = 0;
    const skipped: string[] = [];
    for (const row of rows) {
      if (row.lookupKey) continue;
      let tenant: unknown;
      try {
        tenant = (JSON.parse(row.config) as { tenant?: unknown }).tenant;
      } catch {
        skipped.push(row.spId);
        continue;
      }
      if (tenant !== undefined && typeof tenant !== "string") {
        skipped.push(row.spId);
        continue;
      }
      const tenantId = tenant ?? "";
      await adapterOf(ctx).update({ model: SP_MODEL, where: [{ field: "id", value: row.id }], update: { tenantId, lookupKey: await lookupKeyOf(tenantId, row.entityId) } });
      updated++;
    }
    state.directory.invalidate();
    ctx.context.logger.info(`[saml-idp] backfill: ${updated} SP row(s) given a lookup key${skipped.length ? `; skipped (config isn't valid JSON): ${skipped.join(", ")}` : ""}`);
    return ctx.json({ updated, skipped });
  });

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
