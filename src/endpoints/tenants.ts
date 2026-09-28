// Tenant API (D-052): the host's administrators turn an organization into a tenant (its own IdP
// identity), switch it off and on, and remove it. Mounted with the registry API, under the same
// manager check (`samlTenant` in `samlIdpStatements` with `registry.permissions`). Nothing makes
// a tenant automatically (maintainer decision 1), and an organization's own administrators can't
// manage one while tenants share the signing key (multi-tenant design §5.1).
import type { GenericEndpointContext } from "better-auth";
import { createAuthEndpoint, sensitiveSessionMiddleware } from "better-auth/api";
import * as z from "zod";
import { tenantIdentity } from "../saml/identity";
import { idpBaseURL } from "../saml/idp";
import { lookupKeyOf, SP_MODEL, type StoredSpRow, isEnabled } from "../saml/sp-directory";
import { TENANT_KEY, TENANT_MODEL, type TenantRow } from "../saml/tenant-directory";
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
        const org = (await adapterOf(ctx).findOne({ model: "organization", where: [{ field: "id", value: organizationId }] })) as { id?: string } | null;
        if (org?.id !== organizationId) throw fail("BAD_REQUEST", "INVALID_TENANT", { issues: [`organizationId: no organization "${organizationId}"`] });
        // The key names the tenant in its URLs and entity ID, which SPs pin: by default the
        // organization's id, which never changes (a slug can, and can be claimed; design §1).
        const tenantKey = ctx.body.tenantKey ?? organizationId;
        if (!TENANT_KEY.test(tenantKey))
          throw fail("BAD_REQUEST", "INVALID_TENANT", {
            issues: [`tenantKey: must be 1-64 characters of A-Z a-z 0-9 _ -${ctx.body.tenantKey === undefined ? " (the organization id isn't; choose a tenantKey)" : ""}`],
          });
        const now = new Date();
        const data = { organizationId, tenantKey, enabled: ctx.body.enabled ?? true, createdAt: now, updatedAt: now, updatedBy: user.id };
        try {
          await adapterOf(ctx).create({ model: TENANT_MODEL, data });
        } catch (e) {
          // The UNIQUE columns decide; the reads only classify the failure.
          const taken = (await findTenant(ctx, organizationId)) ?? (await adapterOf(ctx).findOne({ model: TENANT_MODEL, where: [{ field: "tenantKey", value: tenantKey }] }));
          if (taken) throw fail("CONFLICT", "TENANT_EXISTS");
          throw e;
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
        await adapterOf(ctx).delete({ model: TENANT_MODEL, where: [{ field: "id", value: row.id }] });
        changed();
        audit(ctx, `user ${user.id} deleted tenant ${row.tenantKey} (organization ${row.organizationId})`);
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
