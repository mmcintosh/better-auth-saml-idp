// Registry API (D-027): manage database-stored SPs at runtime. Mounted only when
// `registry.canManage` or `registry.permissions` is configured. Every route needs an authoritative (database-checked)
// session of a non-impersonated user that canManage() approves; mutations keep Better Auth's
// origin check (no skipOriginCheck) and are logged with the acting user.
//
// With tenants (D-052), an SP may belong to a tenant (`tenant` in its config, copied to the
// `tenantId` column, and never changed afterwards), entity IDs are unique per tenant, and records
// say which tenant. Only these managers, the host's administrators, manage tenant SPs: with one
// shared signing key, an organization's own administrators must not (multi-tenant design §5.1).
import type { GenericEndpointContext } from "better-auth";
import { APIError, createAuthEndpoint, sensitiveSessionMiddleware } from "better-auth/api";
import * as z from "zod";
import { SAML_IDP_ERROR_CODES } from "../errors";
import { adminAllows, type SamlIdpResource, type SamlServiceProviderAction } from "../access";
import { nameIdFieldProblem } from "../nameid";
import { overlaps, overlapWarning, resolveStoredServiceProvider } from "../options";
import { isEnabled, lookupKeyOf, SP_MODEL, type StoredSpRow } from "../saml/sp-directory";
import { TENANT_MODEL } from "../saml/tenant-directory";
import type { ResolvedServiceProvider, ServiceProviderRecord } from "../types";
import { isBanned, type PluginState } from "./issue";

const MAX_CONFIG_BYTES = 64 * 1024;
const MAX_LIST = 1000;
const MAX_SAME_ENTITY = 100;

export type Adapter = {
  create(a: { model: string; data: Record<string, unknown> }): Promise<unknown>;
  findOne(a: { model: string; where: { field: string; value: unknown }[] }): Promise<unknown>;
  findMany(a: { model: string; where?: { field: string; value: unknown }[]; limit?: number; offset?: number; sortBy?: { field: string; direction: "asc" | "desc" } }): Promise<unknown[]>;
  update(a: { model: string; where: { field: string; value: unknown }[]; update: Record<string, unknown> }): Promise<unknown>;
  delete(a: { model: string; where: { field: string; value: unknown }[] }): Promise<void>;
};

export const adapterOf = (ctx: GenericEndpointContext) => ctx.context.adapter as unknown as Adapter;
export const fail = (status: "FORBIDDEN" | "BAD_REQUEST" | "CONFLICT" | "NOT_FOUND", code: keyof typeof SAML_IDP_ERROR_CODES, extra: Record<string, unknown> = {}) =>
  APIError.fromStatus(status, { ...SAML_IDP_ERROR_CODES[code], ...extra });

export async function manager(ctx: GenericEndpointContext, state: PluginState, action: SamlServiceProviderAction, resource: SamlIdpResource = "samlServiceProvider") {
  const s = (ctx.context as { session?: { user: any; session: any } }).session;
  const reg = state.options.registry;
  if (!s || !reg || (!reg.canManage && !reg.permissions)) throw fail("FORBIDDEN", "REGISTRY_NOT_ALLOWED");
  // An admin acting as another user must not manage SPs under that identity.
  if (s.session.impersonatedBy) throw fail("FORBIDDEN", "REGISTRY_NOT_ALLOWED");
  // Decide on the user as the database has it now, as issuance does: with sessions in secondary
  // storage, the session's copy of the user can predate a ban or a demotion (R4-L3).
  const user = (await ctx.context.internalAdapter.findUserById(s.user.id)) as Record<string, unknown> | null;
  if (!user || isBanned(user, new Date())) throw fail("FORBIDDEN", "REGISTRY_NOT_ALLOWED");
  // Both checks, when both are configured, must allow.
  if (reg.permissions && !adminAllows(ctx.context.options.plugins as any, user as any, action, resource)) throw fail("FORBIDDEN", "REGISTRY_NOT_ALLOWED");
  if (reg.canManage) {
    let ok = false;
    try {
      ok = (await reg.canManage({ user: user as any, session: s.session })) === true;
    } catch (e) {
      ctx.context.logger.error("[saml-idp] registry.canManage threw", e);
    }
    if (!ok) throw fail("FORBIDDEN", "REGISTRY_NOT_ALLOWED");
  }
  return user as { id: string };
}

/** `tenantId` in records only with tenants (D-052), so records are unchanged without them. */
const tenantField = (state: PluginState, tenantId: string | null | undefined) => (state.options.tenants ? { tenantId: tenantId || null } : {});

const codeRecord = (sp: ResolvedServiceProvider, state: PluginState, others: readonly Overlappable[] = []): ServiceProviderRecord => ({
  id: sp.id,
  entityId: sp.entityId,
  source: "code",
  enabled: true,
  valid: true,
  issues: [],
  // The overlap warning (D-052) is the one warning a code record carries: it depends on what's
  // stored, so the startup log can't have said it.
  warnings: overlapWarnings(sp, others),
  config: null,
  createdAt: null,
  updatedAt: null,
  updatedBy: null,
  ...tenantField(state, sp.tenantId),
});

type Overlappable = Pick<ResolvedServiceProvider, "id" | "entityId" | "acsUrls" | "tenantId">;

/** The host-administrator overlap warning (multi-tenant design §5.1 c). */
function overlapWarnings(sp: Overlappable, others: readonly Overlappable[]): string[] {
  const other = others.find((o) => o.id !== sp.id && overlaps(sp, o));
  return other ? [overlapWarning(other)] : [];
}

/** Stored and code SPs with this entity ID, in any tenant: what an SP could overlap with. */
async function sameEntity(ctx: GenericEndpointContext, state: PluginState, entityId: string): Promise<Overlappable[]> {
  if (!state.options.tenants) return [];
  const rows = (await adapterOf(ctx).findMany({ model: SP_MODEL, where: [{ field: "entityId", value: entityId }], limit: MAX_SAME_ENTITY })) as StoredSpRow[];
  const stored = rows.flatMap((r) => {
    const sp = parsed(r, state).r?.serviceProvider;
    return sp && sp.entityId === entityId ? [sp] : [];
  });
  return [...state.directory.codeSps().filter((sp) => sp.entityId === entityId), ...stored];
}

function parsed(row: StoredSpRow, state: PluginState) {
  let json: unknown;
  try {
    json = JSON.parse(row.config);
  } catch {
    json = undefined;
  }
  const config = json !== null && typeof json === "object" && !Array.isArray(json) ? (json as Record<string, unknown>) : null;
  return { config, r: config === null ? undefined : resolveStoredServiceProvider(config, state.options) };
}

/**
 * A stored row as a record. Invalid rows (edited by hand, or options tightened since) are
 * returned with their issues and are not used for sign-in: the same checks the directory
 * applies when it loads a row (R4-L8), so `valid` means used.
 */
function view(row: StoredSpRow, state: PluginState, authOptions: unknown, others: readonly Overlappable[] = []): ServiceProviderRecord {
  const { config, r } = parsed(row, state);
  const issues =
    r === undefined
      ? ["config is not a JSON object"]
      : r.serviceProvider && (r.serviceProvider.id !== row.spId || r.serviceProvider.entityId !== row.entityId)
        ? [...r.issues, "the id/entityId columns don't match the config (edited by hand?); not used for sign-in"]
        : [...r.issues];
  const tenantId = state.options.tenants ? (row.tenantId ?? "") : "";
  if (state.options.tenants && r?.serviceProvider) {
    // The directory's checks (D-052): the tenant column must match the config, and a row is only
    // found through its lookup key, which rows from before tenants were enabled lack.
    if ((r.serviceProvider.tenantId ?? "") !== tenantId) issues.push("the tenantId column doesn't match the config (edited by hand?); not used for sign-in");
    if (!row.lookupKey) issues.push("no lookupKey yet: run the one-time backfill (multi-tenant guide); not used for sign-in until then");
  }
  if (state.directory.inCode(row.spId, row.entityId, tenantId)) issues.push("an SP in code has the same id or entityId; the code one is used");
  // Issuance refuses it too (issue.ts), so it isn't used for sign-in.
  const field = r?.config?.nameId?.field;
  const fieldProblem = field === undefined ? undefined : nameIdFieldProblem(field, authOptions as any);
  if (fieldProblem) issues.push(fieldProblem);
  return {
    id: row.spId,
    entityId: row.entityId,
    source: "database",
    enabled: isEnabled(row.enabled),
    valid: r?.serviceProvider !== undefined && issues.length === 0,
    issues,
    warnings: [...(r?.warnings ?? []), ...(r?.serviceProvider ? overlapWarnings(r.serviceProvider, others) : [])],
    config,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
    updatedBy: row.updatedBy ?? null,
    ...tenantField(state, row.tenantId),
  };
}

async function validate(ctx: GenericEndpointContext, state: PluginState, input: unknown) {
  if (JSON.stringify(input).length > MAX_CONFIG_BYTES) throw fail("BAD_REQUEST", "INVALID_SERVICE_PROVIDER", { issues: [`larger than ${MAX_CONFIG_BYTES} bytes`] });
  const r = resolveStoredServiceProvider(input, state.options);
  if (!r.serviceProvider || !r.config) throw fail("BAD_REQUEST", "INVALID_SERVICE_PROVIDER", { issues: r.issues });
  const fieldProblem = r.config.nameId && nameIdFieldProblem(r.config.nameId.field, ctx.context.options as any);
  if (fieldProblem) throw fail("BAD_REQUEST", "INVALID_SERVICE_PROVIDER", { issues: [`serviceProvider: ${fieldProblem}`] });
  if (state.directory.inCode(r.config.id, r.config.entityId, r.config.tenant ?? "")) throw fail("CONFLICT", "SERVICE_PROVIDER_IN_CODE");
  // An SP can only join a tenant that exists (D-052); disabled is fine, it just isn't used yet.
  if (r.config.tenant !== undefined) {
    const tenant = (await adapterOf(ctx).findOne({ model: TENANT_MODEL, where: [{ field: "organizationId", value: r.config.tenant }] })) as { organizationId?: string } | null;
    if (tenant?.organizationId !== r.config.tenant)
      throw fail("BAD_REQUEST", "INVALID_SERVICE_PROVIDER", { issues: [`serviceProvider.tenant: no tenant for organization "${r.config.tenant}" (create the tenant first)`] });
  }
  return { config: r.config, serviceProvider: r.serviceProvider };
}

/**
 * The row whose spId is exactly `id`. A case-insensitive collation (MySQL's default) would
 * otherwise return "abc" for "ABC", and update or delete would act on that row (R4-L8).
 */
const findRow = async (ctx: GenericEndpointContext, id: string) => {
  const row = (await adapterOf(ctx).findOne({ model: SP_MODEL, where: [{ field: "spId", value: id }] })) as StoredSpRow | null;
  return row && row.spId === id ? row : null;
};

/** The columns that locate an SP: with tenants, its tenant and lookup key too (D-052). */
async function keyColumns(state: PluginState, config: { entityId: string; tenant?: string | undefined }) {
  if (!state.options.tenants) return { entityId: config.entityId };
  const tenantId = config.tenant ?? "";
  return { entityId: config.entityId, tenantId, lookupKey: await lookupKeyOf(tenantId, config.entityId) };
}

/** Another row already holds this entity ID (in this tenant, with tenants): a conflict. */
async function entityTaken(ctx: GenericEndpointContext, keys: Awaited<ReturnType<typeof keyColumns>>) {
  const where = "lookupKey" in keys ? [{ field: "lookupKey", value: keys.lookupKey }] : [{ field: "entityId", value: keys.entityId }];
  return (await adapterOf(ctx).findOne({ model: SP_MODEL, where })) as StoredSpRow | null;
}

const spBody = z.record(z.string(), z.unknown());
const idSchema = z.string().regex(/^[A-Za-z0-9_-]{1,64}$/);

export function registryEndpoints(state: PluginState) {
  const audit = (ctx: GenericEndpointContext, what: string) => ctx.context.logger.info(`[saml-idp] registry: ${what}`);
  const warnOverlap = (ctx: GenericEndpointContext, record: ServiceProviderRecord) => {
    for (const w of record.warnings.filter((x) => x.startsWith("same entity ID and an ACS URL"))) ctx.context.logger.warn(`[saml-idp] registry: SP ${record.id}: ${w}`);
  };
  // `?tenantId=` (with tenants): one tenant's SPs, filtered in the query; "" is the root IdP's.
  const listQuery = z.object({ tenantId: z.string().max(256).optional() }).optional();

  return {
    samlIdpListServiceProviders: createAuthEndpoint(
      "/saml-idp/service-providers",
      { method: "GET", use: [sensitiveSessionMiddleware], query: listQuery, metadata: { openapi: { operationId: "samlIdpListServiceProviders" } } },
      async (ctx) => {
        await manager(ctx, state, "list");
        const tenantId = state.options.tenants ? ctx.query?.tenantId : undefined;
        const rows = (await adapterOf(ctx).findMany({
          model: SP_MODEL,
          ...(tenantId !== undefined ? { where: [{ field: "tenantId", value: tenantId }] } : {}),
          limit: MAX_LIST,
          sortBy: { field: "spId", direction: "asc" },
        })) as StoredSpRow[];
        // Exact match, as findRow does (R4-L8): a collation must not widen the filter.
        const listed = tenantId === undefined ? rows : rows.filter((r) => (r.tenantId ?? "") === tenantId);
        const code = state.directory.codeSps().filter((sp) => tenantId === undefined || (sp.tenantId ?? "") === tenantId);
        // Overlaps are judged against everything listed, plus the rest when filtered.
        const all: Overlappable[] = [...state.directory.codeSps()];
        if (state.options.tenants) {
          const everyRow = tenantId === undefined ? rows : ((await adapterOf(ctx).findMany({ model: SP_MODEL, limit: MAX_LIST })) as StoredSpRow[]);
          for (const r of everyRow) {
            const sp = parsed(r, state).r?.serviceProvider;
            if (sp) all.push(sp);
          }
        }
        const serviceProviders: ServiceProviderRecord[] = [...code.map((sp) => codeRecord(sp, state, all)), ...listed.map((r) => view(r, state, ctx.context.options, all))];
        return ctx.json({ serviceProviders });
      },
    ),

    samlIdpGetServiceProvider: createAuthEndpoint(
      "/saml-idp/service-providers/get",
      { method: "GET", use: [sensitiveSessionMiddleware], query: z.object({ id: idSchema }) },
      async (ctx) => {
        await manager(ctx, state, "read");
        // A stored row first: one that clashes with a code SP is only reachable here.
        const row = await findRow(ctx, ctx.query.id);
        const inCode = state.directory.codeSps().find((sp) => sp.id === ctx.query.id);
        const others = await sameEntity(ctx, state, row?.entityId ?? inCode?.entityId ?? "");
        const serviceProvider: ServiceProviderRecord | undefined = row ? view(row, state, ctx.context.options, others) : inCode && codeRecord(inCode, state, others);
        if (!serviceProvider) throw fail("NOT_FOUND", "SERVICE_PROVIDER_NOT_FOUND");
        return ctx.json({ serviceProvider });
      },
    ),

    samlIdpCreateServiceProvider: createAuthEndpoint(
      "/saml-idp/service-providers/create",
      { method: "POST", use: [sensitiveSessionMiddleware], body: z.object({ serviceProvider: spBody, enabled: z.boolean().optional() }) },
      async (ctx) => {
        const user = await manager(ctx, state, "create");
        const { config } = await validate(ctx, state, ctx.body.serviceProvider);
        const now = new Date();
        const keys = await keyColumns(state, config);
        const data = { spId: config.id, ...keys, config: JSON.stringify(config), enabled: ctx.body.enabled ?? true, createdAt: now, updatedAt: now, updatedBy: user.id };
        try {
          await adapterOf(ctx).create({ model: SP_MODEL, data });
        } catch (e) {
          // The UNIQUE columns decide; the reads only classify the failure. With tenants, an
          // entity ID held in another tenant can also fail here, on an entityId UNIQUE constraint
          // kept from before tenants (the multi-tenant guide says how to drop it).
          const taken =
            (await findRow(ctx, config.id)) ?? (await entityTaken(ctx, keys)) ?? (state.options.tenants ? (await sameEntity(ctx, state, config.entityId))[0] : null);
          if (taken) throw fail("CONFLICT", "SERVICE_PROVIDER_EXISTS");
          throw e;
        }
        state.directory.invalidate();
        audit(ctx, `user ${user.id} created SP ${config.id} (${config.entityId})${config.tenant === undefined ? "" : ` in tenant ${config.tenant}`}${data.enabled ? "" : ", disabled"}`);
        // What was written, not a re-read: a read can miss (replicas, case-folding collations).
        const serviceProvider = view({ id: "", ...data }, state, ctx.context.options, await sameEntity(ctx, state, config.entityId));
        warnOverlap(ctx, serviceProvider);
        return ctx.json({ serviceProvider });
      },
    ),

    samlIdpUpdateServiceProvider: createAuthEndpoint(
      "/saml-idp/service-providers/update",
      { method: "POST", use: [sensitiveSessionMiddleware], body: z.object({ id: idSchema, serviceProvider: spBody.optional(), enabled: z.boolean().optional() }) },
      async (ctx) => {
        const user = await manager(ctx, state, "update");
        const row = await findRow(ctx, ctx.body.id);
        if (!row) throw fail("NOT_FOUND", "SERVICE_PROVIDER_NOT_FOUND");
        // Only switching it on or off: no re-validation, so an invalid row can still be disabled
        // (review 5 R5-8). Its config is untouched.
        if (ctx.body.serviceProvider === undefined) {
          if (ctx.body.enabled === undefined) throw fail("BAD_REQUEST", "INVALID_SERVICE_PROVIDER", { issues: ["send serviceProvider, enabled, or both"] });
          const toggle = { enabled: ctx.body.enabled, updatedAt: new Date(), updatedBy: user.id };
          await adapterOf(ctx).update({ model: SP_MODEL, where: [{ field: "id", value: row.id }], update: toggle });
          state.directory.invalidate();
          audit(ctx, `user ${user.id} ${toggle.enabled ? "enabled" : "disabled"} SP ${row.spId}`);
          return ctx.json({ serviceProvider: view({ ...row, ...toggle }, state, ctx.context.options, await sameEntity(ctx, state, row.entityId)) });
        }
        if (ctx.body.serviceProvider.id !== ctx.body.id)
          throw fail("BAD_REQUEST", "INVALID_SERVICE_PROVIDER", { issues: ["serviceProvider.id: can't be changed (delete and re-create instead)"] });
        // An SP's tenant is part of what its SPs were given (entity ID, URLs, NameIDs): fixed, as the id is (D-052).
        if (state.options.tenants && (ctx.body.serviceProvider.tenant ?? "") !== (row.tenantId ?? ""))
          throw fail("BAD_REQUEST", "INVALID_SERVICE_PROVIDER", { issues: ["serviceProvider.tenant: can't be changed (delete and re-create instead)"] });
        const { config } = await validate(ctx, state, ctx.body.serviceProvider);
        const keys = await keyColumns(state, config);
        const update = {
          ...keys,
          config: JSON.stringify(config),
          enabled: ctx.body.enabled ?? isEnabled(row.enabled),
          updatedAt: new Date(),
          updatedBy: user.id,
        };
        try {
          await adapterOf(ctx).update({ model: SP_MODEL, where: [{ field: "id", value: row.id }], update });
        } catch (e) {
          const other = (await entityTaken(ctx, keys)) ?? (state.options.tenants ? (await sameEntity(ctx, state, config.entityId)).find((o) => o.id !== row.spId) : null);
          if (other && ("spId" in other ? other.spId : other.id) !== row.spId) throw fail("CONFLICT", "SERVICE_PROVIDER_EXISTS");
          throw e;
        }
        state.directory.invalidate();
        audit(ctx, `user ${user.id} updated SP ${row.spId} (${config.entityId})${update.enabled ? "" : ", disabled"}`);
        const serviceProvider = view({ ...row, ...update }, state, ctx.context.options, await sameEntity(ctx, state, config.entityId));
        warnOverlap(ctx, serviceProvider);
        return ctx.json({ serviceProvider });
      },
    ),

    samlIdpDeleteServiceProvider: createAuthEndpoint(
      "/saml-idp/service-providers/delete",
      { method: "POST", use: [sensitiveSessionMiddleware], body: z.object({ id: idSchema }) },
      async (ctx) => {
        const user = await manager(ctx, state, "delete");
        const row = await findRow(ctx, ctx.body.id);
        if (!row) throw fail("NOT_FOUND", "SERVICE_PROVIDER_NOT_FOUND");
        await adapterOf(ctx).delete({ model: SP_MODEL, where: [{ field: "id", value: row.id }] });
        state.directory.invalidate();
        audit(ctx, `user ${user.id} deleted SP ${row.spId} (${row.entityId})`);
        return ctx.json({ deleted: row.spId });
      },
    ),
  };
}
