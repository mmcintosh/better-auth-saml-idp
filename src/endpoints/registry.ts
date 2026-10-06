// Registry API (D-027): manage database-stored SPs at runtime. Mounted only when
// `registry.canManage` or `registry.permissions` is configured. Every route needs an authoritative (database-checked)
// session of a non-impersonated user that canManage() approves; mutations keep Better Auth's
// origin check (no skipOriginCheck) and are logged with the acting user.
//
// With tenants (D-052), an SP may belong to a tenant (`tenant` in its config, copied to the
// `tenantId` column, and never changed afterwards), entity IDs are unique per tenant, and records
// say which tenant. The host's administrators manage every SP. With `tenants.delegation` (phase 3,
// D-059, only on per-tenant keys) an organization's own owners and admins manage their tenant's
// SPs too, and nothing else: its rows only, an allow-list of user fields, no `metadata.url`.
import type { GenericEndpointContext } from "better-auth";
import { APIError, createAuthEndpoint, sensitiveSessionMiddleware } from "better-auth/api";
import * as z from "zod";
import { SAML_IDP_ERROR_CODES } from "../errors";
import { adminAllows, type SamlIdpResource, type SamlServiceProviderAction } from "../access";
import { nameIdFieldProblem } from "../nameid";
import { overlaps, overlapWarning, resolveStoredServiceProvider, type StoredServiceProviderConfig } from "../options";
import { loadMemberships } from "../organizations";
import { isEnabled, lookupKeyOf, SP_MODEL, type StoredSpRow } from "../saml/sp-directory";
import { TENANT_MODEL } from "../saml/tenant-directory";
import type { ResolvedServiceProvider, ServiceProviderRecord } from "../types";
import { AUDIT_MODEL, emit } from "../events";
import { isBanned, type PluginState } from "./issue";

const MAX_CONFIG_BYTES = 64 * 1024;
const MAX_LIST = 1000;
const MAX_SAME_ENTITY = 100;
const MAX_AUDIT = 500;

export type Adapter = {
  create(a: { model: string; data: Record<string, unknown> }): Promise<unknown>;
  findOne(a: { model: string; where: { field: string; value: unknown }[] }): Promise<unknown>;
  findMany(a: { model: string; where?: { field: string; value: unknown; operator?: "in" | "lt" }[]; limit?: number; offset?: number; sortBy?: { field: string; direction: "asc" | "desc" } }): Promise<unknown[]>;
  update(a: { model: string; where: { field: string; value: unknown }[]; update: Record<string, unknown> }): Promise<unknown>;
  delete(a: { model: string; where: { field: string; value: unknown }[] }): Promise<void>;
  deleteMany(a: { model: string; where: { field: string; value: unknown }[] }): Promise<number>;
};

export const adapterOf = (ctx: GenericEndpointContext) => ctx.context.adapter as unknown as Adapter;
export const fail = (status: "FORBIDDEN" | "BAD_REQUEST" | "CONFLICT" | "NOT_FOUND", code: keyof typeof SAML_IDP_ERROR_CODES, extra: Record<string, unknown> = {}) =>
  APIError.fromStatus(status, { ...SAML_IDP_ERROR_CODES[code], ...extra });

/**
 * Who is acting (D-059): a host manager (`tenants` null: every SP and tenant), or an organization's
 * administrator under delegation (`tenants`: the tenants whose SPs it may manage, and nothing else).
 */
export interface Actor {
  user: { id: string };
  tenants: ReadonlySet<string> | null;
}

/** Is this user one of the host's managers (`registry.permissions` and/or `canManage`)? Both, when both are set. */
async function hostManager(ctx: GenericEndpointContext, state: PluginState, user: Record<string, unknown>, session: unknown, action: SamlServiceProviderAction, resource: SamlIdpResource) {
  const reg = state.options.registry;
  if (!reg || (!reg.canManage && !reg.permissions)) return false;
  if (reg.permissions && !adminAllows(ctx.context.options.plugins as any, user as any, action, resource)) return false;
  if (reg.canManage) {
    try {
      return (await reg.canManage({ user: user as any, session: session as any })) === true;
    } catch (e) {
      ctx.context.logger.error("[saml-idp] registry.canManage threw", e);
      return false;
    }
  }
  return true;
}

/**
 * The actor of a registry request. Every route needs a non-impersonated user as the database has
 * it now (R4-L3), not banned. Host managers may do anything; with `delegated`, a user who holds one
 * of `tenants.delegation.roles` in an enabled tenant's organization may act on that tenant's SPs.
 * Memberships are read from the database on every request, never from the session's active
 * organization, so a demoted administrator loses access at once.
 */
export async function access(
  ctx: GenericEndpointContext,
  state: PluginState,
  action: SamlServiceProviderAction,
  resource: SamlIdpResource = "samlServiceProvider",
  o: { delegated?: boolean } = {},
): Promise<Actor> {
  const s = (ctx.context as { session?: { user: any; session: any } }).session;
  if (!s || !state.options.registry) throw fail("FORBIDDEN", "REGISTRY_NOT_ALLOWED");
  // An admin acting as another user must not manage SPs under that identity.
  if (s.session.impersonatedBy) throw fail("FORBIDDEN", "REGISTRY_NOT_ALLOWED");
  // Decide on the user as the database has it now, as issuance does: with sessions in secondary
  // storage, the session's copy of the user can predate a ban or a demotion (R4-L3).
  const user = (await ctx.context.internalAdapter.findUserById(s.user.id)) as Record<string, unknown> | null;
  if (!user || isBanned(user, new Date())) throw fail("FORBIDDEN", "REGISTRY_NOT_ALLOWED");
  if (await hostManager(ctx, state, user, s.session, action, resource)) return { user: user as { id: string }, tenants: null };
  const delegation = state.options.tenants?.delegation;
  if (!o.delegated || !delegation || !state.tenants) throw fail("FORBIDDEN", "REGISTRY_NOT_ALLOWED");
  const tenants = new Set<string>();
  for (const m of await loadMemberships(ctx.context.adapter as any, String(user.id))) {
    if (!m.roles.some((r) => delegation.roles.includes(r))) continue;
    // Only an enabled tenant whose organization is still the one it was made for (D-053), and
    // that signs with its own key: one still on the shared key would let its administrator have
    // assertions for another identity's SPs signed with that key (review 7 R7-5, design §5.1).
    if (!(await state.tenants.byOrganization(ctx.context.adapter as any, m.id))) continue;
    const keys = state.tenantKeys ? await state.tenantKeys.load(ctx.context.adapter as any, m.id) : [];
    if (keys.some((k) => k.state === "active")) tenants.add(m.id);
  }
  if (tenants.size === 0) throw fail("FORBIDDEN", "REGISTRY_NOT_ALLOWED");
  return { user: user as { id: string }, tenants };
}

/** Host managers only: tenants and their keys, and the root IdP's SPs. */
export async function manager(ctx: GenericEndpointContext, state: PluginState, action: SamlServiceProviderAction, resource: SamlIdpResource = "samlServiceProvider") {
  return (await access(ctx, state, action, resource)).user;
}

/** Can this actor see or change an SP of this tenant ("" or undefined: the root IdP)? */
export const inScope = (actor: Actor, tenantId: string | null | undefined) => actor.tenants === null || (!!tenantId && actor.tenants.has(tenantId));

/**
 * What a delegated administrator may not put in an SP (D-059): no SP outside its tenants, user
 * fields only from `tenants.delegation.userFields` (attributes and NameID), and no `metadata.url`
 * unless allowed: it makes the server fetch that URL (D-026, D-029).
 */
function delegatedIssues(
  config: StoredServiceProviderConfig,
  actor: Actor,
  delegation: { userFields: string[]; allowMetadataUrl: boolean },
  previous?: Pick<StoredServiceProviderConfig, "tokenExchange">,
): string[] {
  const issues: string[] = [];
  if (config.tenant === undefined || !actor.tenants?.has(config.tenant)) issues.push("serviceProvider.tenant: must be a tenant you administer");
  const allowed = new Set(delegation.userFields);
  for (const [name, source] of Object.entries(config.attributes ?? {})) {
    const field = typeof source === "string" ? source : "field" in source ? source.field : undefined;
    if (field !== undefined && !allowed.has(field)) issues.push(`serviceProvider.attributes.${name}: the user field "${field}" isn't one a tenant's administrator may send (${[...allowed].join(", ")})`);
    // `only` names organizations: others than the tenant's would tell it its members' other
    // memberships. Without it, a tenant SP's organization attributes cover the tenant (R7-4).
    if (typeof source === "object" && "organization" in source && source.only !== undefined)
      issues.push(`serviceProvider.attributes.${name}.only: a tenant's administrator can't name organizations; the tenant's own is the scope`);
  }
  if (config.nameId !== undefined && !allowed.has(config.nameId.field)) issues.push(`serviceProvider.nameId.field: "${config.nameId.field}" isn't one a tenant's administrator may send`);
  if (config.metadata !== undefined && !delegation.allowMetadataUrl) issues.push("serviceProvider.metadata: a tenant's administrator can't set a metadata URL (the server would fetch it)");
  // Which OAuth client may turn the tenant's members' assertions into tokens (D-071) is the
  // host's call: kept as the host set it, or removed, never set or changed by the tenant.
  if (config.tokenExchange !== undefined && config.tokenExchange.clientId !== previous?.tokenExchange?.clientId)
    issues.push("serviceProvider.tokenExchange: only the host's administrators can set or change it");
  return issues;
}

/** The stored row's `tokenExchange`, for the delegation check; none when the JSON doesn't parse. */
function storedTokenExchange(row: StoredSpRow): Pick<StoredServiceProviderConfig, "tokenExchange"> {
  try {
    const te = (JSON.parse(row.config) as { tokenExchange?: { clientId?: unknown } }).tokenExchange;
    return typeof te?.clientId === "string" ? { tokenExchange: { clientId: te.clientId } } : {};
  } catch {
    return {};
  }
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
  /** Logged, and a `service-provider.changed` event (its handler and the audit log, D-059). */
  const changedBy = (ctx: GenericEndpointContext, actor: Actor, action: "created" | "updated" | "enabled" | "disabled" | "deleted", sp: { spId: string; entityId: string; tenantId?: string | null | undefined }, what: string) => {
    audit(ctx, `${actor.tenants ? "tenant administrator" : "user"} ${actor.user.id} ${what}`);
    emit(ctx, state.options, { type: "service-provider.changed", action, userId: actor.user.id, spId: sp.spId, entityId: sp.entityId, ...(sp.tenantId ? { tenantId: sp.tenantId } : {}), delegated: actor.tenants !== null });
  };
  /**
   * Before validation, which would say whether a named organization is a tenant: a delegated
   * administrator naming anything but its own tenants gets the same 403 (review 7 R7-6).
   */
  const scopeFirst = (actor: Actor, input: Record<string, unknown>) => {
    if (actor.tenants && !(typeof input.tenant === "string" && actor.tenants.has(input.tenant)))
      throw fail("FORBIDDEN", "REGISTRY_NOT_ALLOWED", { issues: ["serviceProvider.tenant: must be a tenant you administer"] });
  };
  /** A delegated administrator's SP config: 403 outside its tenants, 400 for fields it may not set. */
  const checkDelegated = (actor: Actor, config: StoredServiceProviderConfig, previous?: StoredSpRow) => {
    const delegation = state.options.tenants?.delegation;
    if (!actor.tenants || !delegation) return;
    const issues = delegatedIssues(config, actor, delegation, previous ? storedTokenExchange(previous) : undefined);
    if (issues.some((i) => i.startsWith("serviceProvider.tenant:"))) throw fail("FORBIDDEN", "REGISTRY_NOT_ALLOWED", { issues });
    if (issues.length) throw fail("BAD_REQUEST", "INVALID_SERVICE_PROVIDER", { issues });
  };
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
        const actor = await access(ctx, state, "list", "samlServiceProvider", { delegated: true });
        let tenantId = state.options.tenants ? ctx.query?.tenantId : undefined;
        // A tenant's administrator lists one of its tenants, filtered in the query (D-059).
        if (actor.tenants) {
          if (tenantId === undefined && actor.tenants.size === 1) tenantId = [...actor.tenants][0];
          if (tenantId === undefined) throw fail("BAD_REQUEST", "INVALID_SERVICE_PROVIDER", { issues: ["tenantId: required (you administer several tenants)"] });
          if (!inScope(actor, tenantId)) throw fail("FORBIDDEN", "REGISTRY_NOT_ALLOWED");
        }
        const rows = (await adapterOf(ctx).findMany({
          model: SP_MODEL,
          ...(tenantId !== undefined ? { where: [{ field: "tenantId", value: tenantId }] } : {}),
          limit: MAX_LIST,
          sortBy: { field: "spId", direction: "asc" },
        })) as StoredSpRow[];
        // Exact match, as findRow does (R4-L8): a collation must not widen the filter.
        const listed = tenantId === undefined ? rows : rows.filter((r) => (r.tenantId ?? "") === tenantId);
        const code = state.directory.codeSps().filter((sp) => tenantId === undefined || (sp.tenantId ?? "") === tenantId);
        // Overlaps are judged against everything listed, plus the rest when filtered. Never for a
        // tenant's administrator: the warning names another tenant's SP (D-059).
        const all: Overlappable[] = actor.tenants ? [] : [...state.directory.codeSps()];
        if (state.options.tenants && !actor.tenants) {
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
        const actor = await access(ctx, state, "read", "samlServiceProvider", { delegated: true });
        // A stored row first: one that clashes with a code SP is only reachable here.
        const row = await findRow(ctx, ctx.query.id);
        const inCode = state.directory.codeSps().find((sp) => sp.id === ctx.query.id);
        // Another tenant's SP (spId is global) is "not found" to a tenant's administrator: an IDOR otherwise (D-059).
        if (row ? !inScope(actor, row.tenantId) : inCode && !inScope(actor, inCode.tenantId)) throw fail("NOT_FOUND", "SERVICE_PROVIDER_NOT_FOUND");
        const others = actor.tenants ? [] : await sameEntity(ctx, state, row?.entityId ?? inCode?.entityId ?? "");
        const serviceProvider: ServiceProviderRecord | undefined = row ? view(row, state, ctx.context.options, others) : inCode && codeRecord(inCode, state, others);
        if (!serviceProvider) throw fail("NOT_FOUND", "SERVICE_PROVIDER_NOT_FOUND");
        return ctx.json({ serviceProvider });
      },
    ),

    samlIdpCreateServiceProvider: createAuthEndpoint(
      "/saml-idp/service-providers/create",
      { method: "POST", use: [sensitiveSessionMiddleware], body: z.object({ serviceProvider: spBody, enabled: z.boolean().optional() }) },
      async (ctx) => {
        const actor = await access(ctx, state, "create", "samlServiceProvider", { delegated: true });
        const user = actor.user;
        scopeFirst(actor, ctx.body.serviceProvider);
        const { config } = await validate(ctx, state, ctx.body.serviceProvider);
        checkDelegated(actor, config);
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
        changedBy(ctx, actor, "created", { spId: config.id, entityId: config.entityId, tenantId: config.tenant }, `created SP ${config.id} (${config.entityId})${config.tenant === undefined ? "" : ` in tenant ${config.tenant}`}${data.enabled ? "" : ", disabled"}`);
        // What was written, not a re-read: a read can miss (replicas, case-folding collations).
        const serviceProvider = view({ id: "", ...data }, state, ctx.context.options, actor.tenants ? [] : await sameEntity(ctx, state, config.entityId));
        warnOverlap(ctx, serviceProvider);
        return ctx.json({ serviceProvider });
      },
    ),

    samlIdpUpdateServiceProvider: createAuthEndpoint(
      "/saml-idp/service-providers/update",
      { method: "POST", use: [sensitiveSessionMiddleware], body: z.object({ id: idSchema, serviceProvider: spBody.optional(), enabled: z.boolean().optional() }) },
      async (ctx) => {
        const actor = await access(ctx, state, "update", "samlServiceProvider", { delegated: true });
        const user = actor.user;
        const row = await findRow(ctx, ctx.body.id);
        if (!row || !inScope(actor, row.tenantId)) throw fail("NOT_FOUND", "SERVICE_PROVIDER_NOT_FOUND");
        // Only switching it on or off: no re-validation, so an invalid row can still be disabled
        // (review 5 R5-8). Its config is untouched.
        if (ctx.body.serviceProvider === undefined) {
          if (ctx.body.enabled === undefined) throw fail("BAD_REQUEST", "INVALID_SERVICE_PROVIDER", { issues: ["send serviceProvider, enabled, or both"] });
          const toggle = { enabled: ctx.body.enabled, updatedAt: new Date(), updatedBy: user.id };
          await adapterOf(ctx).update({ model: SP_MODEL, where: [{ field: "id", value: row.id }], update: toggle });
          state.directory.invalidate();
          changedBy(ctx, actor, toggle.enabled ? "enabled" : "disabled", row, `${toggle.enabled ? "enabled" : "disabled"} SP ${row.spId}`);
          return ctx.json({ serviceProvider: view({ ...row, ...toggle }, state, ctx.context.options, actor.tenants ? [] : await sameEntity(ctx, state, row.entityId)) });
        }
        if (ctx.body.serviceProvider.id !== ctx.body.id)
          throw fail("BAD_REQUEST", "INVALID_SERVICE_PROVIDER", { issues: ["serviceProvider.id: can't be changed (delete and re-create instead)"] });
        // An SP's tenant is part of what its SPs were given (entity ID, URLs, NameIDs): fixed, as the id is (D-052).
        if (state.options.tenants && (ctx.body.serviceProvider.tenant ?? "") !== (row.tenantId ?? ""))
          throw fail("BAD_REQUEST", "INVALID_SERVICE_PROVIDER", { issues: ["serviceProvider.tenant: can't be changed (delete and re-create instead)"] });
        scopeFirst(actor, ctx.body.serviceProvider);
        const { config } = await validate(ctx, state, ctx.body.serviceProvider);
        checkDelegated(actor, config, row);
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
        changedBy(ctx, actor, "updated", { spId: row.spId, entityId: config.entityId, tenantId: row.tenantId }, `updated SP ${row.spId} (${config.entityId})${update.enabled ? "" : ", disabled"}`);
        const serviceProvider = view({ ...row, ...update }, state, ctx.context.options, actor.tenants ? [] : await sameEntity(ctx, state, config.entityId));
        warnOverlap(ctx, serviceProvider);
        return ctx.json({ serviceProvider });
      },
    ),

    samlIdpDeleteServiceProvider: createAuthEndpoint(
      "/saml-idp/service-providers/delete",
      { method: "POST", use: [sensitiveSessionMiddleware], body: z.object({ id: idSchema }) },
      async (ctx) => {
        const actor = await access(ctx, state, "delete", "samlServiceProvider", { delegated: true });
        const row = await findRow(ctx, ctx.body.id);
        if (!row || !inScope(actor, row.tenantId)) throw fail("NOT_FOUND", "SERVICE_PROVIDER_NOT_FOUND");
        await adapterOf(ctx).delete({ model: SP_MODEL, where: [{ field: "id", value: row.id }] });
        state.directory.invalidate();
        changedBy(ctx, actor, "deleted", row, `deleted SP ${row.spId} (${row.entityId})`);
        return ctx.json({ deleted: row.spId });
      },
    ),

    // The audit log (D-038), newest first. With tenants, one tenant's events (`tenantId`) are
    // filtered in the query; a tenant's administrator sees only its own tenants' (D-059).
    ...(state.options.auditLog
      ? {
          samlIdpListAuditEvents: createAuthEndpoint(
            "/saml-idp/audit",
            {
              method: "GET",
              use: [sensitiveSessionMiddleware],
              query: z.object({ tenantId: z.string().max(256).optional(), limit: z.coerce.number().int().min(1).max(MAX_AUDIT).optional(), before: z.iso.datetime().optional() }).optional(),
            },
            async (ctx) => {
              const actor = await access(ctx, state, "list", "samlServiceProvider", { delegated: true });
              let tenantId = state.options.tenants ? ctx.query?.tenantId : undefined;
              if (actor.tenants) {
                if (tenantId === undefined && actor.tenants.size === 1) tenantId = [...actor.tenants][0];
                if (tenantId === undefined || !inScope(actor, tenantId)) throw fail("FORBIDDEN", "REGISTRY_NOT_ALLOWED", { issues: ["tenantId: one of the tenants you administer"] });
              }
              const where: { field: string; value: unknown; operator?: "lt" }[] = [];
              if (tenantId !== undefined) where.push({ field: "tenantId", value: tenantId === "" ? null : tenantId });
              if (ctx.query?.before) where.push({ field: "at", value: new Date(ctx.query.before), operator: "lt" });
              const rows = (await adapterOf(ctx).findMany({
                model: AUDIT_MODEL,
                ...(where.length ? { where } : {}),
                limit: ctx.query?.limit ?? 100,
                sortBy: { field: "at", direction: "desc" },
              })) as Record<string, unknown>[];
              // Exact tenant match, whatever the collation (R4-L8).
              const mine = tenantId === undefined ? rows : rows.filter((r) => (r.tenantId ?? "") === tenantId);
              return ctx.json({
                events: mine.map((r) => {
                  let details: unknown = null;
                  try {
                    details = JSON.parse(String(r.details));
                  } catch {}
                  return { type: r.type, at: r.at, spId: r.spId ?? null, userId: r.userId ?? null, code: r.code ?? null, tenantId: r.tenantId ?? null, ipAddress: r.ipAddress ?? null, userAgent: r.userAgent ?? null, details };
                }),
              });
            },
          ),
        }
      : {}),
  };
}
