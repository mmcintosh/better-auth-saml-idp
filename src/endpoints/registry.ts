// Registry API (D-027): manage database-stored SPs at runtime. Mounted only when
// `registry.canManage` or `registry.permissions` is configured. Every route needs an authoritative (database-checked)
// session of a non-impersonated user that canManage() approves; mutations keep Better Auth's
// origin check (no skipOriginCheck) and are logged with the acting user.
import type { GenericEndpointContext } from "better-auth";
import { APIError, createAuthEndpoint, sensitiveSessionMiddleware } from "better-auth/api";
import * as z from "zod";
import { SAML_IDP_ERROR_CODES } from "../errors";
import { adminAllows, type SamlServiceProviderAction } from "../access";
import { resolveStoredServiceProvider } from "../options";
import { isEnabled, SP_MODEL, type StoredSpRow } from "../saml/sp-directory";
import { isBanned, type PluginState } from "./issue";

const MAX_CONFIG_BYTES = 64 * 1024;
const MAX_LIST = 1000;

type Adapter = {
  create(a: { model: string; data: Record<string, unknown> }): Promise<unknown>;
  findOne(a: { model: string; where: { field: string; value: unknown }[] }): Promise<unknown>;
  findMany(a: { model: string; limit?: number; sortBy?: { field: string; direction: "asc" | "desc" } }): Promise<unknown[]>;
  update(a: { model: string; where: { field: string; value: unknown }[]; update: Record<string, unknown> }): Promise<unknown>;
  delete(a: { model: string; where: { field: string; value: unknown }[] }): Promise<void>;
};

const adapterOf = (ctx: GenericEndpointContext) => ctx.context.adapter as unknown as Adapter;
const fail = (status: "FORBIDDEN" | "BAD_REQUEST" | "CONFLICT" | "NOT_FOUND", code: keyof typeof SAML_IDP_ERROR_CODES, extra: Record<string, unknown> = {}) =>
  APIError.fromStatus(status, { ...SAML_IDP_ERROR_CODES[code], ...extra });

async function manager(ctx: GenericEndpointContext, state: PluginState, action: SamlServiceProviderAction) {
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
  if (reg.permissions && !adminAllows(ctx.context.options.plugins as any, user as any, action)) throw fail("FORBIDDEN", "REGISTRY_NOT_ALLOWED");
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

function view(row: StoredSpRow, state: PluginState) {
  let config: unknown;
  try {
    config = JSON.parse(row.config);
  } catch {
    config = null;
  }
  const r = config === null ? undefined : resolveStoredServiceProvider(config, state.options);
  return {
    id: row.spId,
    entityId: row.entityId,
    source: "database" as const,
    enabled: isEnabled(row.enabled),
    // Invalid rows (edited by hand, or options tightened since) are listed with their issues and
    // are not used for sign-in.
    // The same checks the directory applies when it loads a row (R4-L8): valid means used.
    valid:
      r?.serviceProvider !== undefined &&
      r.serviceProvider.id === row.spId &&
      r.serviceProvider.entityId === row.entityId &&
      !state.directory.inCode(row.spId, row.entityId),
    issues:
      r === undefined
        ? ["config is not valid JSON"]
        : r.serviceProvider && (r.serviceProvider.id !== row.spId || r.serviceProvider.entityId !== row.entityId)
          ? [...r.issues, "the id/entityId columns don't match the config (edited by hand?); not used for sign-in"]
          : r.issues,
    config,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
    updatedBy: row.updatedBy ?? null,
  };
}

function validate(state: PluginState, input: unknown) {
  if (JSON.stringify(input).length > MAX_CONFIG_BYTES) throw fail("BAD_REQUEST", "INVALID_SERVICE_PROVIDER", { issues: [`larger than ${MAX_CONFIG_BYTES} bytes`] });
  const r = resolveStoredServiceProvider(input, state.options);
  if (!r.serviceProvider || !r.config) throw fail("BAD_REQUEST", "INVALID_SERVICE_PROVIDER", { issues: r.issues });
  if (state.directory.inCode(r.config.id, r.config.entityId)) throw fail("CONFLICT", "SERVICE_PROVIDER_IN_CODE");
  return { config: r.config, warnings: r.warnings };
}

/**
 * The row whose spId is exactly `id`. A case-insensitive collation (MySQL's default) would
 * otherwise return "abc" for "ABC", and update or delete would act on that row (R4-L8).
 */
const findRow = async (ctx: GenericEndpointContext, id: string) => {
  const row = (await adapterOf(ctx).findOne({ model: SP_MODEL, where: [{ field: "spId", value: id }] })) as StoredSpRow | null;
  return row && row.spId === id ? row : null;
};

const spBody = z.record(z.string(), z.unknown());
const idSchema = z.string().regex(/^[A-Za-z0-9_-]{1,64}$/);

export function registryEndpoints(state: PluginState) {
  const audit = (ctx: GenericEndpointContext, what: string) => ctx.context.logger.info(`[saml-idp] registry: ${what}`);

  return {
    samlIdpListServiceProviders: createAuthEndpoint(
      "/saml2/idp/service-providers",
      { method: "GET", use: [sensitiveSessionMiddleware], metadata: { openapi: { operationId: "samlIdpListServiceProviders" } } },
      async (ctx) => {
        await manager(ctx, state, "list");
        const rows = (await adapterOf(ctx).findMany({ model: SP_MODEL, limit: MAX_LIST, sortBy: { field: "spId", direction: "asc" } })) as StoredSpRow[];
        return ctx.json({
          serviceProviders: [
            ...state.directory.codeSps().map((sp) => ({ id: sp.id, entityId: sp.entityId, source: "code" as const, enabled: true, valid: true })),
            ...rows.map((r) => view(r, state)),
          ],
        });
      },
    ),

    samlIdpGetServiceProvider: createAuthEndpoint(
      "/saml2/idp/service-providers/get",
      { method: "GET", use: [sensitiveSessionMiddleware], query: z.object({ id: idSchema }) },
      async (ctx) => {
        await manager(ctx, state, "read");
        const row = await findRow(ctx, ctx.query.id);
        if (!row) throw fail("NOT_FOUND", "SERVICE_PROVIDER_NOT_FOUND");
        return ctx.json({ serviceProvider: view(row, state) });
      },
    ),

    samlIdpCreateServiceProvider: createAuthEndpoint(
      "/saml2/idp/service-providers/create",
      { method: "POST", use: [sensitiveSessionMiddleware], body: z.object({ serviceProvider: spBody, enabled: z.boolean().optional() }) },
      async (ctx) => {
        const user = await manager(ctx, state, "create");
        const { config, warnings } = validate(state, ctx.body.serviceProvider);
        const now = new Date();
        const data = { spId: config.id, entityId: config.entityId, config: JSON.stringify(config), enabled: ctx.body.enabled ?? true, createdAt: now, updatedAt: now, updatedBy: user.id };
        try {
          await adapterOf(ctx).create({ model: SP_MODEL, data });
        } catch (e) {
          // The UNIQUE columns decide; the reads only classify the failure.
          const taken =
            (await findRow(ctx, config.id)) ?? (await adapterOf(ctx).findOne({ model: SP_MODEL, where: [{ field: "entityId", value: config.entityId }] }));
          if (taken) throw fail("CONFLICT", "SERVICE_PROVIDER_EXISTS");
          throw e;
        }
        state.directory.invalidate();
        audit(ctx, `user ${user.id} created SP ${config.id} (${config.entityId})${data.enabled ? "" : ", disabled"}`);
        const row = await findRow(ctx, config.id);
        return ctx.json({ serviceProvider: row ? view(row, state) : null, warnings });
      },
    ),

    samlIdpUpdateServiceProvider: createAuthEndpoint(
      "/saml2/idp/service-providers/update",
      { method: "POST", use: [sensitiveSessionMiddleware], body: z.object({ id: idSchema, serviceProvider: spBody, enabled: z.boolean().optional() }) },
      async (ctx) => {
        const user = await manager(ctx, state, "update");
        const row = await findRow(ctx, ctx.body.id);
        if (!row) throw fail("NOT_FOUND", "SERVICE_PROVIDER_NOT_FOUND");
        if (ctx.body.serviceProvider.id !== ctx.body.id)
          throw fail("BAD_REQUEST", "INVALID_SERVICE_PROVIDER", { issues: ["serviceProvider.id: can't be changed (delete and re-create instead)"] });
        const { config, warnings } = validate(state, ctx.body.serviceProvider);
        const update = {
          entityId: config.entityId,
          config: JSON.stringify(config),
          enabled: ctx.body.enabled ?? isEnabled(row.enabled),
          updatedAt: new Date(),
          updatedBy: user.id,
        };
        try {
          await adapterOf(ctx).update({ model: SP_MODEL, where: [{ field: "id", value: row.id }], update });
        } catch (e) {
          const other = (await adapterOf(ctx).findOne({ model: SP_MODEL, where: [{ field: "entityId", value: config.entityId }] })) as StoredSpRow | null;
          if (other && other.spId !== row.spId) throw fail("CONFLICT", "SERVICE_PROVIDER_EXISTS");
          throw e;
        }
        state.directory.invalidate();
        audit(ctx, `user ${user.id} updated SP ${row.spId} (${config.entityId})${update.enabled ? "" : ", disabled"}`);
        const fresh = await findRow(ctx, row.spId);
        return ctx.json({ serviceProvider: fresh ? view(fresh, state) : null, warnings });
      },
    ),

    samlIdpDeleteServiceProvider: createAuthEndpoint(
      "/saml2/idp/service-providers/delete",
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
