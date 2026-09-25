// Where SPs come from (D-027): the code-configured list, then, when `registry.enabled`, the
// `samlIdpServiceProvider` table. Code always wins. Stored SPs are re-validated on every load
// (a row edited by hand can't bypass the option schema) and cached per isolate, misses too, so
// requests naming unknown issuers don't each cost a database read.
import { resolveStoredServiceProvider } from "../options";
import type { ResolvedSamlIdpOptions, ResolvedServiceProvider } from "../types";
import { createSpRegistry } from "./sp-registry";

export const SP_MODEL = "samlIdpServiceProvider";
const MAX_CACHE_ENTRIES = 2000;

export interface StoredSpRow {
  id: string;
  spId: string;
  entityId: string;
  config: string;
  enabled: boolean | number | string;
  createdAt: Date;
  updatedAt: Date;
  updatedBy?: string | null;
}

export type DirectoryAdapter = {
  findOne(args: { model: string; where: { field: string; value: unknown }[] }): Promise<unknown>;
};

export interface DirectoryLogger {
  error(message: string): void;
}

/** SQLite/D1 may hand booleans back as 0/1 (or "0"/"1"). */
export const isEnabled = (v: StoredSpRow["enabled"]) => v === true || v === 1 || v === "1" || v === "true";

export class SpDirectory {
  private readonly code;
  private readonly cache = new Map<string, { sp: ResolvedServiceProvider | undefined; expires: number }>();

  constructor(
    codeSps: ResolvedServiceProvider[],
    private readonly options: ResolvedSamlIdpOptions,
    private readonly now: () => number = Date.now,
  ) {
    this.code = createSpRegistry(codeSps);
  }

  get registryEnabled(): boolean {
    return this.options.registry !== undefined;
  }

  codeSps(): readonly ResolvedServiceProvider[] {
    return this.code.all();
  }

  /** Is this id or entity ID taken by an SP defined in code? */
  inCode(id: string, entityId: string): boolean {
    return this.code.byId(id) !== undefined || this.code.byEntityId(entityId) !== undefined;
  }

  byEntityId(adapter: DirectoryAdapter, entityId: string, log: DirectoryLogger): Promise<ResolvedServiceProvider | undefined> {
    const sp = this.code.byEntityId(entityId);
    if (sp || !this.registryEnabled) return Promise.resolve(sp);
    return this.stored(adapter, "entityId", entityId, log);
  }

  byId(adapter: DirectoryAdapter, id: string, log: DirectoryLogger): Promise<ResolvedServiceProvider | undefined> {
    const sp = this.code.byId(id);
    if (sp || !this.registryEnabled) return Promise.resolve(sp);
    return this.stored(adapter, "spId", id, log);
  }

  /** After a write in this isolate; other isolates see it within `cacheSeconds`. */
  invalidate(): void {
    this.cache.clear();
  }

  /** Validate a stored row into an SP; undefined (and logged) if it no longer passes. */
  fromRow(row: StoredSpRow | null | undefined, log: DirectoryLogger): ResolvedServiceProvider | undefined {
    if (!row || !isEnabled(row.enabled)) return undefined;
    let config: unknown;
    try {
      config = JSON.parse(row.config);
    } catch {
      log.error(`[saml-idp] registry: SP row ${row.spId} has invalid JSON; ignored`);
      return undefined;
    }
    const r = resolveStoredServiceProvider(config, this.options, this.options.registry?.authorize);
    if (!r.serviceProvider) {
      log.error(`[saml-idp] registry: SP ${row.spId} no longer validates (${r.issues.slice(0, 3).join("; ")}); ignored`);
      return undefined;
    }
    // The lookup columns must agree with the config they were copied from.
    if (r.serviceProvider.id !== row.spId || r.serviceProvider.entityId !== row.entityId) {
      log.error(`[saml-idp] registry: SP row ${row.spId} has mismatched id/entityId columns; ignored`);
      return undefined;
    }
    if (this.inCode(r.serviceProvider.id, r.serviceProvider.entityId)) return undefined; // code wins
    return r.serviceProvider;
  }

  private async stored(adapter: DirectoryAdapter, field: "entityId" | "spId", value: string, log: DirectoryLogger) {
    const key = `${field}\u0000${value}`;
    const cacheMs = this.options.registry?.cacheMs ?? 0;
    const hit = this.cache.get(key);
    if (hit && hit.expires > this.now()) return hit.sp;
    const row = (await adapter.findOne({ model: SP_MODEL, where: [{ field, value }] })) as StoredSpRow | null;
    let sp = this.fromRow(row, log);
    // Exact match only: a case-insensitive or PAD SPACE collation (e.g. MySQL) could return a row
    // for "HTTPS://SP.example " when "https://sp.example" was stored (review 2).
    if (sp && (field === "entityId" ? sp.entityId : sp.id) !== value) sp = undefined;
    if (cacheMs > 0) {
      if (this.cache.size >= MAX_CACHE_ENTRIES) this.cache.clear();
      this.cache.set(key, { sp, expires: this.now() + cacheMs });
    }
    return sp;
  }
}
