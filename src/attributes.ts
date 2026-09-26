// Declarative attribute mapping: `attributes: { email: "email", groups: { field: "role", split: "," } }`.
// Compiled once at startup into the same `(user) => Record<string, string | string[]>` a host
// function provides, so issuing code has one path.
import type { AttributeContext, AttributeMap, AttributeSource, SamlAttributeValue, SamlIdpUser } from "./types";

/** Called with a field name the user object doesn't have (typo, or an unconfigured additional field). */
export type MissingFieldHandler = (field: string) => void;

function scalar(v: unknown): string | undefined {
  if (v === undefined || v === null) return undefined;
  if (typeof v === "string") return v;
  if (typeof v === "number" || typeof v === "bigint" || typeof v === "boolean") return String(v);
  if (v instanceof Date) return Number.isNaN(v.getTime()) ? undefined : v.toISOString();
  // Objects have no single obvious string form: leave them out rather than send "[object Object]".
  return undefined;
}

function nonEmpty(values: string[]): SamlAttributeValue | undefined {
  const kept = values.filter((v) => v !== "");
  if (kept.length === 0) return undefined;
  return kept.length === 1 ? (kept[0] as string) : kept;
}

function resolveSource(source: AttributeSource, user: SamlIdpUser, context: AttributeContext, onMissing?: MissingFieldHandler): SamlAttributeValue | undefined {
  if (typeof source === "string") return resolveSource({ field: source }, user, context, onMissing);
  if ("value" in source) return Array.isArray(source.value) ? [...source.value] : source.value;
  if ("organization" in source) {
    const only = source.only;
    // Scope: the `only` allow-list; else the SP's own organization when it has a rule (review 4:
    // otherwise a member could create "Administrators" and send it); else every membership.
    const orgs = only
      ? context.organizations.filter((o) => only.includes(o.id) || only.includes(o.slug))
      : context.organization
        ? [context.organization]
        : context.organizations;
    const inScope = context.organization && (!only || orgs.includes(context.organization)) ? context.organization : undefined;
    switch (source.organization) {
      case "slugs":
        return nonEmpty(orgs.map((o) => o.slug));
      case "names":
        return nonEmpty(orgs.map((o) => o.name));
      case "ids":
        return nonEmpty(orgs.map((o) => o.id));
      case "roles":
        // In the SP's organization when it has one; otherwise qualified by organization.
        if (context.organization) return inScope ? nonEmpty(inScope.roles) : undefined;
        return nonEmpty(orgs.flatMap((o) => o.roles.map((r) => `${o.slug}:${r}`)));
    }
  }
  if (!Object.hasOwn(user, source.field)) {
    onMissing?.(source.field);
    return undefined;
  }
  const raw = user[source.field];
  let values = (Array.isArray(raw) ? raw : [raw]).map(scalar).filter((v): v is string => v !== undefined);
  if (source.split !== undefined) values = values.flatMap((v) => v.split(source.split as string)).map((v) => v.trim());
  if (source.part) {
    // "Ada King Lovelace" → first "Ada", last "King Lovelace" (the rest), as SPs like HubSpot expect.
    const [first = "", ...rest] = (values[0] ?? "").trim().split(/\s+/);
    values = [source.part === "first" ? first : rest.join(" ")];
  }
  return nonEmpty(values);
}

const NO_ORGS: AttributeContext = { organizations: [], organization: undefined };

/**
 * Mapped user fields that the user can set themselves (R4-L9): Better Auth's `additionalFields`
 * default to `input: true`, so `/update-user` accepts them and the SP would receive whatever the
 * user chose (a "department" or "role" the SP trusts). Core fields and `input: false` are fine.
 */
export function userWritableMappedFields(map: AttributeMap | undefined, additionalFields: Record<string, { input?: boolean; [key: string]: unknown }> | undefined): string[] {
  const out = new Set<string>();
  for (const source of Object.values(map ?? {})) {
    const field = typeof source === "string" ? source : "field" in source ? source.field : undefined;
    if (field !== undefined && Object.hasOwn(additionalFields ?? {}, field) && additionalFields?.[field]?.input !== false) out.add(field);
  }
  return [...out];
}

const warnedWritable = new Set<string>();

/** Warn once per SP about user-writable mapped fields; at startup for code SPs, first use for stored ones. */
export function warnUserWritableFields(
  logger: { warn(message: string): void },
  userOptions: { additionalFields?: Record<string, { input?: boolean; [key: string]: unknown }> } | undefined,
  sp: { id: string; attributeMap?: AttributeMap },
): void {
  if (warnedWritable.has(sp.id)) return;
  const fields = userWritableMappedFields(sp.attributeMap, userOptions?.additionalFields);
  if (fields.length === 0) return;
  warnedWritable.add(sp.id);
  logger.warn(
    `[saml-idp] SP ${sp.id}: attributes map user fields the user can change themselves (${fields.join(", ")}): set input: false on them in user.additionalFields if the SP trusts them.`,
  );
}

/** Does this map read organization data (so issuance must load memberships)? */
export const usesOrganizations = (map: AttributeMap | undefined) => Object.values(map ?? {}).some((s) => typeof s === "object" && "organization" in s);

export function compileAttributeMap(map: AttributeMap) {
  const entries = Object.entries(map);
  return (user: SamlIdpUser, context: AttributeContext = NO_ORGS, onMissing?: MissingFieldHandler): Record<string, SamlAttributeValue> => {
    const out: Record<string, SamlAttributeValue> = {};
    for (const [name, source] of entries) {
      const v = resolveSource(source, user, context, onMissing);
      if (v !== undefined) out[name] = v;
    }
    return out;
  };
}
