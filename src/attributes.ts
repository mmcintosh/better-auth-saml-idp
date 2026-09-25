// Declarative attribute mapping: `attributes: { email: "email", groups: { field: "role", split: "," } }`.
// Compiled once at startup into the same `(user) => Record<string, string | string[]>` a host
// function provides, so issuing code has one path.
import type { AttributeMap, AttributeSource, SamlAttributeValue, SamlIdpUser } from "./types";

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

function resolveSource(source: AttributeSource, user: SamlIdpUser, onMissing?: MissingFieldHandler): SamlAttributeValue | undefined {
  if (typeof source === "string") return resolveSource({ field: source }, user, onMissing);
  if ("value" in source) return Array.isArray(source.value) ? [...source.value] : source.value;
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

export function compileAttributeMap(map: AttributeMap) {
  const entries = Object.entries(map);
  return (user: SamlIdpUser, onMissing?: MissingFieldHandler): Record<string, SamlAttributeValue> => {
    const out: Record<string, SamlAttributeValue> = {};
    for (const [name, source] of entries) {
      const v = resolveSource(source, user, onMissing);
      if (v !== undefined) out[name] = v;
    }
    return out;
  };
}
