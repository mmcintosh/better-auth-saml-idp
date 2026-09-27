// NameID from a user field (roadmap D4): `nameId: { field }`, usable by code and stored SPs.
import type { SamlIdpUser } from "./types";

type FieldDef = { input?: boolean; [key: string]: unknown };
type AuthOptionsLike = {
  user?: { additionalFields?: Record<string, FieldDef> };
  plugins?: readonly { schema?: { user?: { fields?: Record<string, FieldDef> } } }[];
};

/** Fields the user can never set: the id, and the email (changing it goes through verification). */
const SAFE_CORE = new Set(["id", "email"]);

/**
 * Why `field` can't be a NameID, or undefined if it can. The NameID *is* the user's identity at
 * the SP: a field the user can edit (core `name`/`image`, or an additional field without
 * `input: false`) would let them claim someone else's account there. Plugin-added user fields
 * count with their own `input` setting.
 */
export function nameIdFieldProblem(field: string, auth: AuthOptionsLike): string | undefined {
  if (SAFE_CORE.has(field)) return undefined;
  const defs = [auth.user?.additionalFields?.[field], ...(auth.plugins ?? []).map((p) => p.schema?.user?.fields?.[field])].filter(
    (d): d is FieldDef => d !== undefined,
  );
  if (defs.length === 0)
    return `nameId.field "${field}" is not a user field this server can vouch for: use "id", "email", or an additional field with input: false`;
  if (defs.some((d) => d.input !== false))
    return `nameId.field "${field}" is a field users can set themselves (set input: false on it), so a user could take over another's identity at the SP`;
  return undefined;
}

/** The field's value as a NameID: a non-empty string, or a finite number as its digits; otherwise "". */
export function nameIdFromField(user: SamlIdpUser, field: string): string {
  const v = (user as Record<string, unknown>)[field];
  if (typeof v === "string") return v.trim();
  if (typeof v === "number" && Number.isFinite(v)) return String(v);
  return "";
}
