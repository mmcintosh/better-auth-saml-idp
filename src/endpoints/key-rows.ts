// The stored key rows behind tenants' keys (D-058) and the root's managed key (D-080): read, written
// and moved through their states the same way for both. An owner is a tenant's organization id, or
// ROOT_KEY_OWNER for the root.
import type { GenericEndpointContext } from "better-auth";
import { checkKeyPair, encryptTenantKey, KEEP_RETIRED, type KeySecret, stateKeyOf, TENANT_KEY_MODEL, type TenantKeyRow, type TenantKeyState } from "../saml/tenant-keys";
import type { TenantSigningKeyInfo } from "../types";
import { adapterOf } from "./registry";

const date = (v: unknown) => new Date(v as string | number | Date);
const ORDER: Record<TenantKeyState, number> = { next: 0, active: 1, previous: 2, retired: 3 };

/** Key rows as the API shows them: no private material, next first. */
export function keyInfo(rows: TenantKeyRow[], minPublishedMs: number): TenantSigningKeyInfo[] {
  return [...rows]
    .sort((a, b) => ORDER[a.state] - ORDER[b.state] || date(b.createdAt).getTime() - date(a.createdAt).getTime())
    .map((r) => ({
      kid: r.kid,
      state: r.state,
      certificate: r.certificate,
      notAfter: date(r.notAfter),
      createdAt: date(r.createdAt),
      activatedAt: r.activatedAt ? date(r.activatedAt) : null,
      ...(r.state === "next" ? { activatableAt: new Date(date(r.createdAt).getTime() + minPublishedMs) } : {}),
    }));
}

/** An owner's key rows, read now (not the per-isolate cache): exactly its own, whatever the collation. */
export async function keyRows(ctx: GenericEndpointContext, owner: string): Promise<TenantKeyRow[]> {
  const rows = (await adapterOf(ctx).findMany({ model: TENANT_KEY_MODEL, where: [{ field: "tenantId", value: owner }], limit: 100, sortBy: { field: "createdAt", direction: "desc" } })) as TenantKeyRow[];
  return rows.filter((r) => r.tenantId === owner);
}

/** A key row, its private key sealed to this owner and kid (D-058). The pair is checked first. */
export async function writeKeyRow(
  ctx: GenericEndpointContext,
  secret: KeySecret,
  owner: string,
  keyState: TenantKeyState,
  kid: string,
  privateKeyPem: string,
  certificate: string,
  userId: string,
  now = new Date(),
): Promise<TenantKeyRow> {
  const { notAfter } = checkKeyPair(privateKeyPem, certificate);
  const data = {
    tenantId: owner,
    kid,
    state: keyState,
    stateKey: stateKeyOf(owner, keyState),
    encryptedPrivateKey: await encryptTenantKey(secret, owner, kid, privateKeyPem),
    certificate,
    notAfter,
    createdAt: now,
    activatedAt: keyState === "active" ? now : null,
    updatedBy: userId,
  };
  const created = (await adapterOf(ctx).create({ model: TENANT_KEY_MODEL, data })) as { id?: unknown } | null;
  return { id: String(created?.id), ...data } as TenantKeyRow;
}

/** Move a row to another state; `next`/`active` take the owner's UNIQUE slot, others free it. */
export function moveKeyRow(ctx: GenericEndpointContext, row: TenantKeyRow, to: TenantKeyState, update: Record<string, unknown> = {}) {
  return adapterOf(ctx).update({ model: TENANT_KEY_MODEL, where: [{ field: "id", value: row.id }], update: { state: to, stateKey: stateKeyOf(row.tenantId, to), ...update } });
}

/** Keep the newest KEEP_RETIRED retired rows of an owner; the audit log has the rest. */
export async function pruneRetiredRows(ctx: GenericEndpointContext, owner: string): Promise<void> {
  const retiredRows = (await keyRows(ctx, owner)).filter((k) => k.state === "retired").sort((a, b) => date(b.createdAt).getTime() - date(a.createdAt).getTime());
  for (const old of retiredRows.slice(KEEP_RETIRED)) await adapterOf(ctx).delete({ model: TENANT_KEY_MODEL, where: [{ field: "id", value: old.id }] });
}
