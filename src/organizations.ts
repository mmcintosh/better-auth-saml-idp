// Better Auth organization plugin integration (D-031): memberships for per-SP access rules,
// attribute maps ({ organization: "slugs" | … }) and authorize(). Read through the adapter with
// the plugin's model keys ("member", "organization"), so renamed tables work.
import type { OrganizationMembership } from "./types";

type Adapter = {
  findMany(a: { model: string; where: { field: string; value: unknown; operator?: "in" }[]; limit?: number }): Promise<unknown[]>;
};

const MAX_MEMBERSHIPS = 500;

/** Is Better Auth's organization plugin installed? */
export const hasOrganizationPlugin = (plugins: readonly { id: string }[] | undefined) => (plugins ?? []).some((p) => p.id === "organization");

export async function loadMemberships(adapter: Adapter, userId: string): Promise<OrganizationMembership[]> {
  const members = (await adapter.findMany({ model: "member", where: [{ field: "userId", value: userId }], limit: MAX_MEMBERSHIPS })) as {
    organizationId: string;
    role?: string | null;
  }[];
  if (members.length === 0) return [];
  const ids = [...new Set(members.map((m) => m.organizationId))];
  const orgs = (await adapter.findMany({ model: "organization", where: [{ field: "id", value: ids, operator: "in" }], limit: MAX_MEMBERSHIPS })) as {
    id: string;
    slug: string;
    name: string;
  }[];
  const byId = new Map(orgs.map((o) => [o.id, o]));
  const out: OrganizationMembership[] = [];
  for (const m of members) {
    const org = byId.get(m.organizationId);
    if (!org) continue;
    // Better Auth stores several roles comma-separated ("admin,member").
    const roles = String(m.role ?? "")
      .split(",")
      .map((r) => r.trim())
      .filter(Boolean);
    out.push({ id: org.id, slug: org.slug, name: org.name, roles });
  }
  return out;
}

/** The membership an SP's `organization` rule names, if the user has it (and one of its roles). */
export function matchOrganization(
  memberships: OrganizationMembership[],
  rule: { slug?: string; id?: string; roles?: string[] },
): OrganizationMembership | undefined {
  const m = memberships.find((o) => (rule.id !== undefined ? o.id === rule.id : o.slug === rule.slug));
  if (!m) return undefined;
  if (rule.roles?.length && !m.roles.some((r) => rule.roles?.includes(r))) return undefined;
  return m;
}
