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

/**
 * Can users create organizations (and so choose slugs and names)? The organization plugin's
 * `allowUserToCreateOrganization` defaults to true; a function counts as "yes", since it may be.
 */
export function usersCanCreateOrganizations(plugins: readonly { id: string; options?: unknown }[] | undefined): boolean {
  const org = (plugins ?? []).find((p) => p.id === "organization");
  if (!org) return false;
  return (org.options as { allowUserToCreateOrganization?: unknown } | undefined)?.allowUserToCreateOrganization !== false;
}

/**
 * What in this SP's configuration a user could satisfy with an organization they created
 * themselves (review 4, R4-1): a rule by slug (a slug nobody has taken yet can be claimed), and
 * organization attributes without an `only` allow-list (any name or slug the user chose).
 */
const warnedClaimable = new Set<string>();

/**
 * Warn, once per SP, when users can create organizations and this SP relies on something they
 * could claim. Called at startup for code SPs and at first issuance for stored ones.
 */
export function warnClaimableOrganizations(
  logger: { warn(message: string): void },
  plugins: readonly { id: string; options?: unknown }[] | undefined,
  sp: { id: string; organization?: { slug?: string; id?: string }; attributeMap?: Record<string, unknown> },
): void {
  if (warnedClaimable.has(sp.id) || !usersCanCreateOrganizations(plugins)) return;
  const reasons = claimableOrganizationUse(sp);
  if (reasons.length === 0) return;
  warnedClaimable.add(sp.id);
  logger.warn(
    `[saml-idp] SP ${sp.id}: users can create organizations (organization plugin, allowUserToCreateOrganization), so a user can satisfy this with an organization they made: ${reasons.join("; ")}. Set allowUserToCreateOrganization: false, or use organization ids and \`only\`.`,
  );
}

export function claimableOrganizationUse(sp: { organization?: { slug?: string; id?: string }; attributeMap?: Record<string, unknown> }): string[] {
  const out: string[] = [];
  if (sp.organization && sp.organization.id === undefined && sp.organization.slug !== undefined)
    out.push(`organization rule by slug "${sp.organization.slug}" (use its id)`);
  // With a rule, unlisted organization attributes cover only the rule's organization.
  if (!sp.organization)
    for (const [name, source] of Object.entries(sp.attributeMap ?? {}))
      if (source && typeof source === "object" && "organization" in source && !(source as { only?: unknown }).only)
        out.push(`attribute "${name}" from organizations without \`only\``);
  return out;
}

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
