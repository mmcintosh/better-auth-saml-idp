// Better Auth access control (admin plugin) for the SP registry (D-031). Add the statement to your
// access controller and grant actions to roles:
//
//   import { createAccessControl } from "better-auth/plugins/access";
//   import { adminAc, defaultStatements, userAc } from "better-auth/plugins/admin/access";
//   import { samlIdpStatements } from "better-auth-saml-idp";
//   const ac = createAccessControl({ ...defaultStatements, ...samlIdpStatements });
//   const roles = {
//     admin: ac.newRole({ ...adminAc.statements, samlServiceProvider: ["list", "read", "create", "update", "delete"] }),
//     user: ac.newRole({ ...userAc.statements }),
//   };
//   admin({ ac, roles }); samlIdp({ registry: { enabled: true, permissions: true }, ... });
//
// With tenants (D-052), `samlTenant` covers the tenant routes the same way.

export const samlIdpStatements = {
  samlServiceProvider: ["list", "read", "create", "update", "delete"],
  samlTenant: ["list", "read", "create", "update", "delete"],
} as const;

export type SamlServiceProviderAction = (typeof samlIdpStatements)["samlServiceProvider"][number];
export type SamlTenantAction = (typeof samlIdpStatements)["samlTenant"][number];
export type SamlIdpResource = keyof typeof samlIdpStatements;

type Role = { authorize(request: Record<string, string[]>): { success: boolean } };
type AdminPluginOptions = { roles?: Record<string, Role>; adminUserIds?: string[]; defaultRole?: string };

/**
 * The admin plugin's permission check, evaluated with the host's own admin options (its roles
 * and adminUserIds), for one registry action on one resource. Without the admin plugin: false.
 */
export function adminAllows(
  plugins: readonly { id: string; options?: unknown }[] | undefined,
  user: { id: string; role?: unknown },
  action: SamlServiceProviderAction,
  resource: SamlIdpResource = "samlServiceProvider",
): boolean {
  const admin = (plugins ?? []).find((p) => p.id === "admin");
  if (!admin) return false;
  const opts = (admin.options ?? {}) as AdminPluginOptions;
  if (opts.adminUserIds?.includes(user.id)) return true;
  // Default admin-plugin roles know nothing about these resources, so they grant nothing here.
  if (!opts.roles) return false;
  const roles = String(user.role || opts.defaultRole || "user").split(",").map((r) => r.trim());
  return roles.some((r) => opts.roles?.[r]?.authorize({ [resource]: [action] })?.success === true);
}
