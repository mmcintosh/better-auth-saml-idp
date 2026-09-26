# Users and access

[Guide](README.md) › Users and access

Who gets an assertion, what it says about them, and how to decide per SP.

Checks run in this order, right before signing:

1. **Fresh re-read**: the user and (where the database holds it) the session are read again from the database. Deleted, banned, revoked or expired means `ACCOUNT_INACTIVE`.
2. **[Account policy](#account-policy)**: verified email; no impersonated or anonymous sessions.
3. **[Organization rule](#organizations)** of the SP, if it has one.
4. **[`authorize()`](#authorize)** of the SP.
5. **[NameID](#nameid)** and **[attributes](#attributes)** are computed.

## Account policy

An IdP tells other applications "this is who the user is", so the defaults are strict:

```ts
samlIdp({
  // …
  accountPolicy: {
    requireEmailVerified: true,       // default
    allowImpersonatedSessions: false, // default: admin-plugin impersonation can't sign in to SPs
    allowAnonymousUsers: false,       // default: anonymous-plugin users can't
  },
});
```

| Situation | Error |
|---|---|
| Email not verified | `EMAIL_NOT_VERIFIED` |
| Admin impersonating the user (`session.impersonatedBy`) | `SESSION_NOT_ALLOWED` |
| Anonymous user (`user.isAnonymous`) | `SESSION_NOT_ALLOWED` |
| User deleted or banned (`banned`, respecting `banExpires`) | `ACCOUNT_INACTIVE` |
| Session revoked or expired | `ACCOUNT_INACTIVE` |

Relaxing these is possible, but think about what the SP will do with the identity. An unverified email means anyone who typed that address.

## NameID

The NameID is the SP's primary identifier for the user. Each SP sets `nameIdFormat`:

| Format | `nameIdFormat` | NameID value |
|---|---|---|
| Email (default) | `urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress` | The user's (verified) email. |
| Persistent | `urn:oasis:names:tc:SAML:2.0:nameid-format:persistent` | An opaque, stable identifier: an HMAC of the user id and the SP's entity ID, keyed with the Better Auth secret. The same user always gets the same value at one SP and different values at different SPs, so SPs can't link users between them. Never reassigned to someone else. |
| Transient | `urn:oasis:names:tc:SAML:2.0:nameid-format:transient` | A new random value for every assertion. |
| Unspecified | `urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified` | The email. |

`NAMEID_FORMAT` exports these constants. A code SP can override the value with `nameId: (user) => string`, which must return a non-empty string. A NameID the XML can't carry exactly (control characters, lone surrogates, U+FFFD, or line endings such as CR and U+2028) is refused with `INTERNAL_ERROR` and logged, never altered.

If a request's `NameIDPolicy` asks for another format than the SP's, the SP gets `InvalidNameIDPolicy`. If it names a `Subject`, the NameID must match the signed-in user, otherwise `UnknownPrincipal`.

Changing an SP's format (or the Better Auth secret, for persistent IDs) changes every user's identifier at that SP. Treat it as a migration.

## Attributes

Attributes carry everything else the SP needs: email, names, groups. Each SP's `attributes` is a declarative map or a function.

### Declarative map

Works from code, JSON configuration and the [registry](service-providers.md#registry):

```ts
attributes: {
  email: "email",                                // a user field
  role: "role",                                  // additional fields too (e.g. the admin plugin's)
  verified: "emailVerified",                     // booleans become "true"/"false"
  created: "createdAt",                          // dates become ISO 8601
  teams: { field: "teams", split: "," },         // one field → several values
  firstName: { field: "name", part: "first" },   // "Ada King Lovelace" → "Ada"
  lastName: { field: "name", part: "last" },     //                    → "King Lovelace"
  org: { value: "Acme" },                        // a constant
  groups: { organization: "slugs" },             // organization plugin: see below
}
```

| Source | Value |
|---|---|
| `"field"` | The user's own property. Only own properties are read, so `"constructor"` resolves to nothing. |
| `{ field, split }` | Split on the separator (1 to 8 characters); pieces are trimmed, empty ones dropped. |
| `{ field, part }` | `"first"`: the first word; `"last"`: the rest. For SPs that want first and last name. |
| `{ value }` | A string, or a non-empty array of strings. |
| `{ organization, only? }` | `"slugs"`, `"names"`, `"ids"` or `"roles"` from the [organization plugin](#organizations), limited to `only` (ids or slugs) or, with a rule, to the SP's organization. |

> [!IMPORTANT]
> **Map only fields users can't set themselves.** Better Auth's `user.additionalFields` default to `input: true`, so users can change them with `/update-user`, and the SP would trust whatever they chose. For any additional field an SP relies on (a department, a cost center, a role), set `input: false`. The plugin warns at startup, or on first use for stored SPs, when a map reads a user-writable field. The admin plugin's `role` is already `input: false`.

Values that are missing, null, empty or objects are left out, rather than sending `"[object Object]"`; arrays are multi-valued. A field the user doesn't have is logged once per SP and field (`attributes for SP x: the user has no field "departmnt"`), so typos show up.

### Function

For anything the map can't express (code SPs only):

```ts
attributes: (user, { organizations, organization }) => ({
  email: user.email,
  displayName: `${user.name} (${organization?.slug ?? "personal"})`,
  groups: organizations.flatMap((o) => o.roles.map((r) => `${o.slug}-${r}`)),
}),
```

It must be synchronous and return strings or string arrays. A throw means `INTERNAL_ERROR` (no assertion).

### How attributes appear

Each attribute is sent with `NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"`, one `AttributeValue` per value, with values XML-escaped. So that every SP parses the value and verifies the signature:
- characters XML 1.0 can't carry (control characters other than TAB, LF and CR; U+FFFE/U+FFFF; lone surrogates) and U+FFFD are removed;
- CR, CRLF, U+0085, U+2028 and U+2029 become LF, which is how XML parsers would read most of them anyway. Attribute names are what the SP expects: check its documentation (for example `email`, `firstName`, or URIs such as `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress`).

## Organizations

With Better Auth's **organization plugin** installed, SPs can be limited to organizations and can receive organization data.

```ts
{
  id: "zoom",
  entityId: "…",
  acsUrls: ["…"],
  organization: { id: "org_8f3…", roles: ["admin", "member"] }, // members of that organization with one of these roles
  attributes: {
    email: "email",
    groups: { organization: "slugs" },  // this SP's organization only (it has a rule)
    roles: { organization: "roles" },   // their roles in it
    partners: { organization: "slugs", only: ["org_8f3…", "org_2c1…"] }, // several, by id
  },
}
```

> [!WARNING]
> **Users can create organizations.** The organization plugin lets any user create one by default (`allowUserToCreateOrganization`), choosing its name and slug. So a user can make an organization called "Administrators". What protects you:
> - **Rules by `id`**, which nobody can choose. A rule by slug can be satisfied by whoever creates that slug first, if nobody has yet.
> - **Scoped attributes.** With a rule, organization attributes cover only the SP's organization. Without a rule, set `only` to the organizations the SP may hear about, or every organization the user created goes to the SP.
> - Or turn off user-created organizations: `organization({ allowUserToCreateOrganization: false })`.
>
> The plugin warns at startup, or on first use for stored SPs, when users can create organizations and an SP relies on something they could claim.

- **`organization: { slug | id, roles? }`**: only members get in, and with `roles`, only members holding at least one of them. Multi-role members (`"member,admin"`) work. Otherwise: `ACCESS_DENIED`.
- **Fails closed:** an SP with an `organization` rule refuses everyone if the organization plugin isn't installed.
- **Attributes:** `{ organization: "slugs" | "names" | "ids" | "roles" }` covers the organizations in `only` (ids or slugs) when set; otherwise the SP's own organization when it has a rule; otherwise every membership (then roles are `"slug:role"`).
- **Stored SPs:** it's all JSON, so SPs in the registry can use it too.
- Memberships are loaded once per assertion, through Better Auth's adapter by the plugin's model names, so renamed tables work.

## `authorize`

The last word, per SP (code SPs; stored SPs use `registry.authorize`):

```ts
{
  id: "payroll",
  entityId: "…",
  acsUrls: ["…"],
  authorize: async ({ user, session, serviceProvider, organizations }) =>
    user.role === "admin" || organizations.some((o) => o.slug === "finance"),
}
```

Anything other than exactly `true` is `ACCESS_DENIED`, and so is a throw (logged). It runs on the freshly re-read user. `serviceProvider` is a read-only `ServiceProviderInfo`: `id`, `entityId`, `acsUrls`, `nameIdFormat` and the `organization` rule.

## Registry permissions

Who may manage stored SPs through the registry API. Either a function:

```ts
registry: { enabled: true, canManage: ({ user }) => user.role === "admin" }
```

Or Better Auth's **admin-plugin access control**, one action at a time:

```ts
import { createAccessControl } from "better-auth/plugins/access";
import { adminAc, defaultStatements, userAc } from "better-auth/plugins/admin/access";
import { admin } from "better-auth/plugins";
import { samlIdpStatements } from "better-auth-saml-idp";

const ac = createAccessControl({ ...defaultStatements, ...samlIdpStatements });
const roles = {
  admin: ac.newRole({ ...adminAc.statements, samlServiceProvider: ["list", "read", "create", "update", "delete"] }),
  auditor: ac.newRole({ samlServiceProvider: ["list", "read"] }),
  user: ac.newRole({ ...userAc.statements }),
};

betterAuth({
  plugins: [
    admin({ ac, roles }),
    samlIdp({ /* … */, registry: { enabled: true, permissions: true } }),
  ],
});
```

| Action | Endpoint |
|---|---|
| `list` | `GET /saml-idp/service-providers` |
| `read` | `GET /saml-idp/service-providers/get` |
| `create` | `POST /saml-idp/service-providers/create` |
| `update` | `POST /saml-idp/service-providers/update` |
| `delete` | `POST /saml-idp/service-providers/delete` |

- The admin plugin's **default** roles grant nothing on `samlServiceProvider`: you opt roles in explicitly. `adminUserIds` are always allowed.
- A user with several roles is allowed if any of them grants the action.
- With both `canManage` and `permissions`, both must allow.
- Either way, the session is re-read from the database (a demoted admin loses access at once, even with the cookie cache on), impersonated sessions are refused, and mutations keep Better Auth's origin checks.
