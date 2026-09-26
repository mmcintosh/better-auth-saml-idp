# Versioning and support

[Guide](README.md) › Versioning and support

What a version number promises, which Better Auth versions each release works with, and how long each release gets fixes.

The project is **pre-release**. This policy takes effect at 1.0.0, the first npm release.

## Semantic Versioning

Releases follow [SemVer](https://semver.org/). With an IdP, "breaking" also covers what service providers see, not only your code.

**Major** (`2.0.0`): you or your SPs may need to change something.

- Removing or renaming an export, an option, an endpoint path or an error code.
- Changing a default in a way an SP can notice: signing algorithm, what gets signed, NameID values, attribute encoding, bindings.
- A schema change that isn't purely additive, such as a renamed field or a new required field without a default.
- Dropping a Better Auth version, or a Node version, from the supported range.

**Minor** (`1.1.0`): new things you can opt into.

- New options, endpoints, exports, error codes and SP features. They are off by default whenever turning them on would change behaviour.
- **Additive** schema changes: a new optional field or a new table. Run your migrations, as the [changelog](../../CHANGELOG.md) will say.
- Support for a new Better Auth minor.

**Patch** (`1.0.1`): fixes.

- Bug fixes, and docs and dependency updates.
- **Security fixes, even when they refuse input that used to be accepted.** Fuzzing, for example, led to refusing NameIDs that XML can't carry exactly ([D-036](../../DECISIONS.md)). A fix that tightens security isn't held back for a major. The changelog marks it, says what is now refused, and gives the error code.

## Better Auth compatibility

The plugin declares a bounded peer range on `better-auth`, currently `>=1.7.5 <1.8`:

- CI tests every change at the **lowest** version in the range and at the **latest** release in it.
- The [upstream canary](../../.github/workflows/upstream-canary.yml) tests Better Auth's `latest` and `next` tags weekly and opens an issue when something breaks.
- A new Better Auth minor gets support in a plugin **minor** release once it passes, which widens the range. The range is never widened without testing.
- The same goes for `better-auth-cloudflare` on Workers.

## Support windows

| Line | Gets |
|---|---|
| Latest minor of the current major | All fixes. |
| Older minors of the current major | Nothing: upgrading within a major is designed to be safe. |
| Previous major | **Security fixes for 6 months** after the next major is released. |
| Older | Nothing. |

Node: the [active and maintenance LTS lines](https://nodejs.org/en/about/previous-releases). CI tests Node 22 and 24. A Node line that reaches end of life is dropped in the next major. (Node 20 reached end of life in April 2026. `engines` still says `>=20` until 1.0 settles it.)

Cloudflare Workers: the `compatibility_date` in the [example](../../examples/workers-hono/wrangler.jsonc), or later.

## Deprecations

A feature due for removal is:

1. marked `@deprecated` in the types, and logged once at startup when used;
2. listed under **Deprecated** in the changelog;
3. kept for at least one minor release before the major that removes it.

## Where changes are recorded

- [CHANGELOG.md](../../CHANGELOG.md): what changed in each release, in [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) format.
- [DECISIONS.md](../../DECISIONS.md): why, with the evidence.
- [GitHub security advisories](https://github.com/mmcintosh/better-auth-saml-idp/security/advisories): vulnerabilities and the versions they affect.
