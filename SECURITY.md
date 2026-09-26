# Security policy

An identity provider is a high-value target: a flaw here can let someone sign in anywhere as anyone. Reports are welcome and taken seriously.

## Reporting a vulnerability

**Please don't open a public issue.** Report privately through GitHub:

1. Go to the repository's **[Security](https://github.com/mmcintosh/better-auth-saml-idp/security) tab**.
2. Choose **Report a vulnerability**.

Please include, as far as you can:

- the version or commit, the runtime (Node or Workers) and the database;
- the SP or message that triggers it, with any certificates, keys and personal data replaced by throwaway ones;
- what an attacker gains: signing in as someone else, reaching an SP they shouldn't, replaying a message, ending someone's session, denial of service, …

What happens next:

- The maintainer aims to acknowledge a report within **7 days** and to agree on a fix and a disclosure date with you.
- Fixes are developed in a private GitHub security advisory and released with a CVE where one applies.
- You're credited in the advisory and the changelog, unless you'd rather not be.

## Supported versions

The project is **pre-release**: nothing is published to npm yet, and only `main` gets fixes. After 1.0, see [Versioning and support](docs/guide/versioning.md) for which versions get security fixes and for how long.

## Scope

In scope:

- The plugin (`src/`) and its CLI.
- The WebAssembly schema validator (`wasm/`, built from `wasm-validator/`).
- The published package's configuration and defaults.

Out of scope, but still worth telling us about:

- Better Auth itself, `@better-auth/sso` and `better-auth-cloudflare`. Report these to their projects; we'll help coordinate if the plugin is affected.
- An SP's own SAML handling.
- The example Worker's deployment, as opposed to its code.
- Behaviour documented as a [known limitation](docs/security.md#known-limitations-v1).

## What the plugin already defends against

The [threat model](docs/security.md) lists each attack and the control that answers it, and the [security reference](docs/guide/security.md) lists every control with its options. [DECISIONS.md](DECISIONS.md) records the evidence for each: tests, mutation checks, fuzzing and review findings. Reading these first helps tell a new issue from a known limitation.

## Supply chain

- **Actions:** every GitHub Action is pinned to a commit SHA.
- **Automated checks:**
  - CodeQL (security-extended) on every push and PR, and weekly.
  - Runtime dependencies are audited on every push and PR, and a vulnerability blocks the build.
  - OSV-Scanner scans the whole lockfile daily.
  - OpenSSF Scorecard runs weekly.
- **Releases:** they will be published from CI with **npm provenance**, and each GitHub release carries a CycloneDX **SBOM** of the installed dependency tree.
- **Other:** gitleaks scans the full history on every push, and secret push protection is on.
