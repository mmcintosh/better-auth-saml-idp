# Contributing

Thanks for helping. Bug reports, SP interop reports, docs fixes and code are all welcome.

For **security vulnerabilities**, don't open an issue: see [SECURITY.md](SECURITY.md).

## Ways to help without writing code

- **Tell us an SP works (or doesn't).** Open an [SP interop report](https://github.com/mmcintosh/better-auth-saml-idp/issues/new?template=sp-interop.yml). A "works with X" report with the settings you used is as valuable as a bug report: it becomes an SP guide such as [Okta](docs/sp-okta.md) or [Auth0](docs/sp-auth0.md).
- **Improve the docs.** If something in the [guide](docs/guide/README.md) was unclear or wrong for you, it will be for others.

## Setup

You need Node 24 and pnpm 10 (`corepack enable` gives you the pinned version).

```sh
git clone https://github.com/mmcintosh/better-auth-saml-idp.git
cd better-auth-saml-idp
pnpm install
pnpm test
```

## Checks

Everything CI runs, locally:

| Command | What it does |
|---|---|
| `pnpm typecheck` | TypeScript. |
| `pnpm lint` | Biome with the security rules; warnings fail. |
| `pnpm test` | Unit, integration and SP interop tests, on Node and on workerd (D1). |
| `pnpm test:node` / `pnpm test:workerd` | One runtime only: quicker while iterating. |
| `pnpm test:wasm` | The WebAssembly schema validator's own suite. |
| `pnpm docs:check` | Every relative link and `#anchor` in the README and `docs/`. |
| `pnpm pack:check` | Builds, then checks the package with publint and Are the Types Wrong. |
| `pnpm e2e` | Real Chromium against Keycloak, SimpleSAMLphp and node-saml. Needs Docker and Playwright (`npx playwright install chromium`). |

Two suites need something extra:

- **Adapter matrix**, against a real database: start one, then point the tests at it, for example:

  ```sh
  docker run -d --rm -p 55432:5432 -e POSTGRES_PASSWORD=test postgres:17-alpine
  ADAPTER_DB=postgres ADAPTER_URL=postgres://postgres:test@localhost:55432/postgres \
    npx vitest run --project node test/adapters
  ```

  `ADAPTER_DB` is `postgres`, `mysql` or `mongodb`. MongoDB must be a replica set: see the `adapters` job in [ci.yml](.github/workflows/ci.yml).

- **Fuzzing** runs 150 cases per property in `pnpm test`. After touching a parser, the signature verifier or issuance, go deeper:

  ```sh
  FUZZ_RUNS=3000 npx vitest run --project node test/fuzz
  ```

## How changes are made here

- **Tests with every change.** A bug fix comes with the test that would have caught it.
- **Security controls are mutation-checked.** For a check that refuses something, disable it and confirm a test fails, then put it back. Commit first (or `cp` a backup) so the mutation can't lose work. Say in the PR that you did it.
- **Decisions are recorded.** A design choice, an interop finding or a security trade-off gets an entry in [DECISIONS.md](DECISIONS.md): what was found, what was decided, and the evidence. Look at recent entries for the shape.
- **Docs move with the code.** A new option goes in [options](docs/guide/options.md), a new error code in [errors](docs/guide/errors.md), and a new control in [security](docs/guide/security.md). Add a line under `[Unreleased]` in [CHANGELOG.md](CHANGELOG.md).
- **Breaking?** Check [Versioning and support](docs/guide/versioning.md). SAML output an SP can notice counts too.
- **No real secrets, ever.** Tests generate their keys. Use throwaway certificates, users and metadata in fixtures and issue reports. gitleaks runs on every push.
- **Commits:** small, with an imperative subject ("Refuse NameIDs XML can't carry") and a body that says why.

## Pull requests

1. Fork the repository and branch from `main`.
2. Make the change with its tests and docs.
3. Run `pnpm typecheck && pnpm lint && pnpm test && pnpm docs:check`.
4. Open the PR and fill in the template.

CI runs the full matrix, including the adapter matrix, e2e, CodeQL and a dependency review. A new **runtime** dependency needs a good reason: every one is attack surface for an IdP, and must be MIT-compatible.

## Releasing (maintainers)

Releases come only from CI ([release.yml](.github/workflows/release.yml)), so every npm version carries provenance, built from the same commit the tests ran on.

One-time setup (done 2026-09-27):

1. The name was claimed with a placeholder `0.0.1`, published by hand. npm can't trust-publish a package that doesn't exist yet. There is no npm token in this repository, and none is needed.
2. **Trusted publishing** on npmjs.com: package settings → Trusted publishing → GitHub Actions, user `mmcintosh`, repository `better-auth-saml-idp`, workflow `release.yml`, environment `npm`, with **"allow npm publish" left unchecked**: the workflow can only *stage* a version (`npm stage publish`), authenticating with GitHub's short-lived OIDC identity.
3. GitHub **Settings → Environments → `npm`**: the maintainer is a required reviewer, and only `v*` tags may deploy, so every publish waits for an approval.
4. `publishConfig.provenance` stops local `npm publish`: publishing is CI-only.

Each release:

1. Keep CHANGELOG.md's `[Unreleased]` section up to date as changes land.
2. **Check the docs against `[Unreleased]`.** Everything in it must be in the README (features, both option tables, the events row, the table of contents, a usage section for anything new), in the reference pages (options, errors, security, schema, observability, and the threat model in docs/security.md), and, for a new feature, in a guide page linked from docs/guide/README.md. The README goes into the npm package, so the npm page shows it as it is until the next release. The release PR repeats this as a checklist.
3. On an up-to-date, clean `main`: `pnpm release patch|minor|major ["One sentence for the top of the section."]`. It bumps `version` in package.json, dates the `[Unreleased]` section as `## [X.Y.Z] - YYYY-MM-DD`, and opens the **Release X.Y.Z** pull request (it refuses an empty `[Unreleased]`).
4. Optionally, run **Actions → Release → Run workflow** on `main` for a dry run: it tests, packs, and builds the SBOM without publishing.
5. **Merge the release PR when CI is green: that's the go-ahead.** [tag-release.yml](.github/workflows/tag-release.yml) sees the new version on `main`, tags `vX.Y.Z` there, and starts the release run on the tag. It checks the tag matches package.json and its commit is on `main`, tests and packs. After your approval in the `npm` environment, it **stages** the tested tarball with provenance and creates the GitHub release with its CycloneDX SBOM. (Pushing a `vX.Y.Z` tag by hand still works too.)
6. Approve the staged version on npmjs.com (Staged packages, with your security key) or with `npm stage approve <id>`. Only then is it installable; npm's malware scan must finish first.
7. Redeploy the public demo ([examples/workers-hono](examples/workers-hono/README.md)) so it runs the release.

What Dependabot doesn't cover (Better Auth against the peer range, the vendored builds in `vendor/`, updates held back on purpose) is listed weekly in the **Upstream watch** issue ([upstream-watch.yml](.github/workflows/upstream-watch.yml), configured in `.github/upstream-watch.json`). A new `vendor/` build must be added there, or the job fails.
