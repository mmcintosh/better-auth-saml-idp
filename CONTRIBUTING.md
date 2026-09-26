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

Releases come only from CI ([release.yml](.github/workflows/release.yml)), so every npm version carries provenance and the tested tarball is the published one.

One-time setup:

1. The first publish needs an npm automation token as the repository secret `NPM_TOKEN`. `publishConfig.provenance` stops local `npm publish`: publishing is CI-only.
2. After that, configure **trusted publishing** on npmjs.com (package settings → Trusted publisher → GitHub Actions, workflow `release.yml`), then delete the token.

Each release:

1. Move `[Unreleased]` in CHANGELOG.md to `## [X.Y.Z] - YYYY-MM-DD`, set `version` in package.json (and remove `"private": true` for the first release), and commit.
2. Optionally, run **Actions → Release → Run workflow** for a dry run: it tests, packs, and builds the SBOM without publishing.
3. `git tag vX.Y.Z && git push origin vX.Y.Z`. The workflow checks that the tag matches package.json, publishes with provenance, and creates the GitHub release with the tarball and its CycloneDX SBOM.
