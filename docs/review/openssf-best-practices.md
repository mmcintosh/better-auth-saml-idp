# OpenSSF Best Practices badge: answers (passing level)

For the maintainer claiming the badge at <https://www.bestpractices.dev>: sign in with GitHub, choose **Add project**, enter `https://github.com/mmcintosh/better-auth-saml-idp`, then answer each criterion with the evidence below. Answers are **Met** unless noted. `REPO` means `https://github.com/mmcintosh/better-auth-saml-idp`.

## Basics

| Criterion | Answer and evidence |
|---|---|
| `description_good` | Met. README: "Turn your Better Auth server into a SAML 2.0 Identity Provider…" (REPO#readme) |
| `interact` | Met. Issues with forms (bug, SP interop, feature), private vulnerability reporting, CONTRIBUTING (REPO/blob/main/CONTRIBUTING.md) |
| `contribution` | Met. REPO/blob/main/CONTRIBUTING.md |
| `contribution_requirements` | Met. CONTRIBUTING "How changes are made here": tests with every change, the checks to run, DECISIONS entries |
| `floss_license` | Met. MIT (REPO/blob/main/LICENSE) |
| `floss_license_osi` | Met. MIT is OSI-approved |
| `license_location` | Met. `LICENSE` at the repository root |
| `documentation_basics` | Met. The guide: REPO/blob/main/docs/guide/README.md (getting started, every option, flows) |
| `documentation_interface` | Met. Options reference (docs/guide/options.md), errors (docs/guide/errors.md), schema (docs/guide/schema.md); exported TypeScript types |
| `sites_https` | Met. GitHub, npm and the docs site (GitHub Pages) are HTTPS only |
| `discussion` | Met. GitHub issues and pull requests (searchable, URL-addressable) |
| `english` | Met |
| `maintained` | Met. Active development; see the commit history and DECISIONS.md |

## Change control

| Criterion | Answer and evidence |
|---|---|
| `repo_public` | Met. Public GitHub repository |
| `repo_track` | Met. git |
| `repo_interim` | Met. Every change is a commit on `main`, not only releases |
| `repo_distributed` | Met. git |
| `version_unique` | Met. Semantic versions; each release is a git tag (`v1.0.0-rc.1`) |
| `version_semver` | Met (suggested). SemVer; docs/guide/versioning.md |
| `version_tags` | Met (suggested). Releases are tagged `vX.Y.Z[-rc.N]`; the workflow refuses a tag that doesn't match package.json |
| `release_notes` | Met. CHANGELOG.md (Keep a Changelog); each GitHub release carries its section |
| `release_notes_vulns` | Met. The CHANGELOG has a Security section per release; advisories go through GitHub security advisories with CVEs where one applies (SECURITY.md) |

## Reporting

| Criterion | Answer and evidence |
|---|---|
| `report_process` | Met. GitHub issues with forms (REPO/issues/new/choose) |
| `report_tracker` | Met (suggested). GitHub issues |
| `report_responses` | Met. The maintainer responds to issues; SECURITY.md sets a 7-day acknowledgement target for vulnerability reports |
| `enhancement_responses` | Met. Feature requests through the feature form; the roadmap in the README records decisions |
| `report_archive` | Met. GitHub issues are public and archived |
| `vulnerability_report_process` | Met. SECURITY.md: private reporting through GitHub (REPO/security/advisories/new) |
| `vulnerability_report_private` | Met. GitHub private vulnerability reporting is enabled |
| `vulnerability_report_response` | Met. 7-day acknowledgement target (SECURITY.md) |

## Quality

| Criterion | Answer and evidence |
|---|---|
| `build` | Met. `pnpm build` (scripts/build.mjs); CI builds and packs on every change |
| `build_common_tools` | Met (suggested). Node.js, pnpm, esbuild, TypeScript |
| `build_floss_tools` | Met. All build tools are FLOSS |
| `test` | Met. `pnpm test` (Vitest) on Node and on workerd with D1; documented in CONTRIBUTING |
| `test_invocation` | Met (suggested). `pnpm test` |
| `test_most` | Met (suggested). About 1,200 tests: unit, integration, SP interop, fuzzing, Playwright e2e against Keycloak and SimpleSAMLphp; the adapter matrix on Postgres, MySQL and MongoDB, including Prisma and Drizzle; the built package smoke-tested on Bun and Deno; the Next.js example built, started and signed in through on every CI run |
| `test_continuous_integration` | Met (suggested). GitHub Actions on every push and pull request (.github/workflows/ci.yml) |
| `test_policy` | Met. CONTRIBUTING: "Tests with every change. A bug fix comes with the test that would have caught it." |
| `tests_are_added` | Met. Every DECISIONS entry since D-001 lists its tests; recent features also record mutation checks (DECISIONS.md) |
| `tests_documented_added` | Met (suggested). The policy is in CONTRIBUTING |
| `warnings` | Met. TypeScript `strict`, Biome lint with `--error-on-warnings` in CI |
| `warnings_fixed` | Met. CI fails on lint warnings and type errors |
| `warnings_strict` | Met (suggested). `strict: true`, errors on warnings |

## Security

| Criterion | Answer and evidence |
|---|---|
| `know_secure_design` | Met. docs/security.md (threat model) and docs/guide/security.md (every control); five review rounds recorded in DECISIONS (D-029, D-030, D-039, D-046, D-048) |
| `know_common_errors` | Met. XML signature wrapping, XXE/DOCTYPE, replay, open redirects, CSRF and injection are addressed and tested (docs/guide/security.md) |
| `crypto_published` | Met. RSA-SHA256/512 signatures, AES-GCM with RSA-OAEP encryption: published, standard algorithms (XML-DSig, XML-Enc) |
| `crypto_call` | Met. Node's crypto (OpenSSL) and xml-crypto; no custom cryptographic primitives |
| `crypto_floss` | Met. All cryptography is implementable with FLOSS |
| `crypto_keylength` | Met. RSA keys of at least 2048 bits are enforced at startup; `keygen` defaults to 3072 |
| `crypto_working` | Met. SHA-1 and AES-CBC are refused unless explicitly opted into (`allowInsecureSha1`, `allowInsecureCbc`), with warnings; RSA PKCS#1 v1.5 key transport isn't offered |
| `crypto_weaknesses` | Met (suggested). As above |
| `crypto_pfs` | N/A. The plugin doesn't implement network protocols; TLS is the host's |
| `crypto_password_storage` | N/A. The plugin stores no passwords; Better Auth does |
| `crypto_random` | Met. IDs, tokens and keys from `crypto.getRandomValues` / Node crypto |
| `delivery_mitm` | Met. Delivered over HTTPS from npm and GitHub; npm provenance (SLSA) and a signed provenance attached to each GitHub release |
| `delivery_unsigned` | Met. No hash is retrieved over HTTP |
| `vulnerabilities_fixed_60_days` | Met. No publicly known unpatched vulnerabilities |
| `vulnerabilities_critical_fixed` | Met (suggested) |
| `no_leaked_credentials` | Met. gitleaks scans the full history in CI; test keys are generated per run |

## Analysis

| Criterion | Answer and evidence |
|---|---|
| `static_analysis` | Met. CodeQL (security-extended) on every push; Biome; TypeScript strict |
| `static_analysis_common_vulnerabilities` | Met (suggested). CodeQL security queries |
| `static_analysis_fixed` | Met. CodeQL alerts are fixed or dismissed with a recorded reason (DECISIONS D-037) |
| `static_analysis_often` | Met (suggested). Every push and pull request |
| `dynamic_analysis` | Met (suggested). Property-based fuzzing (fast-check) of every inbound parser and the signature verifier on every CI run; Playwright e2e in real Chromium |
| `dynamic_analysis_unsafe` | N/A. TypeScript, not a memory-unsafe language (libxml2 runs as WebAssembly, sandboxed) |
| `dynamic_analysis_enable_assertions` | Met (suggested). Tests run with assertions |
| `dynamic_analysis_fixed` | Met. Fuzzing findings were fixed (D-036) |

After the badge is granted, add it to the README next to the Scorecard badge (the site gives the Markdown), and the Scorecard's CII-Best-Practices check picks it up on its next run.
