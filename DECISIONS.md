# DECISIONS

A running log of the non-obvious choices, with the options considered and the evidence behind each one (SPEC §11).

## Index

- [D-001](#d-001-test-toolchain-versions-phase-0): Test toolchain versions (Phase 0)
- [D-002](#d-002-test-keys): Test keys
- [D-003](#d-003-schema-validator-under-workers-spec-8-open-question-3): Schema validator under Workers (SPEC §8, open question 3)
- [D-004](#d-004-runtime-compatibility-of-samlifys-dependencies-spec-8): Runtime compatibility of samlify's dependencies (SPEC §8)
- [D-005](#d-005-bundle-size-spec-8): Bundle size (SPEC §8)
  - [addendum](#d-005-addendum-real-plugin-size-phase-1): real plugin size (Phase 1)
- [D-006](#d-006-how-the-plugin-uses-the-schema-validator-phase-1): How the plugin uses the schema validator (Phase 1)
- [D-007](#d-007-vendored-xsds-phase-1): Vendored XSDs (Phase 1)
- [D-008](#d-008-node-xmllint-runs-in-emscripten-shell-mode-through-a-generated-wrapper-phase-1): node-xmllint runs in emscripten "shell" mode through a generated wrapper (Phase 1)
- [D-009](#d-009-default-validator-is-the-custom-libxml2-wasm-build-node-xmllint-is-removed-phase-1-2026-09-24): Default validator is the custom libxml2 WASM build; node-xmllint is removed (Phase 1, 2026-09-24)
- [D-010](#d-010-addendum-01-host-stack-and-amended-phase-0-gate-2026-09-24): ADDENDUM-01 host stack and amended Phase 0 gate (2026-09-24)
- [D-011](#d-011-pending-requests-and-replay-storage-addendum-01-r1-r2-resolves-spec-12-q2): Pending requests and replay storage (ADDENDUM-01 R1, R2; resolves SPEC §12 Q2)
- [D-012](#d-012-sp-initiated-sso-design-phase-2): SP-initiated SSO design (Phase 2)
- [D-013](#d-013-phase-3-gate-amended-independent-sps-in-place-of-a-live-hubspot-login-2026-09-25): Phase 3 gate amended: independent SPs in place of a live HubSpot login (2026-09-25)
- [D-014](#d-014-example-app-and-repo-plumbing-phase-3): Example app and repo plumbing (Phase 3)
- [D-015](#d-015-adversarial-review-15-findings-fixed-plus-real-browser-e2e-2026-09-25): Adversarial review: 15 findings fixed, plus real-browser e2e (2026-09-25)
- [D-016](#d-016-tier-3-evidence-a-real-cloudflare-access-login-2026-09-25): Tier-3 evidence: a real Cloudflare Access login (2026-09-25)
- [D-017](#d-017-measured-on-the-live-deployment-2026-09-25): Measured on the live deployment (2026-09-25)
- [D-018](#d-018-signed-authnrequests-and-forceauthn-verified-live-with-cloudflare-access-2026-09-25): Signed AuthnRequests and ForceAuthn, verified live with Cloudflare Access (2026-09-25)
- [D-019](#d-019-key-rotation-rehearsed-live-example-builds-better-auth-once-per-isolate-2026-09-25): Key rotation rehearsed live; example builds Better Auth once per isolate (2026-09-25)
- [D-020](#d-020-encrypted-assertions-2026-09-25): Encrypted assertions (2026-09-25)
- [D-021](#d-021-idp-initiated-sso-spec-5-stretch-roadmap-v11): IdP-initiated SSO (SPEC §5 stretch, roadmap v1.1)
- [D-022](#d-022-per-sp-signing-signed-metadata-sp-registration-from-metadata-2026-09-25): Per-SP signing, signed metadata, SP registration from metadata (2026-09-25)
- [D-023](#d-023-a-command-line-tool-not-a-debug-endpoint-2026-09-25): A command-line tool, not a debug endpoint (2026-09-25)
- [D-024](#d-024-declarative-attribute-mapping-2026-09-25): Declarative attribute mapping (2026-09-25)
- [D-025](#d-025-signed-authnrequests-over-http-post-2026-09-25): Signed AuthnRequests over HTTP-POST (2026-09-25)
- [D-026](#d-026-sp-metadata-url-with-refresh-2026-09-25): SP metadata URL with refresh (2026-09-25)
- [D-027](#d-027-database-backed-sp-registry-and-management-api-2026-09-25): Database-backed SP registry and management API (2026-09-25)
- [D-028](#d-028-saml-single-logout-2026-09-25): SAML Single Logout (2026-09-25)
- [D-029](#d-029-second-adversarial-review-part-1-fresh-eyes-2026-09-25): Second adversarial review, part 1 (fresh eyes, 2026-09-25)
- [D-030](#d-030-second-adversarial-review-part-2-external-different-model-2026-09-25): Second adversarial review, part 2 (external, different model, 2026-09-25)
- [D-031](#d-031-deeper-better-auth-integration-2026-09-25): Deeper Better Auth integration (2026-09-25)
- [D-032](#d-032-the-guide-and-background-work-on-workers-2026-09-26): The guide, and background work on Workers (2026-09-26)
- [D-033](#d-033-database-adapter-matrix-and-replay-protection-on-mongodb-2026-09-26): Database adapter matrix, and replay protection on MongoDB (2026-09-26)
- [D-034](#d-034-okta-as-a-live-sp-2026-09-26): Okta as a live SP (2026-09-26)
- [D-035](#d-035-auth0-as-a-live-sp-tolerate-protocolbindinghttp-redirect-2026-09-26): Auth0 as a live SP; tolerate ProtocolBinding=HTTP-Redirect (2026-09-26)
- [D-036](#d-036-fuzzing-characters-xml-cant-carry-in-issued-assertions-2026-09-26): Fuzzing; characters XML can't carry in issued assertions (2026-09-26)
- [D-037](#d-037-codeql-findings-a-quadratic-xml-pre-scan-and-xmldoms-nesting-cost-2026-09-26): CodeQL findings: a quadratic XML pre-scan, and xmldom's nesting cost (2026-09-26)
- [D-038](#d-038-observability-event-callbacks-and-an-audit-log-table-2026-09-26): Observability: event callbacks and an audit-log table (2026-09-26)
- [D-039](#d-039-third-review-review-4-two-independent-reports-2026-09-26): Third review ("review 4"), two independent reports (2026-09-26)
- [D-040](#d-040-api-decisions-before-10-2026-09-26): API decisions before 1.0 (2026-09-26)
- [D-041](#d-041-nameid-from-a-user-field-2026-09-27): NameID from a user field (2026-09-27)
- [D-042](#d-042-salesforce-verified-live-2026-09-27): Salesforce verified live (2026-09-27)
- [D-043](#d-043-sessions-that-end-without-single-logout-2026-09-27): Sessions that end without Single Logout (2026-09-27)
- [D-044](#d-044-authorize-can-give-a-reason-and-ask-for-re-authentication-2026-09-27): `authorize` can give a reason and ask for re-authentication (2026-09-27)
- [D-045](#d-045-identity-broker-verified-better-authsso-upstream-this-plugin-downstream-2026-09-27): Identity broker verified: `@better-auth/sso` upstream, this plugin downstream (2026-09-27)
- [D-046](#d-046-pre-release-review-2026-09-27): Pre-release review (2026-09-27)
- [D-047](#d-047-step-up-authentication-2026-09-27): Step-up authentication (2026-09-27)
- [D-048](#d-048-review-5-fixes-2026-09-28): Review 5 fixes (2026-09-28)
- [D-049](#d-049-ci-runners-pinned-to-ubuntu-2404-2026-09-28): CI runners pinned to ubuntu-24.04 (2026-09-28)
- [D-050](#d-050-openssf-scorecard-2026-09-28): OpenSSF Scorecard (2026-09-28)
- [D-051](#d-051-adapter-matrix-with-drizzle-and-prisma-bun-and-deno-2026-09-28): Adapter matrix with Drizzle and Prisma; Bun and Deno (2026-09-28)
- [D-052](#d-052-multi-tenant-idp-phase-1-an-idp-identity-per-organization-under-the-shared-key-2026-09-28): Multi-tenant IdP, phase 1: an IdP identity per organization under the shared key (2026-09-28)
- [D-053](#d-053-review-6-fixes-2026-09-28): Review 6 fixes (2026-09-28)
- [D-054](#d-054-aws-iam-identity-center-verified-live-2026-09-28): AWS IAM Identity Center verified live (2026-09-28)
- [D-055](#d-055-repository-clean-up-before-100-2026-09-28): Repository clean-up before 1.0.0 (2026-09-28)
- [D-056](#d-056-101-from-running-on-chardb-2026-09-29): 1.0.1, from running on CharDB (2026-09-29)
- [D-057](#d-057-102-the-client-plugin-under-typescript-5-2026-09-29): 1.0.2, the client plugin under TypeScript 5 (2026-09-29)
- [D-058](#d-058-multi-tenant-idp-phase-2-a-signing-key-per-tenant-2026-09-29): Multi-tenant IdP, phase 2: a signing key per tenant (2026-09-29)
- [D-059](#d-059-multi-tenant-idp-phase-3-delegated-administration-2026-09-29): Multi-tenant IdP, phase 3: delegated administration (2026-09-29)
- [D-060](#d-060-review-7-phases-2-and-3-before-release-2026-09-29): Review 7, phases 2 and 3 before release (2026-09-29)
- [D-061](#d-061-review-8-a-fresh-look-before-110-2026-09-29): Review 8, a fresh look before 1.1.0 (2026-09-29)
- [D-062](#d-062-relaystate-cap-4096-for-cloudflare-access-2026-10-02): RelayState cap 4096, for Cloudflare Access (2026-10-02)

---

## D-001: Test toolchain versions (Phase 0)

- **vitest 4.1.x.** `@cloudflare/vitest-pool-workers@0.22.0` has a peer dependency of `vitest ^4.1.0`. vitest 5 is out but the pool doesn't support it yet.
- **compatibility_date `2026-08-15`.** The workerd binary bundled with pool-workers 0.22.0 (miniflare `5.20260815.0-alpha`) rejects dates after `2026-08-22`: *"This Worker requires compatibility date "2026-09-01", but the newest date supported by this server binary is "2026-08-22"."* Bump the date when pool-workers is bumped.
- A single `vitest.config.ts` defines two projects, `node` and `workerd`, over the **same** test files. That satisfies SPEC §10 without a duplicated suite.

## D-002: Test keys

`test/support/global-setup.ts` generates throwaway RSA-2048 key pairs and self-signed SHA-256 certs with `openssl` at the start of every run and hands them to both projects through `provide`/`inject`. Nothing is written into the repo, and `.gitignore` excludes `*.pem` and `*.key`. CI needs `openssl` on the PATH, which GitHub's Ubuntu runners have.

## D-003: Schema validator under Workers (SPEC §8, open question 3)

samlify requires `setSchemaValidator`. Its only call sites are in the **inbound** parse flows (`flow.js`). For an IdP, that means the validator runs once per incoming AuthnRequest, on attacker-controlled input. It does not validate our own outgoing Responses. We verify those in tests instead.

### Options evaluated

| Option | Node | workerd | Size (gz) | Validate cost | Notes |
|---|---|---|---|---|---|
| `@authenio/samlify-xsd-schema-validator` | — | — | — | — | Needs Java. Excluded by the spec. Not tried. |
| `xmllint-wasm` 5.3.0 | — | ✗ (by design) | 0.38 MB wasm | — | Runs every validation in a Web Worker or `worker_threads`. Workers can't spawn either. Rejected on inspection. |
| `libxml2-wasm` 0.7.2 (libxml2 2.14+, maintained) | ✓ | ✗ | ~0.38 MB wasm | **1.07 ms** avg (Node, 20 runs) | See the blocker below. |
| **`@authenio/samlify-node-xmllint` 2.0.0** (`node-xmllint` 1.0.0, asm.js) | ✓ | ✓ | **+1.03 MB** over samlify | ~40–80 ms Node; **~180 ms warm / ~1.3 s first call on workerd** (Phase 1 re-measurement below) | Chosen for v1. See the risks below. |

**The libxml2-wasm blocker, reproduced in `test/spike/libxml2.test.ts`:**
1. Stock package: `WebAssembly.instantiate(bytes)` → `CompileError: Wasm code generation disallowed by embedder`. Workers only allow precompiled modules imported at bundle time.
2. I extracted the `.wasm` file and passed it as a precompiled module through emscripten's `instantiateWasm` hook (`spike/extract-wasm.mjs`, an isolated patched copy that isn't shipped). Instantiation then succeeds, but `addFunction()` builds a small Wasm module at runtime for every JS callback (input providers, error handlers), and that hits the same `CompileError` at import time.
3. Fixing it means a **custom emscripten build**: callbacks declared at link time, or no JS callbacks at all, exposing a single `validate(xml)` against schemas compiled in. That's a real project in its own right, not a patch, so it's out of scope for the Phase 0 timebox.

### Choice for v1: `node-xmllint` (the engine inside `@authenio/samlify-node-xmllint`), behind a pluggable option

In Phase 1 the plugin stopped using authenio's wrapper and the `node-xmllint` package entry point. It runs the same `xmllint.js` through a generated shell-mode wrapper instead. The reasons are in D-006 and D-008.

Evidence (`test/spike/roundtrip.test.ts`, green on both `node` and `workerd`):
- It accepts the valid signed Response samlify produces: `SUCCESS_VALIDATE_XML`.
- It rejects a well-formed but schema-invalid document with a real libxml2 error: `Element '{urn:oasis:names:tc:SAML:2.0:protocol}Bogus': This element is not expected. Expected is one of ( …Issuer, …Signature, …Extensions, …Status )`.

**Known costs and risks, which have to go in `docs/security.md` and the README:**
- **The libxml2 is very old.** node-xmllint is kripken/xml.js-era libxml2 from roughly 2014 and hasn't been maintained since. It parses attacker-controlled AuthnRequests. The asm.js sandbox contains memory corruption to its own heap, so a bug can't escape into the Worker. It *can* produce a wrong validation result or a crash, which limits the schema check to defence in depth. samlify's own signature and reference checks remain the primary XSW defence.
- **It's slow by construction.** The whole emscripten runtime is inlined inside `validateXML()`, so every call re-links the asm.js module and allocates a fresh heap. The first call in a fresh isolate is noticeably slower. The first round trip in a fresh process, including the first validation, measured 2.3–2.7 s on Node and 0.65–1.1 s on workerd.
- **Workers plan.** A single SSO request (validate plus RSA-SHA256 sign) exceeds the Workers Free plan's 10 ms CPU limit. **The plugin needs Workers Paid** or another host. Document this.
- The console output on failure dumps libxml2's error text, which includes element names but not the full payload. The SPEC §7 logging rules still require routing this through our logger rather than the package's `console.error`, so v1 wraps the validator.

**Mitigation built into the design:** the plugin exposes a `schemaValidator` option (default: the node-xmllint wrapper). Deployments on Node can switch to `libxml2-wasm`, which is ~30× faster and maintained. A later custom WASM build can then replace the default without an API change.

**Follow-up (approved 2026-09-24, running in parallel in `wasm-validator/`):** build a minimal libxml2 WASM validator for workerd. Target: no runtime codegen, no JS callbacks into libxml2, current libxml2, ~0.4 MB gzipped, ~1 ms per validation.

### Correction to the Phase 0 timings (Phase 1)

The Phase 0 workerd figure of 64–100 ms was measured with `performance.now()` inside workerd. It understated the cost because the runtime clamps timers. A re-measurement of a `wrangler dev` Worker, timed by curl from outside (`spike/validator-bench.ts`), gives these per-request wall times:

| Validator | 1st call in isolate | Warm calls |
|---|---|---|
| Our wrapper, upstream schemas *with* DOCTYPE | 3.49 s | 0.49–0.93 s |
| Our wrapper, upstream schemas, DOCTYPE stripped (D-007) | 1.32 s | 0.18–0.19 s (after 2 warm-up calls) |
| authenio wrapper (its modified schemas) | — (asm.js already compiled) | 0.15–0.28 s |

Inside vitest-pool-workers the first call takes about 18 s, because vite transforms the 4 MB file on first import. That's a test-harness artefact, so the validator tests use a 60 s timeout.

With the shell-mode wrapper from D-008 (re-measured the same way): **1.25 s on the first call in an isolate, then 60–95 ms warm**.

So on Workers, each inbound AuthnRequest costs **roughly 0.1 s of CPU warm and over 1 s cold**. That's acceptable for an IdP's volume, since SSO logins are rare per user, but it's the main reason the custom WASM build was pulled forward.

> Timing caveat: workerd clamps `performance.now()` precision in tests, so its numbers are indicative only. Real CPU time will be measured on a deployed Worker in Phase 3.

## D-004: Runtime compatibility of samlify's dependencies (SPEC §8)

All of the following were exercised under workerd with `nodejs_compat` (compat date 2026-08-15) in `test/spike/roundtrip.test.ts`. Nothing needed patching or shimming:
- `@xmldom/xmldom`: parsing AuthnRequests and Responses.
- `xml-crypto` 6.x: **RSA-SHA256 signing, SHA-256 digests**. The assertions check both algorithm URIs in the signed XML. The WebCrypto fallback isn't needed.
- `node-rsa`, `@authenio/xml-encryption`, `node-forge`: loaded without errors. Encryption paths aren't exercised because encrypted assertions are a v1 non-goal.
- Redirect-binding inflate/deflate: `sp.createLoginRequest(…, "redirect")` → `idp.parseLoginRequest(…, "redirect")` round-trips.
- Signature verification is real. A NameID tampered after signing is rejected with `FAILED_TO_VERIFY_SIGNATURE` on both runtimes.

## D-005: Bundle size (SPEC §8)

`wrangler deploy --dry-run` of the minimal Workers in `spike/` (wrangler 4.139):

| Worker | Raw | gzip |
|---|---|---|
| baseline (`new Response("ok")`) | 0.31 KiB | 0.23 KiB |
| + samlify (no-op validator, **size measurement only**) | 1062 KiB | **182.8 KiB** |
| + samlify + node-xmllint validator | 10,725 KiB | **1,210.9 KiB** |

So the validator is about 85% of what the plugin adds. That's under the Workers limits (3 MB gzipped Free, 10 MB Paid), but it's the main reason for the follow-up in D-003. Plugin code and Better Auth itself come on top of this and will be measured in Phase 1 and 2.

## D-006: How the plugin uses the schema validator (Phase 1)

Findings:
- `@better-auth/sso` calls `samlify.setSchemaValidator` **at module import**. Its validator only checks that the XML is well-formed (`fast-xml-parser`); it doesn't check the XSD. samlify's validator is a single process-global value, so if both plugins are installed, the last one to set it wins.
- samlify rejects every parse when no validator is set.
- `node-xmllint` returns its output with the last two lines removed, which is meant to drop the trailing `file_0.xml validates` or `fails to validate` line. If the document can't be parsed at all, that line never appears, so a lone parse error could be removed and the document read as valid.

Decisions:
1. The plugin **explicitly** runs its own `SchemaValidator` on every inbound SAML message before samlify sees it. Security doesn't depend on samlify's global hook.
2. The plugin sets samlify's global validator only when none is set yet, so samlify can run, and never overrides one set by `@better-auth/sso`, so the SSO plugin's behaviour is unchanged.
3. Well-formedness is decided by a strict `@xmldom/xmldom` 0.9 parse, where any warning or error rejects. `node-xmllint` only decides schema validity. `test/unit/validator.test.ts` pins the single-schema-error case and five kinds of malformed input.
4. Checks before any parser runs: a byte-size cap (default 128 KiB) and outright rejection of `<!DOCTYPE` and `<!ENTITY`. SAML never needs a DTD.
5. The validator's error text is returned to the plugin, which logs it at debug level. Nothing is printed by the engine.
   - Evidence: `test/integration/coexistence.test.ts` on Node. For Workers, a real wrangler bundle (`spike/coexist.ts` under `wrangler dev`) returned `{"ssoValidatorVisible":"function","unchangedAfterPlugin":true}`. The same test is skipped under vitest-pool-workers, because that runner loads `samlify` and `samlify/build/src/api` as two separate module instances. That's a harness artefact which wrangler bundles don't have.
   - The check reads samlify's internal `build/src/api` module, because samlify exports no getter. samlify has no `exports` map, so the path resolves everywhere, but a samlify upgrade must re-run this check.
   - Gotcha found on the way: `@better-auth/sso` is `"sideEffects": false`, so a bare `import "@better-auth/sso"` is tree-shaken and never installs its validator. Real apps call `sso()`, which keeps it.
6. `SchemaValidator` is `validate(xml, kind: "protocol" | "metadata") → {valid} | {valid:false, errors}`. It's a public option (`schemaValidator`).

## D-007: Vendored XSDs (Phase 1)

`schemas/` holds the **unmodified upstream files** (OASIS SAML 2.0 protocol, assertion and metadata; W3C xmldsig, xenc and xml.xsd). `scripts/build-schemas.mjs` generates `src/saml/schemas.generated.ts` and records the SHA-256 and source URL of each file in its header.

I checked authenio's bundled copies against upstream and rejected them. Besides localised `schemaLocation`s, they loosen `ds:X509SerialNumber` from `integer` to `string` and ship an older xenc revision.

The build script applies exactly two transforms, and asserts that each is safe:
1. Absolute `schemaLocation` URLs → local file names.
2. The DOCTYPE is removed from xmldsig and xenc. It points at the external `XMLSchema.dtd` and declares entities the schemas never use (the build fails if one is used). Its `#FIXED xmlns:*` attributes are already on `<schema>` (the build fails if not). Removing it cut the warm validation time from ~0.5 s to ~0.18 s (D-003).

## D-008: node-xmllint runs in emscripten "shell" mode through a generated wrapper (Phase 1)

**Found by a failing test.** On workerd, every `xmllintValidator()` instance after the first returned `validateXML is not a function`. The cause is in the emscripten code inside `validateXML()`. When it detects Node (`typeof process==="object" && typeof require==="function"`, which is true under `nodejs_compat` and in esbuild's CJS shim), **every call**:
- runs `module["exports"]=Module`, replacing the package's exports with emscripten's internal object. The workerd module runner re-reads CJS exports, so later imports broke.
- runs `process.on("uncaughtException", …)`. Measured on Node: 5 validations left 5 listeners. A long-running Node server would leak one listener per SSO request.
- wires in the real `fs`, `require("ws")` sockets and `process.exit`, and prints a blank line to stdout.

**Fix:** `scripts/build-xmllint.mjs` generates `src/vendor/xmllint.generated.mjs`. It contains the unmodified `xmllint.js` (sha256 recorded in the header, version asserted), wrapped in a function whose parameters shadow `module`, `exports`, `require`, `process`, `window` and `importScripts` as `undefined`, with no-op `print`/`printErr`. Emscripten then runs in shell mode: in-memory filesystem only, and no access to Node APIs.

Evidence:
- Node: 0 listeners after repeated calls, `validateXML` intact, correct valid and invalid results.
- `test/unit/validator.test.ts` "keeps working across validator instances" and "does not add process-wide listeners or write to stdout per call" pass on both runtimes.
- Shell mode is also faster on workerd: 60–95 ms warm versus ~180 ms.

`node-xmllint` is now a devDependency, only needed to regenerate the file. The published package ships the generated module. It's loaded with a dynamic `import()` on first validation, so its 4 MB isn't evaluated at Worker startup, where the global-scope CPU limit applies.

## D-005 addendum: real plugin size (Phase 1)

`wrangler deploy --dry-run` for a minimal Better Auth Worker (memory adapter):

| Worker | Raw | gzip |
|---|---|---|
| better-auth only | 1,905 KiB | 333 KiB |
| better-auth + `samlIdp()` | 13,351 KiB | 1,611 KiB |

**The plugin adds about 1,278 KiB gzipped**, mostly the asm.js validator. The pending WASM validator should cut most of that.

## D-009: Default validator is the custom libxml2 WASM build; node-xmllint is removed (Phase 1, 2026-09-24)

**Supersedes** the v1 choice in D-003. D-008 now only matters historically: the xmllint wrapper and its generator were deleted.

The WASM validator was built in parallel in `wasm-validator/` (README there covers build, pins and results):
- libxml2 **2.15.4** (tarball sha256 pinned).
- Compiled with `emscripten/emsdk:6.0.10` (image digest pinned) as a **standalone wasm with no emscripten JS glue**. The hand-written loader implements exactly 7 imports, and a test pins that list.
- No callbacks into JS. Schemas load only from an in-memory registry; libxml2's file callbacks are removed.
- DOCTYPE is rejected in C. Errors go to a buffer, not stdio.
- The build is reproducible: two builds gave the same wasm sha256, `d116cf5d…7750` (rebuilt in D-015 with the namespace check: `cfef04b6…0103`).

I re-ran its suite independently: `pnpm test:wasm` → 67 passed, 1 skipped (a workerd-only case) across Node and workerd. That includes 800 validations with 0 bytes of heap growth, and a workerd check that runtime codegen really is forbidden in that isolate.

| | node-xmllint (D-008) | xsd.wasm |
|---|---|---|
| libxml2 | ~2014 | 2.15.4 |
| workerd cold (1st call per isolate) | 0.7–1.9 s | 41–55 ms |
| workerd warm | 60–95 ms | **~0.1 ms** |
| Node warm | 22–26 ms | ~0.05 ms |
| gzip added to a Better Auth Worker | 1,278 KiB | **356 KiB** (332 → 688 KiB, better-auth 1.7.5) |

(The workerd numbers come from `wrangler dev` timed with curl. The agent's run measured both validators the same way, in the same session.)

Integration:
- `wasm/xsd.wasm` ships in the package.
- The package `imports` entry `#xsd-wasm` resolves to `load.workerd.ts` under the `workerd` condition (a static `.wasm` import, which wrangler turns into a precompiled `WebAssembly.Module`) and to `load.node.ts` otherwise (reads the file).
- The wrangler bundle was confirmed to emit `xsd.wasm` as a separate module.
- The public factory is `libxml2Validator({ maxBytes?, wasm? })`. It still runs `precheckXml` (128 KiB cap, DOCTYPE/ENTITY) before the wasm, which covers the missing size limit the agent flagged.

Open items carried over from the agent's report:
1. The cold start (~40–55 ms of CPU per isolate, mostly libxml2 compiling the protocol XSD) is above the Workers Free 10 ms limit for the first request only.
2. A trap is untested because no input that triggers one was found. The loader fails closed and re-instantiates.
3. libxml2 2.15.4 doesn't pass a schema parser's resource loader on to nested imports (xmlschemas.c, around line 9925). The shim works around it with global registry-only callbacks. This should be reported upstream.

## D-010: ADDENDUM-01 host stack and amended Phase 0 gate (2026-09-24)

**Source check.** Every claim in the addendum that the plugin depends on was confirmed:
- In better-auth **1.7.5/1.7.6** source: `internalAdapter.consumeVerificationValue` exists. It's the path magic-link, 2FA, OTP and password reset use. It treats expired rows as consumed.
  - With `storeInDatabase` it runs under a per-instance in-process lock, and the Drizzle adapter's `consumeOne` is a single `DELETE … WHERE id IN (SELECT …) RETURNING`. Without it, it uses `secondaryStorage.getAndDelete`.
  - `advanced.database.validateSchema` defaults to `true`. For Drizzle it checks the local schema metadata.
- In `better-auth-cloudflare`:
  - #69 (the storage-routing check) was merged to main on 2026-09-06. **No release contains it:** npm `latest` is still 0.3.1, the broken version.
  - #72 and #61 are open.

**Version pins.**
- better-auth is pinned to **1.7.5** (the minimum) for development. The same suite passes on **1.7.6** (latest 1.7.x): 279 passed / 5 skipped on both.
- `better-auth-cloudflare` is **main @ `dbe08c51b`**. Main has no `dist/` in git and its `prepare` script only runs husky, so a git dependency can't build. It was cloned, built with its own `unbuild` and packed to `vendor/better-auth-cloudflare-0.3.1-main-dbe08c51b.tgz` (sha256 `410ca53a…6d76`). It's a **devDependency only**, for tests and the example. Replace it with `^0.4.0` when that's published.
- drizzle-orm is 0.45.3.
- `@better-auth/oauth-provider` was removed and `@better-auth/sso` is pinned to the same version, so exactly one better-auth copy is installed.

**Test host (R5)**, `test/support/host.ts`:
- `withCloudflare`, with `samlIdp()` and `admin()` **inside** its second argument.
- `verification.storeInDatabase`, `rateLimit: { enabled: true, storage: "database" }` and `validateSchema: true`.
- workerd uses Drizzle on **D1**, with migrations in `test/support/d1/migrations`.
- Node uses **node:sqlite**, a real database that enforces keys, with tables created by Better Auth's own migrator.
- Rate limiting stays on. Each simulated browser uses its own `cf-connecting-ip`, so tests don't share a sign-up budget. With a shared IP, D1-backed rate limiting returned 429 after 3 sign-ups, which shows it was really active.

**Evidence** (`test/integration/host-stack.test.ts`, both runtimes):
- The versions are reported, and `validateSchema` passes with the plugin's table. It's **not vacuous**: removing `samlIdpSeenRequests` from the Drizzle schema makes `checkSchema()` reject and name `samlIdpSeenRequest`.
- Sign-up writes `rateLimit` rows to the database, and metadata validates against the XSD.
- **Negative host config:** KV secondary storage without `storeInDatabase` throws `Better Auth 1.7.x storage is not atomic: verification requires a database or secondaryStorage.getAndDelete`.

## D-011: Pending requests and replay storage (ADDENDUM-01 R1, R2; resolves SPEC §12 Q2)

- **Pending AuthnRequests (R1)** are Better Auth verification values with identifier `saml-idp:pending:<rid>`, where `rid` is 256 random bits in base64url. They're written with `createVerificationValue` and read **only** via `consumeVerificationValue`. The plugin never finds-then-deletes, and never touches KV or secondary storage directly.
  - `rid` is also bound to the starting browser. The pending record holds the SHA-256 of a random value kept in a signed `saml_idp_binding` cookie, which is checked after the consume.
  - Consequence: a leaked resume link can't be completed in another browser (tested).
  - It's checked after the consume on purpose, so the value is single-use whatever the outcome. The cost is that someone holding a leaked link can burn it, which is a denial of service only.
- **Seen request IDs (R2)** go in the plugin-owned `samlIdpSeenRequest(spId, requestId, expiresAt)` table.
  - Better Auth's plugin schema format can't declare a composite UNIQUE. So `id` is `SHA-256("saml-idp:seen\0"+spId+"\0"+requestId)`, inserted with `forceAllowId`, which makes the primary key the constraint on the pair.
  - The documented host schema (README and the D1 test schema) **also** has `UNIQUE(sp_id, request_id)`.
  - The replay check inserts first. On failure, one re-read of the row classifies the error, the same technique as Better Auth's `reserveVerificationValue`.
  - Row lifetime is `REQUEST_MAX_AGE (300 s) + 2×skew`, which covers the whole window in which `IssueInstant` is accepted. Expired rows are deleted opportunistically on each SSO request.
- **Alternative considered:** Better Auth 1.7's `reserveVerificationValue` is a first-writer-wins primitive whose own doc comment names "a SAML assertion id". It would avoid a plugin table. It wasn't used because R2 explicitly requires a plugin-owned table with a unique constraint.

**Evidence.** Each item below holds on both runtimes, plus the check that the tests can fail:

| Check | Result |
|---|---|
| R1: 10 parallel resumes of one `rid`, one auth instance | 1 issued, 9 × 400 |
| R1: 10 parallel resumes spread over **5 independent auth instances on one D1** | 1 issued |
| R1: resume the same `rid` again, then an expired `rid` | 400, 400; nothing issued |
| R2: duplicate ID, sequentially / concurrently / across 2 instances | 400 / `[200,400]` / `[302,400]` |
| **Mutation:** R1 consume swapped for find-then-delete | tests **fail**: 9–10 of 10 issued |
| **Mutation:** R2 swapped for naive read-then-write | tests **fail**: `[200,200]` on Node; D1's composite UNIQUE turned it into `[200,500]` |

The cross-instance R1 test matters. `consumeVerificationValue`'s in-process lock serialises consumes within one instance, so a single-instance race never reaches the database.

## D-012: SP-initiated SSO design (Phase 2)

- **Response construction.** An explicit, fully escaped XML template carries every field from SPEC §6 step 7. It's signed with `xml-crypto` 6: the assertion first, then the response, with enveloped + exclusive c14n, the signature placed after `Issuer`, and `KeyInfo` carrying the cert. samlify's template engine wasn't used, so that each field is visible and auditable in one file (`src/saml/response.ts`). A strict samlify SP, with message and assertion signatures required, is the independent verifier in tests.
- **Inbound AuthnRequest pipeline** (`src/saml/request.ts`):
  1. Size-bounded base64 decode, then DEFLATE inflate stopping at 64 KiB (a DEFLATE bomb is tested). Strict UTF-8.
  2. `precheckXml`, then the XSD check (libxml2 WASM), then a strict xmldom parse.
  3. Structural checks: the root is `samlp:AuthnRequest` with Version 2.0, it has exactly one direct `Issuer`, `IssueInstant` is within 300 s plus skew and not in the future, `Destination` (if present) equals our SSO URL, `ProtocolBinding` (if present) is HTTP-POST, and `NameIDPolicy@Format` is absent, unspecified or the SP's format.
  4. Then the SP lookup, the signature policy, the ACS allow-list and the R2 insert.
- **Signed AuthnRequests.** HTTP-Redirect only, verified over the raw query octets (`SAMLRequest`, `RelayState`, `SigAlg`, as received) using `node:crypto` and the SP certificate. This has no XML-signature surface and so no XSW exposure. **POST-binding signed requests weren't supported in v1:** an SP that required signing and posted was rejected with `UNSIGNED_SAML_REQUEST` (SPEC §9 stretch list). They're supported since D-025. SHA-1 `SigAlg` is refused unless `allowInsecureSha1` is set.
- **Issuance** (`src/endpoints/issue.ts`), right before signing:
  1. **R3:** `findUserById` (a database read) → missing or banned (admin `banned`, respecting `banExpires`) → `ACCOUNT_INACTIVE`. Where the database holds sessions (no secondary storage, or `storeSessionInDatabase`), the session row is re-read by token → missing or expired → `ACCOUNT_INACTIVE`. This covers #61: a KV-cached session is refused once its database row is gone (tested with an atomic in-memory cache standing in for KV).
  2. `authorize()` runs on the fresh user. A denial or an exception gives `ACCESS_DENIED` (403).
  3. `SessionIndex` is a hash of the session id, never the token. `AuthnContextClassRef` is `unspecified`, because the plugin can't know how the user authenticated.
- **ForceAuthn:** the session must have been created after the AuthnRequest, otherwise `REAUTHENTICATION_REQUIRED`. The host's login page must let an already-signed-in user sign in again. **IsPassive** without a session gives an error page. v1 doesn't send a `NoPassive` status Response.
- **`AssertionConsumerServiceIndex` without a URL is rejected**, because indexes refer to SP metadata that the static registry doesn't hold.
- **Origin check:** `/saml2/idp/sso` is added to `skipOriginCheck` in `init`, the same way `@better-auth/sso` handles its ACS, because SPs POST there cross-origin.
- **Logging:** errors log a code and a short detail at debug level, and never payloads. The logging test runs a full flow at debug level and asserts that no private-key fragment, SAMLResponse, SAMLRequest or rejected issuer appears in the logs.

## D-013: Phase 3 gate amended: independent SPs in place of a live HubSpot login (2026-09-25)

**Deviation from SPEC §9 Phase 3**, approved by the owner. There's no HubSpot portal with SSO available: HubSpot SSO generally needs a paid tier, and we have no entity ID or ACS URL. The gate's purpose is proof that *independent, strict* SP implementations accept our assertions, plus an external validator result. That's now covered in four tiers (`docs/testing-with-sps.md`). `docs/hubspot.md` stays as a guide marked "not yet verified live".

| Tier | SP / validator | Evidence (2026-09-25) |
|---|---|---|
| 1 (CI) | `@better-auth/sso` 1.7.5 (Better Auth's own SP) | `test/interop/sp-interop.test.ts`, Node + workerd: SP-initiated flow ends with a Better Auth session on the SP for the same email |
| 1 (CI) | `@node-saml/node-saml` 5.1.0, strict (`validateInResponseTo: always`, both signatures required) | same file: profile NameID, issuer and email verified; **rejects** the Response under the wrong IdP cert |
| 2 (CI job + local) | Keycloak 26.4, SAML identity broker with `validateSignature` and `wantAssertionsSigned` | `pnpm e2e`: PASS. A new user was created in Keycloak and linked to `our-idp`; first/last name mapped from our attributes |
| 2 | SimpleSAMLphp 2.5.0 SP | `pnpm e2e`: PASS (new user: NameID + `email, name, firstName, lastName`), PASS (existing IdP session → no login page) |
| 3 | **Cloudflare Access** (Zero Trust Free, team `aged-bird-8df2`) | **PASS 2026-09-25** (see D-016). |
| 3 | AWS IAM Identity Center | **PASS 2026-09-28** (see D-054). Guide: `docs/sp-aws-iam-identity-center.md` |
| 4 | SAMLtool (samltool.com/validate_response.php) | A throwaway local user and dev key, with the Response from `examples/workers-hono` on workerd → **"The SAML Response is valid."** The same Response with a wrong certificate → **"invalid. Response signature validation failed. Assertion signature validation failed."**, so the check is real |

The tier-2 e2e drives the **example app on workerd** (`wrangler dev`, local D1), with a scripted browser that follows redirects and auto-submits SAML forms. Everything else about it is in `e2e/run.mjs`. Problems found and fixed while building it:
- SimpleSAMLphp's image only aliases `/simplesaml` on its :443 vhost, so a `conf-enabled` alias was added for http.
- Compose v1 (`docker-compose` 1.29) needs a `version:` key.
- The script now refuses to start when a port is busy, after stale `wrangler dev` processes caused a false start.

## D-014: Example app and repo plumbing (Phase 3)

- **`examples/workers-hono`:** Hono + D1 + Drizzle + `withCloudflare`, with `samlIdp()` inside it (R6), `storeInDatabase`, database rate limits and `validateSchema`.
  - SPs come from the `SAML_SERVICE_PROVIDERS` JSON var, so no code change is needed per SP.
  - The sign-in page only follows same-origin `callbackURL`s and uses a nonce CSP.
  - It depends on `better-auth-cloudflare` from `vendor/` until 0.4 is on npm.
- **Performance fix from building it:** hosts on Workers typically build `betterAuth()` per request, to pass `cf`. A per-request `samlIdp()` would re-instantiate the wasm and recompile the XSDs (~40–55 ms) each time. Two layers prevent that:
  1. The default validator is now an isolate-wide singleton (`defaultSchemaValidator()`).
  2. The example also caches the plugin per isolate.
- **pnpm workspace:** the root package `exports` temporarily point at `src/*.ts` until the Phase 4 build adds `dist/`. `src/index.ts` references its ambient `.d.ts` files, so consumers type-check.
- **`pnpm.overrides["@better-auth/utils"] = "0.4.2"`:** after adding the workspace, pnpm resolved 0.5.0 for part of the tree, while Better Auth 1.7.x pins 0.4.2 (an unmet-peer warning). The override affects only this repo's installs, not the published package.

## D-015: Adversarial review: 15 findings fixed, plus real-browser e2e (2026-09-25)

A max-effort review of the whole codebase found 15 verified defects. The key lesson: **the test harness wasn't a real browser**. It sent every cookie everywhere and enforced no CSP, which hid findings 5 and 6.

**Browser e2e.** It's now Playwright + Chromium over HTTPS, replacing the scripted `e2e/run.mjs`:
- Every party is its own site: `idp.test`, `kc.test`, `ssp.test`, `sp.test`, `app.test`, all mapped via `--host-resolver-rules`, with a throwaway CA from `e2e/lib/tls.mjs`. So SameSite, `Secure` cookies and CSP behave as in production.
- A new `node-saml` test SP uses the **HTTP-POST binding** and **redirects cross-site after its ACS**, like Cloudflare Access, AWS and HubSpot.
- The example app got real email verification: a dev-only `/dev/mailbox`, behind `DEV_MAILBOX`.
- **Failing first:** before the fixes, Chromium logged `Sending form data to 'https://sp.test:9100/acs' violates … "form-action https://sp.test:9100/acs"` and the flow hung (finding 5). After the fixes, 7/7 pass, including POST-binding while signed in, which skips the login page (finding 6), and IsPassive both ways.
- Building it also exposed a real interop issue: **node-saml DEFLATEs HTTP-POST AuthnRequests**, contrary to Bindings §3.5.4. We now accept raw DEFLATE on POST when the payload isn't XML, under the same size cap.

**Fixes.** Each has a test, and each test was proven by mutation (re-breaking the fix makes it fail) in `test/integration/review-findings.test.ts` and `security.test.ts`:

| # | Finding | Fix |
|---|---|---|
| 1 | Assertions signed for **unverified** emails, admin impersonation and anonymous users, which enabled account takeover at the SP | `accountPolicy`: `requireEmailVerified` (default **true**), `allowImpersonatedSessions` (false), `allowAnonymousUsers` (false). It's checked on the fresh DB user and session row. |
| 2 | Percent-encoded `Relay%53tate` smuggled an unsigned RelayState past Redirect signatures | `parseRedirectQuery` decodes names before matching, rejects duplicates, and builds the octets from exactly the parameters used, plus a guard that refuses signed requests with encoded SAML parameter names. **Either layer alone defeats the attack.** The mutation test removes both. |
| 3 | Replay relied on a forced hashed primary key. `generateId: "serial"/"uuid"` dropped it (replays accepted), and MySQL's varchar(36) id made every request 500 | A separate **UNIQUE `key` column**, with the id left to Better Auth. Tested with `serial` and `uuid`. Hosts need migration `0002_seen_request_key.sql`. |
| 4 | `banned === true` missed adapters that return `1` | Truthiness check, as in Better Auth's admin plugin |
| 5 | The `form-action` CSP blocked SPs that redirect after the ACS | No `form-action` on the auto-POST page (the error page keeps `'none'`). The page has no injection point, and its action is an allow-listed ACS. |
| 6 | The SP's cross-site POST carries no SameSite=Lax cookies: signed-in users were sent to log in, IsPassive failed, and the binding cookie was clobbered | The POST binding validates, records the replay, then **303s to a single-use same-site GET** (`sso?cid=`, 120 s) where cookies are present. The binding cookie is only read or created on that GET. |
| 7 | An unbounded IdP cache keyed by the Host-derived base URL, and host-steerable metadata served `public` | A `baseURL` option pins the IdP's URLs (init warns if nothing is pinned). Otherwise the cache is a 32-entry LRU. Metadata is `private` with `Vary: Host, X-Forwarded-Host, X-Forwarded-Proto`. |
| 8 | An expired certificate, even a rotation one, was fatal, taking every Better Auth route down | Expiry is a warning, and so is expiry within 30 days |
| 9 | Pending AuthnRequests were never swept: Better Auth only deletes expired verification rows in `findVerificationValue` | A throttled sweep (60 s) of expired verification rows and seen-request rows on SSO requests |
| 10 | `mergeSchema` mutated a shared module-level schema | A fresh schema object per plugin instance |
| 11 | NameID was always the email, even for persistent/transient formats | persistent → per-SP HMAC of the user id (keyed with the Better Auth secret: rotating the secret changes these IDs); transient → random per assertion |
| 12 | A requested `Subject` and `RequestedAuthnContext` were ignored | Subject mismatch → `UnknownPrincipal`. RequestedAuthnContext is matched against the new `authnContextClassRef` option (default `unspecified`; no class ordering is known, so `better` never matches) → `NoAuthnContext`. **All protocol-level refusals now go back as signed SAML error Responses** (also NoPassive and InvalidNameIDPolicy). |
| 13 | The browser-binding test passed without the binding check | The attacker in the test now holds their own valid binding cookie |
| 14 | No test depended on the R3 user re-read or the expired-session branch | Tests where each check alone decides the outcome |
| 15 | The WASM tests exercised a copy of the loader and binary | One loader and one binary; the build writes `wasm/xsd.wasm`. xsdv.c now rejects namespace-ill-formed documents, and a failed compile is no longer cached. |

Smaller verified items, also fixed:
- `ForceAuthn`, `IsPassive` and `ID` are whitespace-collapsed.
- `IssueInstant` must carry a time zone.
- No `xsi:type` (its `xs` prefix sat outside exclusive c14n).
- `loginPage` rejects backslashes and control characters.
- An empty SP list is allowed with a warning.
- Attacker-supplied text in debug logs is bounded and sanitised.
- The private key is parsed once.
- The e2e cleans up on Ctrl-C.
- The unused samlify global is gone.

**Behavioural changes for hosts:**
- Unverified users no longer receive assertions (opt out with `accountPolicy.requireEmailVerified: false`).
- SPs asking for `RequestedAuthnContext` classes the IdP doesn't assert now get `NoAuthnContext`. `node-saml` asks for `PasswordProtectedTransport` by default, so set `authnContextClassRef` to what your sign-in guarantees.
- The seen-request table has a new `key` column.

## D-016: Tier-3 evidence: a real Cloudflare Access login (2026-09-25)

**Setup:**
- `examples/workers-hono` deployed to the owner's Cloudflare account as `better-auth-saml-idp-example.mmcintosh-f61.workers.dev`, with its own D1 database `saml-idp-example` and migrations 0001–0002.
- Production signing key (RSA-2048, valid until 2028) generated and piped straight into `wrangler secret put`. It was never printed or stored.
- The deploy config with account-specific IDs is the gitignored `wrangler.deploy.jsonc`.
- The SP entry was taken from Cloudflare's published SP metadata (`/cdn-cgi/access/saml-metadata`). Its entity ID and ACS URL are both `https://aged-bird-8df2.cloudflareaccess.com/cdn-cgi/access/callback`. The metadata says `AuthnRequestsSigned="true"`, but with "Sign SAML authentication requests" off, Cloudflare sends unsigned requests.
- The owner's IdP account was verified by hand in D1, because the example sends no email in production.

**Result:** Zero Trust's identity-provider **Test** returned
the owner's email, name, `givenName` and `surName`, with `saml_attributes.email` (values omitted here).
The IdP logs show the matching sequence: SSO → sign-in → resume, with the assertion auto-posted to Cloudflare.

**Real-world finding: Cloudflare Access sends a RelayState longer than 80 bytes.** The first attempt failed with `RELAY_STATE_TOO_LONG`. The plugin's default follows SAML Bindings §3.4.3 ("MUST NOT exceed 80 bytes"), and none of the IdPs in the comparison research is documented as enforcing that limit. The example now sets `relayStateMaxBytes: 1024`, the plugin's hard cap, and that made the login work. **Decided (owner, 2026-09-25):** the plugin default is now **1024**, with `relayStateMaxBytes: 80` as the strict-spec opt-in. The example no longer needs to set it.

**Not a plugin issue:** the first password attempts failed with "Invalid password". The password typed didn't match the one set at sign-up. The account was deleted and re-created.

## D-017: Measured on the live deployment (2026-09-25)

These results come from the example deployed to Cloudflare (see D-016), with no local simulation.

**CPU time per request**, from `wrangler tail --format json` (`cpuTime`) after a fresh deploy:

| Request | Warm median / p90 | Notes |
|---|---|---|
| `/sign-in` (static page, no auth code) | 0 / 1 ms | baseline |
| IdP metadata | 8 / 16 ms | includes building `betterAuth()` per request, as the example does |
| SSO AuthnRequest | **16 / 24 ms** | adds XSD validation (WASM), replay insert and sweep on D1 |
| First request on a fresh isolate | **56–162 ms** | bundle evaluation, WASM compile and first-time init |

Conclusions:
- **Workers Paid is required.** The Free plan's 10 ms CPU limit is exceeded even by warm SSO requests, not only by cold starts. README and docs should state this plainly, not as an estimate.
- About half the warm cost is the example rebuilding `betterAuth()` per request, which is the upstream `withCloudflare` pattern for per-request `cf` geolocation. **Optimisation opportunity:** cache the auth instance per isolate when geolocation isn't needed, or build it once and pass `cf` per request. This is an example/host concern, not plugin code.

**Live smoke test:** `e2e/live/smoke.mjs` (since D-023: `npx better-auth-saml-idp smoke`) passed **16/16** against production. It covers:
- metadata caching headers
- unknown SP and disallowed ACS (400, nothing reflected), and replay (302 then 400)
- duplicate or percent-encoded SAML parameters, and RelayState limits (1025 bytes rejected, 200 accepted)
- DOCTYPE, schema-invalid documents, a stale or zone-less IssueInstant, and a non-AuthnRequest root
- a 5 MB DEFLATE bomb, rejected in 158 ms
- the HTTP-POST 303 re-entry and its single use
- a malformed `rid`, and the dev mailbox being off in production
- **IsPassive producing a NoPassive Response whose RSA-SHA256 signature verifies against the metadata certificate**

On this machine Node needs `--network-family-autoselection-attempt-timeout=3000`: there's no IPv6 route, and IPv4 connects to Cloudflare sometimes take longer than Node's 250 ms happy-eyeballs attempt. The npm script sets it.

**SAMLtool on a production Response:** a throwaway account (created, verified in D1, then deleted) got an assertion for the Cloudflare Access SP. The assertion was captured and never posted. SAMLtool returned **"The SAML Response is valid."** with the production certificate, and "Response signature validation failed. Assertion signature validation failed." with a wrong one.

## D-018: Signed AuthnRequests and ForceAuthn, verified live with Cloudflare Access (2026-09-25)

- **Signed AuthnRequests.** The owner turned on "Sign SAML authentication request" in Zero Trust.
  - Cloudflare publishes **two** signing certificates at `/cdn-cgi/access/certs` (a rotation pair). The plugin accepted only one `spCertificate`, so `spCertificate` now also takes an **array**, and a signature from any listed certificate is accepted. Tests cover both an accepted signature from a second certificate and a rejected signature from an unconfigured key.
  - The SP was set to `requireSignedAuthnRequests: true` with both certificates.
  - An unsigned probe then got `400 UNSIGNED_SAML_REQUEST` in production, so the requirement was active.
  - Zero Trust **Test** then **succeeded**. The logs show Cloudflare uses the HTTP-Redirect binding signature (`SAMLRequest, RelayState, SigAlg, Signature`) with `rsa-sha256`, which is exactly what `parseRedirectQuery` and `checkRequestSignature` verify.
- **ForceAuthn.** With "Require reauthentication" on (and signing still on), a Test from a browser **already signed in** to the IdP was sent to `/sign-in` again, then sign-in, then resume, and succeeded. That is the SSO → `/sign-in` → sign-in → `/resume` sequence in the logs at 9:09 (resume issues the assertion because the new session postdates the request).
- The example's `SAML_SERVICE_PROVIDERS` now passes `requireSignedAuthnRequests` and `spCertificate` through.
- Zero Trust state left as tested: signing **on**, reauthentication **on**, encryption and SCIM **off**.

## D-019: Key rotation rehearsed live; example builds Better Auth once per isolate (2026-09-25)

**Key rotation**, with Cloudflare Access as the SP. Guide: `docs/key-rotation.md`.
- **#1 → #2 by coordinated switch.**
  - Pasting **two PEM blocks into Cloudflare's single certificate box** saved without error, but then made Cloudflare trust **neither** certificate. Old-key and new-key Responses both failed with `Response uses a certificate that is not configured`.
  - Setting the box to the new certificate alone, while signing with key #2, fixed it.
- **#2 → #3 with zero downtime.**
  1. Certificate #3 was published through `SAML_IDP_ADDITIONAL_CERTS`.
  2. The owner added #3 in Cloudflare **as a separate certificate entry**, using the add-certificate button. Test passed, signed with #2.
  3. Signing was switched to #3 without touching Cloudflare. **Test passed.**
  4. #2 was removed from the metadata and from Cloudflare. Test passed.
- Every private key went straight into `wrangler secret put`. Local copies were shredded right after use.
- The example gained `SAML_IDP_ADDITIONAL_CERTS`, a secret of concatenated PEMs that are published but never used for signing.

**Example performance.** `examples/workers-hono` now builds Better Auth **once per isolate** (per env and origin). Each request's `cf` geolocation reaches it through `AsyncLocalStorage`, using better-auth-cloudflare's documented resolver-function form of `cf`, which is safe for concurrent requests.

Measured on production with the same method as D-017:

| Request, warm | Before | After |
|---|---|---|
| Metadata, median / p90 | 8 / 16 ms | 6 / 11 ms |
| Validation-only SSO, median / p90 | — | 8 / 12 ms |

The plugin also caches the metadata XML per IdP instance now; samlify was rebuilding it on every request.

The browser e2e (7/7) and the live smoke test (16/16) passed after both changes. The smoke test now uses a dummy SP, `https://smoke.invalid/sp`, registered on the example deployment, because the Cloudflare SP requires signed requests. Right after a deploy, give the new version a few seconds to propagate before running it.

## D-020: Encrypted assertions (2026-09-25)

**What.** A per-SP option, `serviceProviders[].encryption: { certificate, dataAlgorithm?, keyAlgorithm?, allowInsecureCbc? }`. When it's set, the `<saml:Assertion>` is sent as a `<saml:EncryptedAssertion>` (SAML Core §2.3.4) holding one `xenc:EncryptedData Type="#Element"`. Its `ds:KeyInfo` carries an `xenc:EncryptedKey` with `Recipient` (the SP's entity ID), the SP certificate's `X509Data`, and the RSA-wrapped content key. The encryptor is `src/saml/encrypt.ts`, about 150 lines on `node:crypto` (`createCipheriv`, `publicEncrypt`). It has no new dependencies.

**Algorithms.**
- **Data:**
  - `aes256-gcm` (`xmlenc11#aes256-gcm`) is the default.
  - `aes128-gcm` is also available.
  - GCM output is a 12-byte IV, then the ciphertext, then a 16-byte tag (XML Enc 1.1 §5.2.4).
  - `aes256-cbc` (16-byte IV, PKCS#7 padding, which is a valid XML Enc padding) needs `allowInsecureCbc: true`, because of CBC's padding-oracle history. It logs a startup warning.
  - Every assertion gets a fresh random key and IV.
- **Key transport:**
  - `rsa-oaep` (`xmlenc#rsa-oaep-mgf1p`, SHA-1 digest and MGF1-SHA1) is the default. It's the only OAEP form both SP libraries below can decrypt. SHA-1 inside OAEP isn't a collision-resistance use.
  - `rsa-oaep-sha256` (`xmlenc11#rsa-oaep` with a SHA-256 `ds:DigestMethod` and `xenc11:MGF mgf1sha256`) is available for SPs that want it. node:crypto and WebCrypto tie MGF1's hash to the OAEP digest, so both are SHA-256 and declared as such.
  - **RSA PKCS#1 v1.5 isn't implemented.** There's no table entry, options reject `rsa-1_5`, and unknown names throw.
- **SP certificate at startup:** it must parse and be RSA ≥ 2048 bits. Expiry only warns, as for signing certificates.

**Order: sign, then encrypt.**
1. Sign the Assertion.
2. Encrypt that exact serialized, signed element string.
3. Sign the Response, when `signResponse` is set.

SPs verify the assertion signature after decrypting. **Rule:** an encrypted assertion is always signed when the Response isn't. `buildSignedResponse` enforces this even if the options say otherwise, and the startup rule "at least one of signResponse/signAssertion" already implies it for global signing.

SPs parse the decrypted element on its own, outside the Response that declares `saml:`. So an `xmlns:saml` declaration is added to the Assertion's start tag before encryption. That declaration is already in scope, so the exclusive-c14n form and the signature don't change: node-saml and our own xml-crypto check both verify the decrypted assertion's signature.

**Workers findings:**
- workerd's `publicEncrypt`/`privateDecrypt` reject `KeyObject`s ("Received an instance of PublicKeyObject"). The SP key is therefore kept as an SPKI PEM string.
- workerd's `privateDecrypt` with OAEP padding and **no `oaepHash`** fails ("Failed to cipher/decipher"), where Node defaults to SHA-1. We always pass `oaepHash`. The gap breaks samlify's decryptor on workerd (below).

**Evidence** (`test/unit/encrypt.test.ts`, `test/interop/encryption-interop.test.ts`, plus `test/support/xmlenc.ts`, a test-only decryptor that reads the algorithms from the XML and decrypts with node:crypto *and* WebCrypto):

| SP library (decryptor) | aes256-gcm + rsa-oaep | aes128-gcm | aes256-cbc | signResponse: false | rsa-oaep-sha256 | Runtimes |
|---|---|---|---|---|---|---|
| `@node-saml/node-saml` 5.1 (`xml-encryption` 3.1), strict: both signatures, InResponseTo `always` | decrypts + validates | yes | yes | yes, the assertion signature is checked after decryption | **no**: "key encryption algorithm …xmlenc11#rsa-oaep not supported" | Node **and** workerd |
| samlify 2.13.1 (`@authenio/xml-encryption` 2.0.2), strict XSD + signatures | decrypts + validates (NameID, attributes, InResponseTo) | yes | yes | yes, samlify verifies the decrypted assertion | **no**: XSD check rejects `xenc11:MGF`, and the library lacks `xmlenc11#rsa-oaep` | **Node only.** On workerd it can't decrypt any RSA-OAEP key (no `oaepHash`, see above). A workerd-only test pins this, so it flips if workerd changes. |

- **Negative tests:**
  - A wrong SP key fails in node-saml, samlify, node:crypto and WebCrypto.
  - A missing key is refused by node-saml, and an SP not set up to decrypt fails closed in samlify.
  - A flipped ciphertext or tag bit fails GCM in both crypto stacks.
  - The NameID, attribute values, `<saml:Assertion`, `<saml:Subject>` and `SessionIndex` never appear in the posted Response XML.
- **XSD:** the default encrypted Response validates against the vendored SAML/XML-Enc schemas (libxml2). `rsa-oaep-sha256`'s `xenc11:MGF` doesn't, because `EncryptionMethodType`'s wildcard is strict and the XML Enc 1.1 schema isn't vendored. This is tested and documented, and it's why `rsa-oaep` stays the default.
- **Mutation proof:** with the `encryptAssertionInResponse` call removed from `buildSignedResponse`, the unit "plaintext never appears" test fails on both runtimes ("expected … not to contain 'secret-person@example.com'"). All 22 non-skipped interop tests fail too, most of them on the same plaintext check.
- **Counts:** `pnpm test` went from 388 passed / 8 skipped to 462 passed / 14 skipped.
  - Node: 235 passed / 3 skipped.
  - workerd: 227 passed / 11 skipped. The new skips are the 5 Node-only samlify decryption tests on workerd and the workerd-only probe on Node.
  - Per runtime, the new tests are 26 unit tests, plus 13 interop tests on Node or 9 on workerd.

**Out of scope:** encryption certificates advertised in SP metadata (`KeyDescriptor use="encryption"`) are left to the SP-metadata import work. Encrypted NameID/attributes (`EncryptedID`, `EncryptedAttribute`) aren't implemented.

**Verified live with Cloudflare Access (2026-09-25).** With **Enable SAML encryption** on, Access first rejected our plaintext assertion: `SAML Verify: Encryption required but assertion not encrypted`. We then configured `encryption.certificate` for `cf-access` with the defaults (AES-256-GCM, RSA-OAEP mgf1p). The next **Test** returned "Your connection works!" with the expected identity. The request was a signed AuthnRequest (rsa-sha256 over HTTP-Redirect, required per SP), so signed requests, Response and Assertion signatures and encryption were all exercised together. Notes:
- Cloudflare's certificate is available only through the API (`saml_certificate_set.current_certificate.public_certificate`). The dashboard shows the set ID, and the SP metadata doesn't include it.
- It's an RSA 2048 CA-style certificate: key usage *Certificate Sign, CRL Sign*, no `keyEncipherment`, valid for one year. Our startup check deliberately checks only type, size and expiry, not key usage, and that choice is what makes this certificate work.

## D-021: IdP-initiated SSO (SPEC §5 stretch, roadmap v1.1)

`GET /saml2/idp/init?sp=<id>[&RelayState=…]` sends an **unsolicited** Response. It's off by default and enabled per SP with `allowIdpInitiated: true`, which startup validation used to reject as "not supported in this version".

**Design choices:**
- **Opt-in per SP, checked twice.** `init` refuses an SP without the opt-in (`IDP_INITIATED_NOT_ALLOWED`, 400) and an unknown or missing `sp` (`UNKNOWN_SERVICE_PROVIDER`, 400; the value isn't reflected). When the user has to sign in first, `resume` checks the opt-in again, because the configuration may change while the user signs in.
- **GET only.** Launcher links and bookmarks are GETs. A POST from another site would carry no `SameSite=Lax` cookies, so it would always detour through the login page, and it would add surface for no use case. POST isn't routed, and `init` isn't added to `skipOriginCheck`.
- **No request, so no `InResponseTo`.** `ValidatedRequest.requestId` is now `string | undefined`. Undefined means unsolicited, and `buildResponseXml` then omits `InResponseTo` on both the Response and `SubjectConfirmationData` (Profiles §4.1.4.2, §4.1.5). Everything else is the SP-initiated path unchanged: `issueResponse` does the R3 re-read, account policy, `authorize()`, NameID per format, attributes, `Destination`/`Recipient`/`Audience`/`NotOnOrAfter` and signing. There's no replay record (R2), because there's no request ID to record. As a safety net, a POST-binding continuation (`sso?cid=`) without a request ID is refused, since only `init` creates unsolicited requests.
- **Without a session**, the request is parked through the same code as SP-initiated SSO (`parkForLogin`, extracted from `sso.ts`): a single-use pending value bound to the browser, consumed only by `consumeVerificationValue` in `resume`. R1 is unchanged.
- **ACS URL:** always the SP's first registered URL. There's no `acs` parameter, which is one less caller-controlled input. SPs with several ACS URLs should list the IdP-initiated one first.
- **RelayState: allow-list, and ignore anything else.** In IdP-initiated SSO, RelayState conventionally names the SP-side landing URL, and many SPs redirect to it after sign-in. So a RelayState forwarded from the query string would turn every launcher link into an open redirect *at the SP*, behind a trusted IdP domain. New per-SP options:
  - `idpInitiatedRelayState`: the default target.
  - `allowedRelayStates`: caller values accepted by **exact** string match. Near-misses (trailing slash, case, an added query) are tested.
  - Anything else is **ignored**, not rejected: the default is sent, or no RelayState at all. Rejecting would break stale bookmarks for no security gain, since an ignored value never reaches the SP.
  - Both options require `allowIdpInitiated` and must fit in `relayStateMaxBytes`. Both rules are startup errors.
- **Login CSRF.** Any site can send a signed-in user's browser to `init`. The user lands in their *own* SP account, so this isn't the classic "log the victim into the attacker's account". Mitigations:
  - GET only, a fixed ACS URL, and the RelayState allow-list.
  - A **Fetch Metadata check.** `Sec-Fetch-Site: cross-site` without `Sec-Fetch-User: ?1` means another site navigated the browser without a user gesture (a script or meta-refresh). That gets a confirmation page on the IdP's origin: `frame-ancestors 'none'`, one "Continue" link back to the same URL. Clicking it is a same-origin navigation, which goes through.
  - Real clicks from a portal, bookmarks, typed URLs and same-site links go straight through.
  - Browsers without Fetch Metadata send neither header and aren't challenged. The check narrows the attack; it doesn't close it (docs/security.md).
  - Better Auth's global rate limiter covers the endpoint. A dedicated rule wasn't added, because launch clicks are rare and the limiter keys on IP.
- **Replay** can't be tied to a request, so the SP must track assertion IDs until `NotOnOrAfter`. The lifetime stays short (default 300 s). This is documented in docs/security.md, and every issued assertion ID is logged at info level.

**Evidence** (Node and workerd, `pnpm test`):

| Check | Result |
|---|---|
| `test/integration/idp-initiated.test.ts` (20 tests) | refusals (no opt-in with and without a session, unknown or missing `sp`, POST); an unsolicited Response with no `InResponseTo` anywhere, verified by the **strict samlify SP** (both signatures required); NameID format and attributes; login → resume → single use; browser binding; opt-in removed between init and resume; the RelayState default, allow-listed, near-miss and dropped cases, plus RelayState across the login detour; unverified email, `authorize()` denial and a banned user; Fetch Metadata confirmation and pass-through |
| `test/interop/idp-initiated-interop.test.ts` (4 tests) | **node-saml** accepts with `validateInResponseTo: "never"` and rejects with `"always"` with exactly `InResponseTo is missing from response`. **`@better-auth/sso`** signs the user in with `saml.allowIdpInitiated: true` (redirects to `idpInitiatedCallbackUrl`) and rejects it as `unsolicited_response` without it |
| `pnpm e2e` (Chromium, 12/12) | The node-saml test SP is registered a second time (`test-sp-idp-init`, `validateInResponseTo: "never"`). It covers: init without a session → sign-in → resume → SP accepts (`inResponseTo: null`); a portal link click from `app.test` goes straight through with an allow-listed RelayState; a disallowed RelayState is replaced by the default; a **script redirect from `app.test` gets the confirmation page in real Chromium**, and Continue then signs in; an SP without the opt-in gets 400. The IdP-initiated tests sign in with the file's existing account, because a fifth sign-up from 127.0.0.1 tripped Better Auth's sign-up rate limit (3 per 10 s) in the first run. |

**Mutation proofs** (each re-broken, run on Node, then restored):
- **Opt-in check removed from `init`:** 2 tests fail.
- **`InResponseTo="_forged"` always emitted:** the node-saml `"always"` test flips to `InResponseTo is not valid`, the `"never"` test's no-`InResponseTo` assertion fails, and both `@better-auth/sso` tests fail (`unknown or expired request ID`).
- **Caller RelayState passed through:** 2 tests fail.
- **Opt-in re-check removed from `resume`:** 1 test fails.
- **Fetch Metadata check removed:** 1 test fails.

**Not done:** a Keycloak IdP-initiated e2e. Keycloak's broker accepts unsolicited Responses only at `/realms/{realm}/broker/{alias}/endpoint/clients/{client}`, with a realm client that has an "IDP-Initiated SSO URL name", which means extra realm setup and a second ACS URL. The node-saml SP already covers the real-browser path.

**Live check with Cloudflare Access (2026-09-25).** With `allowIdpInitiated: true` on `cf-access`, `/saml2/idp/init?sp=cf-access` issued the unsolicited Response (signed, encrypted, no `InResponseTo`) and auto-posted it. Access rejected it with "Invalid login session. Please try going to the URL of your application again". Access doesn't support IdP-initiated SAML, and its callback requires the state from its own SP-initiated login. The opt-in was then removed again. The interop evidence for this feature therefore remains node-saml in Chromium, samlify and `@better-auth/sso` (in CI).

## D-022: Per-SP signing, signed metadata, SP registration from metadata (2026-09-25)

- **Per-SP `signResponse` / `signAssertion`** override the global `signing` values. As before, at least one must be on. An SP is only rejected for turning both off when it set one itself, so a global both-off is reported once. Tests show that an assertion-only or response-only Response is accepted by an SP that requires exactly that, and refused by node-saml when it requires both. samlify's `wantMessageSigned` / `wantAssertionsSigned` are **not enforced** when it parses a Response, so a samlify SP can't be used to prove that a signature is missing.
- **`signMetadata`** (default false) adds an `ID` to `EntityDescriptor` and an enveloped signature with the active key. It is placed as the first child, as the metadata XSD requires. The document still validates against the metadata XSD, the signature verifies with xml-crypto, and tampering breaks it. It is cached per IdP, like unsigned metadata.
- **`serviceProviderFromMetadata()`** is a helper, not an endpoint.
  - It runs a size precheck, rejects any DOCTYPE, validates against the metadata XSD, then parses strictly.
  - It accepts an `EntityDescriptor`, or an `EntitiesDescriptor` with an explicit `entityId` (a selector is required: an aggregate never silently yields its first entity).
  - It collects HTTP-POST ACS endpoints only: `isDefault` first, then by `index`. Other bindings produce warnings.
  - It takes the first supported NameIDFormat, not `unspecified`.
  - Signing certificates come from `use="signing"` or unmarked KeyDescriptors. Encryption certificates are returned separately.
  - It does **not** verify the metadata signature. Trust comes from how the document was obtained, and the output is meant to be reviewed and pinned. Verifying against a federation's signing key belongs with URL refresh (v1.2).
  - Tested with Cloudflare Access's real metadata, and with metadata generated by samlify and node-saml.

## D-023: A command-line tool, not a debug endpoint (2026-09-25)

- Developers get diagnostics from **outside** the app: `npx better-auth-saml-idp <command>`. The IdP has no debug or status route. That kind of route would report configuration and internals to anyone who can reach it, and every fact the CLI needs is already public (metadata) or comes from the developer (captured messages, their own keys and config).
- **Node only**, with no new dependencies:
  - `node:util` `parseArgs` handles the arguments.
  - xml-crypto verifies signatures.
  - `node:crypto` decrypts XML Encryption.
  - A small DER encoder produces the `keygen` certificate. OpenSSL parses it: v3, sha256WithRSA, CA:FALSE, digitalSignature. The plugin accepts the generated key and certificate pair.
- **`decode` verifies signatures the way an SP must.** The ds:Signature must be a direct child of the element, have exactly one Reference whose URI is `#` plus that element's ID, and the ID must be unique in the document. Only then is the value checked against the given certificates. So a signature-wrapping attempt is reported as invalid rather than valid.
  - Captured Responses are expected to be expired, so an expired time window only warns.
  - Decryption refuses RSA PKCS#1 v1.5 key transport.
- **Key material:** `keygen` writes the key to `--key-out` with mode 0600 and never overwrites a file without `--force`. It prints the key to stdout only when stdout is a pipe, so the key doesn't land in terminal scrollback. The report goes to stderr, so a pipe receives only the key.
- **Output:** `--json` gives machine-readable output. Exit codes are 0 (OK), 1 (a check failed) and 2 (a usage or input error). `request` and `sp-from-metadata` put their result alone on stdout, with the report on stderr.
- **`smoke` replaces `e2e/live/smoke.mjs`.** It has the same checks, except the example-specific dev-mailbox check, and uses the CLI's metadata and signature code.
- **Tests:** 26, Node project only, with `fetch` routed to an in-process IdP.
  - Every command is covered.
  - Response checks: altered Responses, the wrong certificate, wrong Audience, ACS and InResponseTo, a duplicated ID, and DOCTYPE refusal.
  - Encrypted assertions: decryption, and the wrong key.
  - Requests: signed-request verification.
  - Checked by hand against the live Workers deployment: `inspect`, `smoke` (15 of 15), and `request` then `decode` of a live signed NoPassive Response.

## D-024: Declarative attribute mapping (2026-09-25)

Spec open question 5. `serviceProviders[].attributes` accepts a map as well as a function: `{ attributeName: source }`. A source is one of:
- a user field (`"email"`, `"role"`);
- `{ field, split?, part? }`: split a field into several values, or take the first word or the rest of it (first/last name from `name`);
- `{ value }`: a constant.

**Why this shape.** It covers what SPs actually ask for (email, names, groups/roles, a fixed org) while staying data, not code. That means an SP entry is plain JSON: the Workers example's config var, `check-config`, `sp-from-metadata` output, and the planned database registry can all hold it. Anything more complex stays a function. We deliberately don't provide expressions or templates, since a mini-language would be attack surface and a maintenance burden.

**Semantics.**
- The map is compiled once at startup into the same `(user) => attributes` function, so issuing has one code path.
- Only the user's *own* properties are read (`Object.hasOwn`), so `"constructor"` and the like resolve to nothing.
- Field names must match `[A-Za-z_][A-Za-z0-9_]{0,63}`.
- Values: null, empty and object values are left out (no `"[object Object]"`). Dates become ISO 8601, and arrays and `split` results are multi-valued.
- A field the user doesn't have is logged once per SP and field, so a typo shows up instead of silently dropping the attribute.
- Validation messages name the exact problem (for example `part: must be "first" or "last"`), not zod's generic "Invalid input".

**Tests.** Unit tests cover every source type and edge case, inherited properties, and each validation message. An integration test has the strict samlify SP read mapped fields, the admin plugin's `role`, name parts, constants and escaped values. It also checks that a missing field is left out and warned about exactly once.

## D-025: Signed AuthnRequests over HTTP-POST (2026-09-25)

**What.** A POST-binding AuthnRequest may carry an enveloped XML signature. Policy is unchanged: `requireSignedAuthnRequests` and `spCertificate` work as for Redirect.
- A signature is verified whenever the SP has certificates.
- An invalid signature is always rejected.
- With no SP certificates and no requirement, a signature is ignored.

The Redirect binding still verifies the query octets. An embedded signature on a Redirect request is ignored, because that binding signs the query.

**Signature wrapping is the risk, so verification is by allow-list, in `src/saml/xmldsig.ts`, before any cryptography:**
1. Exactly one `ds:Signature` in the document, and it's a direct child of the AuthnRequest. The XSD also allows at most one.
2. Exactly one `Reference`, whose URI is `#` plus the AuthnRequest's `ID`.
3. That value appears on exactly one element across `ID`, `Id` and `id` attributes, which is every attribute xml-crypto may resolve a reference through. The XSD's `xs:ID` uniqueness catches the plain duplicate first. Our check also covers `Id`/`id` on foreign elements.
4. Canonicalization is exc-c14n or c14n 1.0, with no `WithComments`. Transforms are enveloped-signature and those two only, so no XPath or XSLT. Signatures are rsa-sha256 or rsa-sha512, and digests sha256 or sha512. SHA-1 is allowed only with `allowInsecureSha1`.
5. No XML comments anywhere in a signed request. Exclusive c14n drops comments, so `sp<!---->.evil` would keep a valid signature. We read text with `textContent`, which isn't vulnerable, but refusing comments closes that class of bug outright.
6. Verification uses the SP's configured certificates only (`getCertFromKeyInfo: () => null`). A certificate in the message's `KeyInfo` is never trusted.

The verified document is the same string that the request pipeline reads. It's **not** read by the same xmldom version (corrected in D-030): xml-crypto 6 brings its own xmldom 0.8 and the plugin uses 0.9. The one known way they read a document differently, duplicate expanded attribute names, is refused by `parseXmlStrict` and by the XSD before any signature is checked.

**Evidence.**
- 14 integration tests (both runtimes):
  - accepted: sha256 and sha512;
  - interop: node-saml's own signed POST request;
  - refused: unsigned, altered, wrong key with the attacker's certificate in `KeyInfo`, SHA-1 without the opt-in, wrapping inside `Extensions`, a duplicated ID, comment injection, `WithComments`, two signatures;
  - SP key rotation;
  - optional-signature policy.
- 10 unit tests exercise each rule without the XSD in front.
- **Mutation proof:** disabling each rule in turn made at least one test fail:
  - Reference-URI check: 2 tests. Without it, xml-crypto accepted the wrapped request **end to end**. So this rule, not the library, is what stops signature wrapping.
  - ID uniqueness: 1 test.
  - c14n allow-list: 1 test.
  - transform allow-list: 1 test.
  - ignoring KeyInfo: 5 tests.
  - comment refusal: 1 test.
  - multiple signatures: 1 test.
  - POST verification removed entirely: 8 tests.
- The CLI's `decode` now uses this same verifier, for Responses too. `request --binding post --sign-key` produces a signed POST request, which the IdP accepts in a test.

## D-026: SP metadata URL with refresh (2026-09-25)

**What.** `serviceProviders[].metadata: { url, refreshSeconds?, signingCertificate? }` keeps an SP's certificates current from its metadata.
- Learned signing certificates are **added** to the configured `spCertificate`.
- When `encryption` is on, the metadata's encryption certificate **replaces** `encryption.certificate`. The configured algorithms are kept.
- `requireSignedAuthnRequests` no longer needs a configured `spCertificate` when a metadata URL is set.

**Certificates only, by design.** Metadata controls security-relevant settings, so the blast radius is kept small:
- The entity ID must equal the configured one.
- **ACS URLs are never taken from metadata.** A compromised metadata endpoint therefore can't redirect assertions (tested).
- The worst case is a swapped certificate:
  - A swapped signing certificate lets an attacker sign AuthnRequests, but only for the pinned ACS URLs.
  - A swapped encryption certificate makes assertions undecryptable by the SP, but they still only travel through the user's browser to the pinned ACS URL.
- Pinning the metadata's signature (`signingCertificate`, checked by the D-025 verifier with SHA-1 refused) closes that gap. Without a pin, startup logs a warning.

**Fetching.**
- https only, 5 s timeout, `redirect: "error"`, at most 1 MiB.
- Then `precheckXml`, a strict parse, the metadata XSD (through `serviceProviderFromMetadata`), and a refusal when `validUntil` has passed on the document or the entity.

**Freshness, per isolate, with no shared storage.** The certificates are small and the SP is the source of truth, so every isolate fetches on its own.
- The first use in an isolate waits for the fetch. It's bounded by the timeout, so a slow SP delays one request, not all of them.
- After that, a due refresh runs through `ctx.context.runInBackground`, which is `waitUntil` on Workers when the host configures it, while requests use the cached copy.
- A failure keeps the last good copy, or the configured certificates if there is none, and retries after 5 minutes, doubling up to the refresh interval. Tested: no retry storm.
- Changes are logged, with counts, once per change.

**Evidence.**
- 26 tests (both runtimes):
  - the first use waits for the fetch;
  - rotation is picked up after the interval, and the old learned key stops being trusted;
  - a failed fetch falls back to the configured certificates, with backoff;
  - ACS URLs are never learned;
  - rejected: another entity ID, an expired `validUntil`, unsigned metadata when pinned, metadata signed by another key than the pinned one, and non-XML;
  - pinned and signed metadata is accepted;
  - the encryption certificate from metadata wins;
  - option validation and the unpinned warning.
- **Mutation proof:** disabling each of these made tests fail:
  - entity-ID pin: 1 test;
  - `validUntil`: 1;
  - signature pin: 2;
  - merging learned certificates: 5;
  - backoff: 1.

**Verified live with Cloudflare Access (2026-09-25).** `cf-access` was configured with **no** SP certificates, `requireSignedAuthnRequests: true` and `metadata.url` set to Cloudflare's `/cdn-cgi/access/saml-metadata`. Access's signed AuthnRequest (rsa-sha256, HTTP-Redirect) was verified with the two certificates learned from that metadata, and the login succeeded with encryption on.

The live test also found a **workerd incompatibility the stubbed tests couldn't**: workerd rejects `fetch(..., { redirect: "error" })` ("does not make sense at the edge"). The first attempt therefore failed closed. The refresh failed, no certificates were learned, and the signed request was refused with `UNSIGNED_SAML_REQUEST`. The fix is `redirect: "manual"`, with any non-200 response, including a 3xx, treated as a failure. A redirect test was added.

## D-027: Database-backed SP registry and management API (2026-09-25)

**What.** `registry: { enabled, canManage?, cacheSeconds?, authorize? }`.
- It adds a `samlIdpServiceProvider` table with columns spId (unique), entityId (unique), config (JSON), enabled, and created/updated/updatedBy.
- The table is only in the plugin schema when the registry is enabled, so D1 `validateSchema` hosts without it need no migration.
- SPs are looked up in code first, then in the table.
- With `canManage`, five endpoints manage stored SPs: list, get, create, update (full replacement, id immutable) and delete.

**Stored SPs are data, not code.**
- They use the option schema minus `nameId`/`authorize`, and `attributes` must be a map (D-024).
- `authorize` for stored SPs comes from `registry.authorize`.
- One shared `resolveServiceProvider()` validates code SPs and stored SPs. That refactor also made SP certificates parse at startup, which they didn't before, so a garbage `spCertificate` is now a configuration error.

**Trust boundaries.**
- **API access:**
  - The API is mounted only when `canManage` exists, and it uses `sensitiveSessionMiddleware`, which reads the session and user from the database.
  - Mutation proof: with the plain session middleware and Better Auth's cookie cache on, a **demoted admin kept access**. The authoritative read is what revokes it.
  - Impersonated sessions are refused, `canManage` must return `true` (a throw denies), Better Auth's origin checks apply (verified with `disableOriginCheck: false`, because Better Auth disables origin checks under test), and every change is audit-logged with the user id.
- **Rows edited directly in the database:**
  - Every row is re-validated on each (cache-missing) load, and invalid JSON or config is ignored and logged.
  - The lookup columns must equal the config's id and entityId, a disabled row is never used, and code SPs always win.
  - The API refuses the id or entity ID of a code SP (409). UNIQUE columns decide create races, and a read only classifies the failure, as for R2.
- **Load:** lookups are cached per isolate (default 60 s), misses too, capped at 2000 entries, so unknown issuers don't each cost a read. Other isolates see changes within `cacheSeconds`; that's tested both ways.
- **Metadata:** with a registry, IdP metadata no longer claims `WantAuthnRequestsSigned`, because SPs added later might not sign. The metadata-refresh cache is keyed by SP *and* URL.

**Evidence.**
- 43 tests (both runtimes):
  - lifecycle: create, then sign in at once with stored attributes; list and get; update, where the old ACS stops working; disable; delete; required signed requests;
  - validation: five invalid-config cases with their issues;
  - conflicts: duplicates, and code-SP conflicts;
  - access: unmounted without `canManage`; 401 and 403; demotion, with and without the cookie cache; impersonation; origin; `canManage` throwing;
  - isolates: two sharing one database, with 0 s and 60 s caches;
  - a tampered row;
  - the conditional schema.
- **Mutation proof:** disabling each of these made tests fail:
  - impersonation refusal: 1 test;
  - the `canManage` decision: 3;
  - code-SP conflict: 1;
  - re-validating stored rows: 1;
  - disabled rows: 1;
  - authoritative session: 1, once the cookie-cache test was added (0 before, which is why it was added).

**Verified live on Workers + D1 (2026-09-25).** Migration `0003_service_providers.sql` was applied to the example's D1 database, and the example was deployed with `registry.enabled`. The API is limited to emails in `SAML_REGISTRY_ADMINS` with verified addresses. A stored SP (`smoke-db`) was inserted as a D1 row, and `npx better-auth-saml-idp smoke --sp https://smoke-db.invalid/sp` passed **15/15** against production. The code-configured SP still passed 15/15 as well.

## D-028: SAML Single Logout (2026-09-25)

**What.** `singleLogout: { enabled: true }` plus a per-SP `singleLogoutService: { url, binding? }`, which `serviceProviderFromMetadata` also reads, preferring Redirect.
- A `samlIdpSessionParticipant` table records `(hash(session id), SP, NameID, format, SessionIndex)` on every issuance, one row per SP per session through a UNIQUE key, refreshed for transient NameIDs.
- `/saml2/idp/slo` takes SPs' LogoutRequests and LogoutResponses over both bindings.
- `/saml2/idp/logout?returnTo=` starts an IdP-initiated logout.
- IdP metadata advertises `SingleLogoutService` only when enabled.

**Flow.**
1. The IdP session is ended **first**: the Better Auth session row, the session cookie and the participant rows.
2. Then there's one front-channel hop per other participant: our LogoutRequest, always HTTP-Redirect and query-signed with the IdP key, about the NameID and SessionIndex that SP was given.
3. The hop state is a single-use verification value named by the RelayState (5 min). The SP's answer, over either binding, continues the chain. No cookies are needed, so a cross-site POST answer works.
4. Finally, the originator gets a signed LogoutResponse over its configured binding (Redirect query signature, or auto-POST with an enveloped XML signature): `Success`, or `Success/PartialLogout` if a participant failed, answered for another request, had a bad signature, or has no SLO endpoint.
5. An IdP-initiated logout ends with a redirect to `returnTo`.

**Authenticating a LogoutRequest** (Profiles §4.4.4.1: it must be authenticated):
- With SP certificates, a valid signature is required: the D-025 POST verifier, or the Redirect query check. `verifyMessageSignature` refuses an unsigned message itself, so the explicit "must be signed" check is belt-and-braces. Its mutation didn't fail a test because the next line already refuses the message.
- Without certificates, the session ends only if a `SessionIndex` equals the value issued **to that SP** for this browser's session (per-SP keyed MAC since review 2; see D-029).
- A signed request without `SessionIndex` must name the NameID stored for that SP and session.
- A request that matches nothing is answered `Success` and ends nothing, because "this principal has no session here" is true from that SP's point of view.
- LogoutRequest IDs go through the R2 replay table, namespaced `logout:`.

**Cross-site POST:** an HTTP-POST LogoutRequest can't see `SameSite=Lax` cookies, so it re-enters on a single-use same-site `slo?cid=` GET, as the SSO POST binding does.

**Logout CSRF:** `/logout` is GET, for "sign out" links, with the same Fetch-Metadata drive-by confirmation as `/init`. `returnTo` must be a same-origin path or a Better Auth trusted origin, with backslashes and control characters refused.

**Evidence.**
- 14 integration tests (both runtimes):
  - the full two-SP chain, with IdP signatures on every outgoing message checked;
  - `PartialLogout` for a failure status, a wrong `InResponseTo` and a wrong signing key;
  - hop-state replay; unsigned and forged requests; `SessionIndex` authentication without certificates; LogoutRequest replay; no session;
  - POST re-entry; a POST-binding originator (XML-signed, auto-POSTed, and the session cookie cleared on that raw Response too);
  - an SP without SLO;
  - IdP-initiated propagation to both SPs, then `returnTo`; `returnTo` validation; drive-by confirmation;
  - **node-saml interop**: its signed LogoutRequest ends the session, and it validates our LogoutResponse (`loggedOut: true`);
  - metadata advertised only when enabled.
- **Mutation proof:** 9 of 10 rules fail at least one test when disabled:
  - signature verified; SessionIndex binding; unsigned requests not matched by NameID; replay; the answer matching our request; the answer's signature; `returnTo`; drive-by confirmation;
  - session cookie cleared (2 tests);
  - the explicit "must be signed" check is the redundant one described above.

**Live on Workers + D1 (2026-09-25).** Migration `0004_session_participants.sql` was applied, and the example deployed with `singleLogout` enabled. The live metadata advertises both SingleLogoutService bindings. `/logout` without a session redirects to `returnTo`. A hostile `returnTo` gets `400 INVALID_RETURN_TO` (the error page now says "Sign-out could not be completed" for logout errors). The code-configured SP and the D1-stored SP both still pass smoke 15/15. Cloudflare Access doesn't do SAML SLO, so SP interop is node-saml, in CI on both runtimes.

**Found after release, by `inspect` on the live IdP:** SLO-enabled metadata **failed the metadata XSD**. samlify emits `SingleLogoutService` after `SingleSignOnService`, but `SSODescriptorType` requires it before `NameIDFormat`. The SLO metadata test had only matched a regex. `renderMetadata` now moves the elements into schema order before any signing. The test validates the real document, signed and unsigned, against the XSD, and fails without the fix (mutation-checked). Live `inspect` is clean again.

## D-029: Second adversarial review, part 1 (fresh eyes, 2026-09-25)

**How it was run.** A reviewer with no conversation context worked in its own worktree, with the code, README, threat model and DECISIONS only, and the brief to break it. It wrote a failing proof-of-concept test for each finding, and none touched `src/`. I re-ran each proof against `main` (all 9 reproduced), then fixed each one with its test turning green. The tests stay in `test/review2/` as regressions. A second, independent review by a different model follows.

**Findings and fixes**
- **R2-SLO-2 (Medium): one SessionIndex for every SP, an unkeyed hash, not tied to the requesting SP.**
  - Impact: SP B could use its own value to end the user's session in the name of certificate-less SP C. SPs could also link a user across SPs, which defeated pairwise NameIDs.
  - Fix: `sessionIndexOf(secret, sessionId, spId)` is an HMAC with the Better Auth secret. The logout check compares against the value for the SP named as Issuer.
- **R2-SLO-1 (Medium): participant rows expired at the session's expiry *at sign-in*.** After Better Auth's sliding refresh, the expiry sweep dropped them, and logout silently skipped SPs while reporting `Success`.
  - Fix: a `session.update.after` database hook moves the participants' expiry with the session's.
  - Fix: a failure to list participants, or hitting the 200-participant cap, now reports `PartialLogout`.
- **R2-MD-1 (Medium): certificates learned from metadata survived a re-pin** of `metadata.signingCertificate`, or a change of entity ID or encryption settings, until the next refresh.
  - Fix: the cache key covers the id, entity ID, URL, pin fingerprints and encryption algorithms.
  - Fix: learned encryption keys apply only while `encryption` is configured, with the current algorithms.
- **R2-SLO-3 (Medium): SLO accepted unsigned requests whenever the SP's certificate list was empty**, including when its certificates come from a metadata URL that failed to load.
  - Fix: logout messages must be signed when the SP has certificates, requires signed AuthnRequests, or has `metadata`. With no certificates available, they fail closed. An unverifiable participant answer counts as partial.
- **R2-SLO-4 (Low): `singleLogoutService.binding: "post"` was ignored for our LogoutRequests**, so the chain stalled at POST-only SPs.
  - Fix: POST participants get an auto-posted, XML-signed LogoutRequest.
- **R2-MD-2 (Low): metadata import used `ResponseLocation` for requests.**
  - Fix: `Location` for requests, and `responseUrl` (from ResponseLocation) for our LogoutResponses.
- **R2-SLO-5 (Low): SLO didn't enforce `relayStateMaxBytes`**, so unauthenticated cross-site POSTs could store large values.
  - Fix: `checkRelayState`, as SSO does.
- **R2-CLI-1 (Low): `keygen --force` kept an existing file's permissions** and followed symlinks.
  - Fix: remove the file, then create it exclusively (`wx`) with mode 0600.
- **Info items fixed:**
  - Metadata bodies are read as a stream with a 1 MiB cap (tested with an endless body).
  - Stored-SP lookups must match the requested value exactly (unit test with a case-insensitive, PAD SPACE adapter; mutation-checked).
  - Signed LogoutRequests and LogoutResponses need a `Destination` (Bindings §3.4.5.2 / §3.5.5.2).
  - The logout drive-by page no longer talks about signing in.
- **Info items documented, not changed:**
  - A certificate-less SP's LogoutResponse can be obtained unauthenticated (docs/security.md: SPs must check `InResponseTo`; give SLO SPs a certificate).
  - Registry `metadata.url` can reach internal https hosts (admin-only).

**Rejected by the reviewer after trying:**
- XSW through ID/Id/id or namespaced ids.
- XPath injection through the Reference URI.
- Comment truncation.
- xmldom 0.9 vs 0.8 parser differences.
- Redirect signature octet tricks.
- `returnTo` open redirects.
- Logout-state forgery.
- Registry authorization bypass and mass assignment.
- Prototype pollution through attribute maps.
- XML injection.
- Stored SPs being more powerful than code SPs.

## D-030: Second adversarial review, part 2 (external, different model, 2026-09-25)

**How it was run.** A different model reviewed all of `src/` in its own worktree, from the pre-fix code and without seeing part 1's findings, and wrote a failing proof-of-concept test for each finding. It found **six of part 1's nine issues independently**:
- R3-1: metadata body not capped when there's no Content-Length;
- R3-2: a participant-read failure reported as Success;
- R3-3: participants expiring before a refreshed session;
- R3-4: SLO RelayState size not enforced;
- R3-5: ResponseLocation used for requests;
- R3-6: `keygen --force` file mode.

All six were already fixed by D-029, and their proof-of-concept tests pass against the fixed code. Two of the tests needed adjusting, and neither adjustment weakens what they check:
- **Metadata body limit:** the reader stops just past 1 MiB, but the stream pre-fetches one chunk ahead, so the slack is now two 64 KiB chunks instead of one.
- **Participant expiry:** the test swept with a cutoff 61 s in the future to get past the throttle, which would also delete correctly extended rows. It now resets the throttle and sweeps at the real "now". It also reads the new `{ participants, truncated }` shape.

**New in part 2**
- **R3-2, second half (Medium): recording a participant could fail silently at issuance**, so a later logout skipped that SP and still reported Success.
  - Fix: fail closed. With `singleLogout` enabled, an assertion the IdP couldn't record isn't issued (`INTERNAL_ERROR`). Tested by making the participant insert fail.
- **R3-7 (Info): two xmldom versions.** xml-crypto 6 verifies with its own xmldom 0.8, and the plugin reads with 0.9. D-025's "same xmldom" claim was wrong and is corrected.
  - The reviewer fuzzed about 60 constructs. The only divergence found: two attributes with the same expanded name (`p:x` and `q:x`, with p and q bound to one URI). xmldom 0.9 silently drops one, contradicting the "strict parse" comment, while 0.8 keeps both. It isn't exploitable, because the digest breaks and the XSD rejects it on protocol paths, but it made the strict parse dishonest.
  - Fix: `parseXmlStrict` now runs a Namespaces-in-XML §6.3 check first. A scanner tracks namespace declarations through the element stack and rejects duplicate expanded names, so the claim holds on every path, including the CLI and metadata.
  - The scanner's regex was timed on adversarial inputs: 200 KB of unterminated tags takes under 10 ms, and a 1 MiB document takes about 320 ms in total, mostly xmldom.
  - Metadata refresh now runs the XSD check **before** the metadata signature check, like every other path.
  - Pinning xmldom to one version in this repository would prove nothing for consumers, whose install gives xml-crypto its own copy. So the test documents the two versions and asserts the mitigation instead.

**Rejected by the reviewer after trying:** everything listed under D-029, plus:
- POST continuation and resume-link binding;
- R3 re-reads, bans and `authorize()` throwing;
- encryption order and key freshness;
- CLI `decode` never reporting a forged, wrapped or duplicate-ID message as valid;
- login and logout CSRF limited to user-activated navigation (documented residual risk).

**Mutation proof for the review fixes:**
- Each of these made at least one test fail when disabled:
  - the expanded-name check: 2 tests;
  - fail-closed participant recording: 1;
  - participants following session refresh: 2;
  - the per-SP SessionIndex: 8;
  - pin fingerprints in the metadata cache key: 1.
- The explicit "no SP certificate available" refusal in SLO is belt-and-braces: `verifyMessageSignature` with no certificates already rejects the message, so it fails closed either way.

## D-031: Deeper Better Auth integration (2026-09-25)

The goal is for the plugin to feel native to Better Auth, using its own plugins' data and access model instead of inventing parallel ones.

- **Organization plugin.**
  - An SP can set `organization: { slug | id, roles? }`: only members get in, and with `roles`, only members holding one of them. Multi-role members (`"member,admin"`) are handled.
  - The rule is evaluated before `authorize()`, and it **fails closed** when the organization plugin isn't installed.
  - Attribute sources `{ organization: "slugs" | "names" | "ids" | "roles" }`. Roles are scoped to the SP's organization when it has one, and are `slug:role` otherwise.
  - `authorize()` and attribute functions receive the user's memberships.
  - It's JSON, so it works for registry SPs too.
  - Memberships are read through the adapter by the plugin's model keys (`member`, `organization`), so renamed tables work. They're loaded only when the plugin is installed.
  - The tests run on Node only: the organization plugin needs tables and a session column that the workerd D1 test schema doesn't carry, and the logic is the same adapter calls on both runtimes.
- **Admin plugin access control.**
  - `registry.permissions: true` checks a `samlServiceProvider` resource for each action (list, read, create, update, delete) against the host's own admin-plugin roles and `adminUserIds`.
  - `samlIdpStatements` is exported for `createAccessControl`.
  - The admin plugin's default roles grant nothing on this resource, so hosts must opt roles in explicitly.
  - With `canManage` too, both must allow.
  - The admin plugin's `hasPermission` isn't a public export, so its roughly six lines of logic are mirrored in `src/access.ts` and read the plugin's resolved options at runtime.
- **Client plugin.**
  - Registry calls are typed from the server plugin (`authClient.saml2.idp.serviceProviders.*`, checked by `expectTypeOf` under `tsc`).
  - `logoutUrl` / `signOutEverywhere` / `launchUrl` / `launch` build the navigation URLs from the client's `baseURL` and `basePath`.
- **Better Auth CLI.** `npx auth generate` (the CLI moved from `@better-auth/cli` to the `auth` package) was checked from a packed tarball in a clean project. It emits all three plugin tables with their UNIQUE constraints and indexes, for whatever is enabled.

## D-032: The guide, and background work on Workers (2026-09-26)

**Documentation.** Better Auth's `@better-auth/sso` page is about 1,900 lines, and it documents each security control as *how it works / options / errors*, plus a full schema and options reference. Our equivalent material was spread across the README, docs/security.md and this file, so it was consolidated into `docs/guide/`:
- how-to pages: getting started, service providers, flows, users and access, signing and encryption, Single Logout, `@better-auth/sso` interop, Cloudflare Workers, the CLI, troubleshooting;
- complete references: options, errors, security controls, schema.

Writing the references surfaced three corrections:
- `PASSIVE_SIGN_IN_NOT_POSSIBLE` was never produced (IsPassive gets a SAML `NoPassive` Response instead), so it was removed from the public codes before v1.0.
- `NAMEID_FORMAT` was documented but not exported; it now is.
- The example Worker didn't wire Better Auth's background tasks to `waitUntil`. See below.

`scripts/check-links.mjs` (`pnpm docs:check`, in CI) checks every relative link and heading anchor.

**Background work on Workers.** Better Auth runs background tasks fire-and-forget unless `advanced.backgroundTasks.handler` is set. On Workers, a promise left running after the response can be cancelled and never settle. Our metadata-refresh cache would then have kept that refresh "in flight" forever, so that isolate would never refresh again. Two fixes:
- **In the plugin:** a refresh unsettled after 30 s counts as abandoned and is replaced. The first-use wait is also bounded by its own timer, not only by the fetch's abort signal. Tested with a fetch that never settles; mutation-checked (without the rule, no second attempt happens).
- **In the example:** `advanced.backgroundTasks.handler` passes work to the current request's `waitUntil` (through `AsyncLocalStorage`, since one auth instance serves every request in the isolate). The Workers guide documents this as a requirement.

## D-033: Database adapter matrix, and replay protection on MongoDB (2026-09-26)

**What.** `test/adapters/adapter-matrix.test.ts` runs every database-dependent behaviour against a real server, selected by `ADAPTER_DB`:
- a full sign-in;
- replay under 10 concurrent identical requests, and the seen-request UNIQUE key enforced by the database itself (the first test on a fresh database, so on MongoDB it races the lazily created index);
- a concurrent single-use resume;
- a registry create race, exact lookups, and boolean and date round-trips;
- logout participants: upsert, list, clear;
- organization memberships (`in`);
- the expiry sweep (`lt`).

CI runs it on PostgreSQL 17 and MySQL 8.4 (Kysely, as Better Auth builds for a raw pool) and MongoDB 8.2 as a single-node replica set, next to the existing SQLite and D1 suites. Each run creates a fresh database and migrates it with Better Auth's own migrator.

**Found: replay protection did nothing on MongoDB.** With the plugin as it was:
- 10 of 10 replayed requests were accepted;
- 5 of 5 concurrent registry creates succeeded;
- logout participants were duplicated.

The cause: Better Auth 1.7's MongoDB adapter creates indexes only from table-level `indexes` declarations and ignores field-level `unique: true`, which the SQL migrators and `npx auth generate` do honour. Our tables declared uniqueness only at field level.

**Fix.** Each unique column is also declared as a named table-level unique index:
- `saml_idp_seen_request_key_unique`;
- `saml_idp_service_provider_sp_id_unique` and `saml_idp_service_provider_entity_id_unique`;
- `saml_idp_session_participant_key_unique`.

They're named because an unnamed one collides with the name the field-level flag reserves, and Better Auth refuses that. The field-level flags stay, so SQL databases and the D1 schema are unchanged.

After the fix, all 8 behaviours pass on MongoDB, including the first-insert race (the adapter awaits index creation before inserting). Postgres, MySQL, SQLite and D1 were re-run and still pass. `npx auth generate` now also emits the named `uniqueIndex(...)` entries.

**Also learned.**
- MongoDB needs a replica set: Better Auth's adapter uses transactions when given a `client`, and a standalone server rejects them ("Transaction numbers are only allowed on a replica set member").
- MongoDB 8.0 doesn't start on Linux kernels 6.19 and newer (SERVER-121912); 8.2 does.
- MySQL's default collation is case-insensitive, so the registry's exact-match lookup (review 2) is now proven against a real database.
- **Upstream:** Better Auth's own core tables declare uniqueness at field level (for example `user.email` and `session.token`), so on MongoDB those may not be backed by unique indexes either. This is worth a careful report to Better Auth; it's not ours to fix.

**Not yet covered:** Drizzle on Postgres and MySQL, and Prisma (still on the roadmap).

## D-034: Okta as a live SP (2026-09-26)

An Okta Integrator (free) org added the example Worker as an external SAML IdP (Security → Identity Providers). Its SP metadata, downloaded because it needs an admin session, was turned into an entry with `npx better-auth-saml-idp sp-from-metadata`. That gave the entity ID and ACS URL, `requireSignedAuthnRequests` with Okta's signing certificate, and Okta's encryption certificate.

**Round 1, plain assertions (SP in the `SAML_SERVICE_PROVIDERS` var):**
- Okta sent a signed AuthnRequest (HTTP-Redirect, RSA-SHA256), and it was verified.
- After a Better Auth sign-in, Okta accepted the signed Response and assertion and JIT-provisioned the user, then applied its own authenticator enrollment.

**Round 2, encrypted assertions:** enabling `encryption` pushed the JSON var past Workers' 5.1 kB limit for a text binding, so Okta moved into the **D1 registry**, with the same config plus `encryption` and an attribute map, inserted as a row. Okta signed in again, which proves:
- it decrypted our AES-256-GCM / RSA-OAEP assertion;
- signed requests and encryption work for a stored SP.

If the stored config hadn't validated, the SP would have been unknown, not signed in.

**Documented** in `docs/sp-okta.md`: the direct admin URL (the menu location varies by plan), the metadata needing an admin session, the 5 kB var limit and why the registry is the better home, and Okta's own authenticator enrollment on first sign-in.

## D-035: Auth0 as a live SP; tolerate ProtocolBinding=HTTP-Redirect (2026-09-26)

An Auth0 free tenant added the example Worker through an Enterprise SAML connection, with requests signed (RSA-SHA256) over HTTP-Redirect. Auth0's SP metadata is public (`/samlp/metadata?connection=…`), so Auth0 was stored in the **D1 registry** with **only `metadata.url`**: no certificates configured, and signed requests required.

**Found (interop):** Auth0's AuthnRequest carries `ProtocolBinding="…:HTTP-Redirect"`. The attribute names the binding for the *Response*, which can't be HTTP-Redirect (Profiles §4.1.2), and Auth0 fills it with its request binding. The IdP refused it (`INVALID_SAML_REQUEST`).

**Fix:** HTTP-Redirect in `ProtocolBinding` is treated as "no preference", and the Response goes by HTTP-POST as always. Other bindings, such as Artifact, are still refused. This is safe because the Response is still only ever posted to an allow-listed ACS URL. Tests cover both cases.

**Result:** Auth0's "Try" signed in and returned the profile:
- `sub: samlp|better-auth|<email>`, from our NameID;
- `given_name` / `family_name`, from the declarative map (`{ field: "name", part: "first" | "last" }`).

Auth0's signed request was verified with the certificate **learned from its metadata URL**, from a registry SP. The `npx better-auth-saml-idp decode --cert` run before the fix also confirmed that Auth0's query signature verifies.

**Auth0 setup notes** (docs/sp-auth0.md):
- The connection must be enabled for an application (in the connection's Applications tab, or the application's Connections tab), otherwise "the connection is not enabled".
- The Sign In URL only saves with "Save Changes" at the bottom of the page.

**Round 2: HTTP-POST signed requests (the D-025 verifier, live).** With Auth0's Protocol Binding switched to HTTP-POST, Auth0 posted an AuthnRequest with an **enveloped XML signature**. The log shows `POST /sso`, then the same-site `GET /sso?cid=…` re-entry. Because signatures are required and the certificate came only from Auth0's metadata, the request passed the full XSW rule set (one direct-child Signature, a single Reference to the root's unique ID, allow-listed algorithms, no comments, configured certificates only), and Auth0 signed in again with the same profile. This is the first live SP exercising the hardened XML-signature verifier.

**Round 3: encrypted assertions.** `encryption` was added to the stored Auth0 config with a D1 `UPDATE`, and no redeploy. Because `metadata.url` is set, the encryption key comes from Auth0's metadata, the rotation path. Auth0 signed in again (01:49:33, past the 60 s registry cache after the update), so it decrypted our AES-256-GCM / RSA-OAEP assertion. Two independent SPs, Okta and Auth0, now decrypt our assertions live, as well as Cloudflare Access.

## D-036: Fuzzing; characters XML can't carry in issued assertions (2026-09-26)

Property-based tests (fast-check, `test/fuzz/`) now cover:
- **the XML signature verifier:** mutated signed values, wrapping, duplicated IDs, moved or duplicated Signatures and random byte flips never verify a different document;
- **every inbound parser:** hostile input only ever produces a `SamlRequestError` / `XmlParseError`, in bounded time;
- **issuance:** a Response built from arbitrary user data is well-formed, schema-valid, and verifies both as built and as sent (UTF-8).

The verifier held. Issuance didn't:
- **C0 controls, U+FFFE/U+FFFF:** the Response failed the XSD ("PCDATA invalid Char value"), which xmldom had accepted.
- **Lone surrogates:** the Response was signed over the JavaScript string, but UTF-8 encoding replaced the surrogate, so the sent Response didn't verify.
- **U+FFFD:** xmldom warns "source encoding issues?"; strict parsers (ours, and node-saml's) reject the document.
- **CR:** parsers read it as LF. Escaping it as `&#xD;` kept the value, but samlify re-serialises before verifying, and its signature check failed.
- **U+0085, U+2028, U+2029:** xmldom rewrites them to LF (XML 1.1 rules; U+2029 from 0.9), and xml-crypto signs over xmldom's view. libxml2 keeps them (XML 1.0), so an xmlsec-based SP would digest different text. (Reasoned from the specs; xmlsec wasn't available to try.)

**Fix:**
- `escapeXml` removes the first three kinds and turns the line endings into LF, as most parsers would read them anyway. Attribute values arrive changed only where they could never have arrived intact.
- The NameID is an identifier, so it is never altered: one containing any of these is refused (`INTERNAL_ERROR`, logged).
- End-to-end tests with samlify cover both cases, and mutation checks confirm the tests fail without each fix.

The byte-flip property also caught its own oracle: flipping base64 padding in `SignatureValue` to a space leaves the same signature bytes, so it still verifies. The oracle now compares only the content outside the Signature.

## D-037: CodeQL findings: a quadratic XML pre-scan, and xmldom's nesting cost (2026-09-26)

The first CodeQL run (security-extended) flagged polynomial regular expressions in `src/saml/xml.ts`, the scan for duplicate expanded attribute names (R3-7) that `parseXmlStrict` runs before xmldom. The warning was measured instead of argued:

| Input (unterminated markup, repeated) | 64 KiB (largest SAMLRequest) | 1 MiB (largest SP metadata) |
|---|---|---|
| `</` | **2,463 ms** | minutes (quadratic) |
| `<!--` | 502 ms | |
| `<!DOCTYPE` | 457 ms | |

The regex rescanned to the end of the input from every `<` looking for a terminator. D-030 had timed it at "under 10 ms for 200 KB of unterminated tags". That was true for the shape it tried, but not for unterminated comments or end tags.

**Reachability: not exploitable in the default configuration.** Every caller runs libxml2 schema validation before `parseXmlStrict`:
- AuthnRequests, LogoutRequests and LogoutResponses, in `sso.ts` and `slo.ts`, before any signature check;
- SP metadata, from `metadata.url` or `serviceProviderFromMetadata`.

libxml2 rejects all of these inputs in 0–7 ms (measured), and the validator refuses anything over 128 KiB. So the quadratic scan only ever saw schema-valid documents, where it is linear. An initial assessment called this a DoS; tracing the call sites showed otherwise.

It is still worth fixing, as defense in depth. `parseXmlStrict` promises linear time on its own, which matters for:
- hosts that replace `schemaValidator`;
- the CLI's `decode`;
- any future caller.

**Fix:** a hand-written scanner, linear in the input:
- constructs are found with `indexOf` from where the last one ended;
- unterminated markup is refused at once (xmldom would refuse it too);
- namespace prefixes resolve through per-prefix binding stacks, O(1) at any depth. The old lookup walked the element stack, which was also quadratic.

The same cases now take 0–12 ms at 64 KiB and at most 71 ms at 1 MiB.

**xmldom itself** turned out to be quadratic in nested namespace declarations: it copies scopes per element. 1 MiB of nesting took 27 s in xmldom alone, and 66 ms at 64 KiB. Validation bounds this in practice (size, and libxml2's own depth limit). Still, **nesting is now capped at `MAX_XML_DEPTH` = 100** before xmldom or xml-crypto see a document. SAML messages nest about 10 deep.

**Tests** (`test/unit/xml-scanner.test.ts`):
- every hostile shape at 1 MiB finishes in under 2 s;
- the depth limit holds at the boundary;
- namespace scopes revert after a child closes and don't leak from self-closing siblings;
- `>` inside attribute values doesn't end the tag;
- a property: generated well-formed trees (comments, CDATA, both quote styles, whitespace, namespaces) are never refused.

**Mutation checks:** the old regex scanner, no depth limit, and no scope pop each fail the tests.

**The other CodeQL findings:**
- **`src/cli/keygen.ts`, file-system race:** harmless, because the write was already exclusive (`wx`). It is restructured anyway so the exclusive create is the only check.
- **`src/client.ts`, `/\/+$/`:** runs on the developer's own `baseURL`. Replaced with a loop anyway.
- **Test and e2e code:** now excluded from CodeQL, because it doesn't ship.
- **`scripts/check-links.mjs`:** a false positive. The stripped text becomes a heading slug and is never rendered.

**SBOM:**
- The release SBOM listed Better Auth's packages, because npm installs peers by default; it now installs with `--legacy-peer-deps`.
- It now also lists **libxml2**, compiled into `wasm/xsd.wasm` and invisible to scanners. Version and source hash are read from the wasm build script, and a CPE lets vulnerability databases match libxml2 CVEs (`scripts/sbom-add-libxml2.mjs`).

## D-038: Observability: event callbacks and an audit-log table (2026-09-26)

Hosts need to know what their IdP did: for audit trails, for SIEM, and for answering "who signed in to payroll yesterday?". Until now there were only log lines.

**Design:**
- **Three callbacks,** one per outcome an auditor asks about:
  - `events.onAssertionIssued`: who, which SP, which NameID, which attribute names (never values), SP- or IdP-initiated, encrypted or not;
  - `events.onDenied`: every refusal, as an error page `code` or a SAML status Response (`SAML_STATUS` with `status`);
  - `events.onLogout`: the IdP session ended by SLO, and the SPs about to be notified.
- **Observers, never gates.** Handlers run through Better Auth's `runInBackground` (`waitUntil` on Workers), so a slow handler never delays the user, and the host's `backgroundTasks.handler` keeps the work alive after the response. A throw or rejection is logged and changes nothing. Access decisions stay in `authorize`, where a throw means *deny*. An observer that could block sign-in would be a second, badly placed gate.
- **One emission point per outcome.** `fail()` and `samlError()`, which every refusal already goes through, now emit `denied`. They take the plugin state, and the compiler found every call site. Refusals carry the SP and user whenever the request identified them.
- **IP address** is read as Better Auth reads it (`advanced.ipAddress.ipAddressHeaders`, `disableIpTracking`), so it matches Better Auth's own session records. `withCloudflare` sets `cf-connecting-ip`.

**Audit table** (`auditLog: { enabled, retentionDays = 90 }`, table `samlIdpAuditEvent`, D1 migration `0005`):
- **Columns:** the queryable fields are columns (`type`, `at`, `spId`, `userId`, `code`, `ipAddress`, `userAgent`, indexed where useful), and the whole event is JSON in `details`, so new event fields need no migration.
- **Anonymous refusals aren't stored.** A refusal that names neither an SP nor a user (a malformed request, an unknown issuer) reaches `onDenied` but not the table. Otherwise anyone could grow the table at will.
- **Retention:** rows expire after `retentionDays` and are swept with the plugin's other expiring rows.
- **Best effort,** like the callbacks: a failed write is logged, and sign-in proceeds. Hosts that need guaranteed delivery forward from the callbacks.

**Tests** (`test/integration/events.test.ts`, Node and workerd/D1; plus the adapter matrix on Postgres, MySQL and MongoDB):
- field contents of all three events;
- three kinds of denial;
- a throwing handler doesn't break sign-in;
- a handler that never settles doesn't delay it;
- events are delivered through the host's background-task handler;
- audit rows, and that anonymous denials are absent;
- retention arithmetic and the sweep;
- no table without the option.

**Mutation checks:**
- storing anonymous denials fails a test;
- not catching handler errors fails a test;
- running handlers outside Better Auth's background tasks fails a test.

That last mutant first survived. The test handler recorded synchronously before its first `await`, so it recorded even without a background task. The handler now finishes after a delay, so only a task the host waits on can deliver it.

## D-039: Third review ("review 4"), two independent reports (2026-09-26)

**How it was run.** Two independent reviews of tag `review-3-baseline` (`c338731`) from the review brief (`docs/review/brief.md`, removed in D-055), each with proof tests.
- **Report A:** six parallel adversarial passes; 18 proof assertions.
- **Report B:** its own branch, with failing tests `r4-1`…`r4-7` that pass once fixed.

**Agreement:** six of B's seven security findings are also in A, found separately. Every proof reproduced at the baseline, and all of them pass now. A's are rewritten as regression tests in `test/review4/r4-*`; B's are kept as written in `test/review4/second-*`.

**Findings and fixes** (A's numbering; B's in brackets)
- **R4-1 (High) [B R4-4]: organizations are user-claimable.** The organization plugin lets any user create an organization by default, naming it anything, and the IdP matched rules by slug and sent every membership as `slugs`/`names`/`ids` attributes. A stranger could claim a slug nobody had created, and a member could create "Administrators".
  - Fixes:
    - With an SP rule, organization attributes now cover only the SP's organization.
    - `only` (ids or slugs) is an explicit allow-list.
    - A warning names claimable configurations (rules by slug, unscoped attributes) when users can create organizations.
    - Docs and examples use ids.
  - Mutation-checked: each part fails a test when removed.
- **R4-2 (Medium) [B R4-5 Low]: revoked sessions still got assertions** with the cookie cache on and sessions only in secondary storage. The issuing endpoints read the cookie cache, and the pre-signing re-read covered only the database.
  - Fixes:
    - `getAuthoritativeSessionFromCtx` on `sso`, `resume` and `init`.
    - The re-read goes to the database whenever it holds sessions (KV is eventually consistent, so the database stays authoritative), and otherwise to secondary storage.
  - A test that revokes between the read and the signing pins the re-read on its own.
  - The first version of this fix read KV even when the database held sessions, and two older tests (stale-KV revocation) caught it.
- **R4-3 (Medium) [B R4-3]: the audit table grew from unauthenticated requests** that named a public SP. D-038's filter only dropped denials naming neither SP nor user. Fix: only denials with a signed-in user are stored.
- **R4-4 (Medium) [B R4-2]: signed-POST verification cost ~200 ms per SP certificate** on a schema-valid 64 KiB message, and a metadata URL chose how many certificates there were. Fixes:
  - protocol messages are capped at 200 elements and 1000 attributes right after parsing;
  - the certificate is picked by checking the SignatureValue over SignedInfo, canonicalised once with xml-crypto's own code, before the one full verification;
  - at most 10 certificates of each kind are taken from metadata.
- **Low:**
  - L1 [B R4-6]: signed AuthnRequests must carry `Destination`, as SLO required.
  - L2 [B R4-7]: the Subject NameID is capped at 1024 characters and its Format at 256.
  - L3: the registry re-reads the user and refuses banned users.
  - L4: sign-out everywhere confirms same-site drive-bys. IdP-initiated sign-in keeps same-site navigations, by design.
  - L5: `prompt=login` goes to the login page under ForceAuthn.
  - L6: `logSafe` strips C1 controls, bidi overrides and invisible formatting characters.
  - L7 [B R4-1]: the pre-scan tokenises tags as XML does: whitespace between attributes, and no control or Unicode space characters in names.
  - L8: registry lookups are exact whatever the collation, and `view()` reports valid only for rows sign-in uses.
  - L9: a warning when attribute maps read user-writable additional fields.
  - L10: releases only from commits on `main`, in a gated `npm` environment; container images pinned by digest.
- **Tests that couldn't fail now can:** the organization guard, the DEFLATE cap, SLO partial logout, and the adapter matrix, which now fails in CI when its database variables are missing.
- **Fuzzing** now also covers the LogoutRequest, LogoutResponse and SP-metadata parsers, as the README claimed.
- **Docs corrected:**
  - Node 22+ (`engines` too);
  - "mutation-checked when written", not an ongoing CI claim;
  - "logged" instead of "audited" for registry changes;
  - release tense;
  - the adapter matrix's real scope;
  - expired certificates warn rather than fail;
  - four tables, migration `0005`;
  - the npm name isn't published yet (don't `npx` it);
  - the Artifact binding wording;
  - samlify decryption is Node-only.

**Open, for the maintainer:**
- the API decisions before 1.0 (client namespace, `export type *`, `options.directory`, booleans vs enums, registry JSON shapes, `baseURL`);
- registering the npm name;
- a reproducible-build check for `wasm/xsd.wasm`;
- repository settings: private vulnerability reporting, reviewers on the `npm` environment, branch protection.

## D-040: API decisions before 1.0 (2026-09-26)

After 1.0, anything public is a semver promise. Review 4 listed six choices that would be breaking to change later. They are taken one at a time, each with its options, and recorded here.

**1. Exported types: an explicit list (option A).**
- **Before:** `export type * from "./types"` published every type, including the plugin's resolved internals: `ResolvedSamlIdpOptions`, which holds a `KeyObject` and startup warnings, and `ResolvedServiceProvider`. Any refactor of those would have been a major version.
- **Now:**
  - The index exports a named list: options, SP config, attributes, callback contexts, events, the validator interface, `StoredServiceProviderConfig`, `SamlIdpErrorCode`.
  - `authorize()` receives `ServiceProviderInfo`, a frozen, read-only view (`id`, `entityId`, `acsUrls`, `nameIdFormat`, `organization`), instead of the internal object.
- **Rejected:**
  - B, marking the internals `@internal`: semver would still see them as public.
  - C, stabilising everything: that freezes internals.
- **Test:** `test/unit/public-api.test.ts` asserts the view's exact keys and that it is frozen. It also uses `@ts-expect-error` on the internal types, so typecheck fails if they are exported again (checked by re-adding `export type *`).

**2. The client namespace: one, `authClient.samlIdp` (option A).**
- **Before:** there were two namespaces.
  - `authClient.saml2.idp.*` was inferred from route paths. It held the registry API, and also the SAML protocol routes as fetch functions, which are browser navigations and pointless to call.
  - `authClient.samlIdp.*` held the hand-written helpers.
- **Now:**
  - The registry API lives at `/saml-idp/service-providers/*`, so its inferred client is `authClient.samlIdp.serviceProviders.*`, next to the helpers.
  - The protocol routes keep `/saml2/idp/*`: SPs are configured with those URLs, so they can never move. They are marked `isAction: false`, so the client doesn't offer them.
  - One prefix is for SAML, and the other is for the app's own API.
- **Rejected:**
  - B, hiding the protocol routes but keeping two namespaces.
  - C, putting the helpers under `saml2.idp`: mixing hand-written actions into the inferred object is fragile.
- **Test** (`test/unit/client.test.ts`):
  - real client calls are asserted to reach `/api/auth/saml-idp/service-providers/*`;
  - `@ts-expect-error` checks that `authClient.saml2` and `authClient.samlIdp.sso` don't exist. Re-exposing `sso` fails typecheck.

**3. No `options` on the plugin object (option A).**
- **Before:** `options: { directory }` exposed the internal SP lookup and cache (a class instance) through `auth.options.plugins`. Nothing in the plugin read it, and nothing documented it.
- **Now:** there is no `options` field. Hosts change SPs through the registry API (immediately); rows edited in the database directly apply within `cacheSeconds`.
- **Rejected:**
  - B, a small `invalidateRegistryCache()` handle: new API for a rare need, and it bends the convention.
  - C, exposing our configuration as `options` like the organization plugin does: it includes the private signing key, readable by every other plugin.
  - D, leaving it.
- **Test:** `test/unit/public-api.test.ts` asserts the plugin object has no `options`.

**4. Honest option shapes: `sign`, `requestSignatures`, plural certificate names (all three as proposed).**
- **Before:**
  - `signResponse` and `signAssertion` were two booleans for a three-way choice. "Both false" had to be rejected by two separate startup checks, one global and one per SP.
  - `requireSignedAuthnRequests: boolean` hid three behaviours, and which one applied depended on whether certificates were configured. With `false` and no certificate, a signed request was accepted without its signature being checked. Logout had its own, separately written `mustSign` rule.
  - `spCertificate` and `metadata.signingCertificate` held lists under singular names.
- **Now:**
  - `sign: "both" | "response" | "assertion"`, both globally (`signing.sign`) and per SP; default `"both"`. "Sign nothing" can't be expressed. `buildSignedResponse` takes the choice directly, and its defensive "encrypted assertion without any signature" branch is gone because it can no longer be reached.
  - `requestSignatures: "require" | "verify-if-signed" | "ignore"`. Its default is derived: `"verify-if-signed"` with `spCertificates` or `metadata`, else `"ignore"`. One value drives both AuthnRequests and logout: logout messages must be signed unless the policy is `"ignore"`, the same outcome as the old `mustSign`. `"require"` and `"verify-if-signed"` without certificates are startup errors, and so is `"ignore"` together with `spCertificates`.
  - IdP metadata advertises `WantAuthnRequestsSigned` only when every SP is `"require"`.
  - `spCertificates` and `metadata.signingCertificates` take one PEM or a list. The old names are unknown keys and are rejected, not ignored.
- **One tightening:** under `"verify-if-signed"` with certificates only from a metadata URL that hasn't loaded, a *signed* AuthnRequest is now refused (`UNSIGNED_SAML_REQUEST`) instead of being accepted unchecked. That matches logout and `"require"`, which already failed closed.
- **Rejected:** keeping the booleans and documenting the hidden cases; accepting only arrays for certificates (clumsy for the common single certificate).
- **Stored SPs:** registry rows use the same JSON, so rows with the old names fail validation. The example's migration `0006_api_decision_4_option_names.sql` rewrites them. It's idempotent, and it was checked on copies of the live demo's okta and auth0 rows, which need it.
- **Tests:** `options.test.ts` (derivation, the three startup errors, old names rejected, single or list); `encrypt.test.ts` (every `sign` value leaves the encrypted assertion signed at least once); `sp-metadata-refresh.test.ts` (`"ignore"` never checks, even with loaded certificates; the new fail-closed case); `metadata.test.ts` (`WantAuthnRequestsSigned` stays false for `"verify-if-signed"`).
- **Mutation proof:** ten mutations, each caught:
  1. drop the `"ignore"` early return;
  2. revert the fail-closed branch;
  3. make logout require signatures only for `"require"`;
  4. always derive `"ignore"`;
  5. sign the assertion only for `"both"`;
  6. drop the per-SP `sign` override;
  7. drop the `"ignore"` + certificates check;
  8. drop the `"verify-if-signed"` needs-certificates check;
  9. advertise `WantAuthnRequestsSigned` for any non-ignore policy (caught after adding the lenient-metadata case);
  10. stop importing `AuthnRequestsSigned="true"` as `"require"`.

**5. One record shape for the registry API (`ServiceProviderRecord`).**
- **Before:**
  - The list returned five fields for code SPs and eleven for stored ones.
  - Get returned 404 for a code SP that the list had just shown.
  - Create and update returned `{ serviceProvider, warnings }`, with `warnings` outside the record, so a stored SP's warnings were visible only at the moment it was saved.
  - Create and update re-read the row after writing it, and returned `serviceProvider: null` with a 200 if that read missed (a read replica, or a case-folding collation).
  - A stored row that clashed with a code SP was reported `valid: false` with an empty `issues` list.
- **Now:**
  - Every route returns `ServiceProviderRecord` (exported), with the same eleven keys for both sources. Code SPs have `config: null`, `issues: []`, `warnings: []` and `null` timestamps.
  - `warnings` is part of the record, recomputed from the stored config on every read.
  - Create and update build the record from what they wrote, with no read-back.
  - Get falls back to code SPs, checking the stored row first because a clashing row is only reachable there. A clash is reported as an issue.
  - Delete still returns `{ deleted: id }`.
- **Rejected:** keeping the per-route shapes and documenting them. That leaves every client handling four shapes and a null that means "saved, but we can't show you".
- **Tests:** `registry.test.ts` ("one record shape on every route"):
  - the exact keys, from list (both sources), get, create and update;
  - get of a code SP;
  - warnings kept in the record;
  - the clash issue;
  - create and update returning the record while every read-back of the row misses. This fails against the old code, which returned `null`.
- **Mutation proof:** five mutations, each caught:
  1. drop `issues`/`warnings` from code records;
  2. get ignoring code SPs;
  3. empty `warnings`;
  4. drop the clash issue;
  5. update overwriting `createdAt`.

**6. `samlIdp({ baseURL })` follows Better Auth's `baseURL` rule.**
- **Before:** the plugin's `baseURL` had to be the full auth base URL (`https://auth.example.com/api/auth`), while Better Auth's `baseURL` is the origin (`https://auth.example.com`), with `basePath` added. A host pasting the same value into both got metadata advertising `https://auth.example.com/saml2/idp/sso`, a URL that doesn't exist, and `Destination` checks against it. Nothing warned.
- **Now:**
  - At `init`, the plugin applies Better Auth's own `withPath` rule, including a custom `basePath`: a bare origin gets `basePath` appended, and a URL with a path is used as it is. The same value works in both places, and existing full-URL values keep working, so nothing breaks.
  - If both are pinned and resolve differently, a startup warning names both; the plugin's value is used.
  - `check-config` shows the resolved URL.
- **Rejected:**
  - Removing the option and always using Better Auth's: hosts that let Better Auth's `baseURL` follow the request (several hosts) could no longer pin the IdP's URLs.
  - Renaming it (`authBaseURL`): the trap would remain for anyone who guesses the meaning from Better Auth.
- **Tests:** `test/integration/base-url.test.ts`:
  - the rule's cases;
  - metadata from an origin value, a custom `basePath`, and the old full-URL form;
  - the mismatch warning.
- **Mutation proof:** four mutations, each caught:
  1. no rule at `init`;
  2. ignoring the custom `basePath`;
  3. dropping the warning;
  4. always appending `basePath`.

## D-041: NameID from a user field (2026-09-27)

Roadmap D4. Stored SPs could only get the default NameID per format (email, persistent HMAC, transient), because a NameID function can't be JSON.

- **Now:** `nameId: { field }` for code and stored SPs. The value is the user field, trimmed; a finite number becomes its digits; anything else is empty, and a user with an empty value is denied (`ACCESS_DENIED`, with the field named in the log).
- **The security rule:** the NameID is the user's identity at the SP. The field must be one users can't set themselves:
  - `id`;
  - `email` (a change goes through verification);
  - an additional or plugin user field declared with `input: false`, and with no declaration allowing input.

  Core `name` and `image` (editable through `/update-user`), unknown fields, and fields declared with input are refused:
  - at startup for code SPs (`SamlIdpConfigError`);
  - on registry create/update (`INVALID_SERVICE_PROVIDER`);
  - at issuance, every time. A field can become writable after a row was saved, or a row can be edited by hand, and such an SP issues nothing (`INTERNAL_ERROR`).

  The registry reports such a row as `valid: false`, with the reason.
- **Stricter than attribute maps:** they only warn about writable fields (R4-L9), because an attribute is data the SP interprets, while the NameID picks the account.
- **Tests:** `test/integration/nameid-field.test.ts` covers the rule's cases (core, additional, plugin, double declaration), value conversion, option shapes, the user id end to end on both runtimes, an `input: false` field with a denied empty user (Node), the startup error, the registry refusal, and a hand-edited row reported invalid that never issues.
- **Mutation proof:** eight mutations, each caught:
  1. drop the issuance check;
  2. drop the registry check;
  3. drop the startup check;
  4. ignore plugin fields;
  5. `some` → `every` for double declarations;
  6. drop `ACCESS_DENIED` for empty values;
  7. drop the registry issue;
  8. allow `name`.

## D-042: Salesforce verified live (2026-09-27)

A free Salesforce Developer Edition org (My Domain `orgfarm-63501b2853-dev-ed.develop.my.salesforce.com`) as the SP, and the deployed Workers example as the IdP.
- **Setup:** Salesforce SAML SSO configuration "Better Auth demo". The IdP certificate is from the live metadata (CN "better-auth-saml-idp-example (rotation 3)"); identity type Federation ID in the NameID; HTTP-Redirect requests signed RSA-SHA256; no encryption; Salesforce MFA off.
- **Registry:** Salesforce was registered in the D1 registry from its downloaded metadata (`sp-from-metadata`):
  - the entity ID was the value the admin entered (a `…salesforce-setup.com/` URL: any stable value works);
  - the ACS was the My Domain URL;
  - `requestSignatures: "require"` came from `AuthnRequestsSigned="true"`, with Salesforce's self-signed certificate.
- **Checks:**
  - before the browser test, an unsigned probe got `UNSIGNED_SAML_REQUEST`, proving the row loaded with the new API-decision-4 names;
  - the maintainer then signed in from the My Domain login button in a private window and landed in Salesforce, with the Federation ID set to the demo account's email.

  That exercises Salesforce's signed Redirect request, verified with a certificate from the registry, and our signed Response and Assertion accepted by a strict commercial SP.
- **A real interop bug, found live and fixed:** Salesforce's AuthnRequest IDs are about 300 characters (296 in the captured request), and the parser capped `ID` at 256. So the SP-initiated button failed with `INVALID_SAML_REQUEST`. The first successful sign-in didn't go through that path.
  - xs:ID has no length limit. The cap is now `MAX_SAML_ID_LENGTH = 1024`, for AuthnRequests and LogoutRequests.
  - The ID is stored as text, which is unbounded on every Better Auth dialect: `text` on MySQL, because the field has no index. Replay detection keys on a fixed-length hash of it.
  - `test/integration/long-request-id.test.ts` replays the captured Salesforce ID end to end (`InResponseTo` echoed), checks the 1024 and 1025 boundary, and checks LogoutRequests. Three of its tests fail against the old cap.
  - The cap had no test at all before, which is how it slipped through three reviews.
- **Single Logout, verified both ways** (Workers logs captured with `wrangler tail`):
  - The logout endpoint (`/services/auth/sp/saml2/logout`, from the SSO settings' Endpoints) was added to the registry row by hand. The downloaded metadata had none, because Single Logout wasn't saved in Salesforce yet.
  - **IdP-initiated** (`/saml2/idp/logout`): our signed LogoutRequest went to Salesforce, Salesforce answered at `/slo` with a LogoutResponse, and the Salesforce session was gone.
  - **SP-initiated** (Log Out in Salesforce): Salesforce's signed LogoutRequest reached `/slo`, was verified against its registered certificate, and ended the demo session.
  - An earlier "SP-initiated" attempt was *not* counted. At the time, the login button wasn't enabled and the ID bug was still live, so that session never came from SAML.
- **Salesforce-side traps hit on the way** (now in the guide):
  - "SAML Enabled" wasn't saved, so the IdP didn't appear in My Domain's Authentication Configuration;
  - "Single Logout Enabled" was off, so Salesforce said "We are unable to log you out";
  - the Federation ID wasn't set, so the SAML Assertion Validator passed every check but said "Unable to map the subject to a Salesforce user".

## D-043: Sessions that end without Single Logout (2026-09-27)

From a fresh-eyes design review for a host integration: an admin disable or a factor change deletes sessions with no browser, so SPs can't be told through the front channel.

- **Already guaranteed (verified in code, pinned by a test):** no new assertion once the session or user is gone. Issuance re-reads both from the database.
- **New: `events.onSessionEnded`.** A `session.delete` database hook marks the session's participant rows ended, and emits `session.ended`:
  - `{ userId, sessionId, reason: "revoked" | "signed-out" | "expired", participants: [{ spId, entityId?, nameId, nameIdFormat, sessionIndex }] }`.
  - It uses the `AuthContext` captured in `init`, never the hook's context. That context is undefined outside endpoints, which is exactly the admin-page case; the oauth-provider's own logout hook bails out there.
  - The plugin's own Single Logout marks the session first, so its SPs, which are about to be told, aren't reported.
  - The hook is an observer: errors are logged and never block the delete.
  - Nothing is emitted for sessions with no participants.
  - Audit: `revoked` and `signed-out` rows only; `expired` never.
- **Found while building, missed by the review:** Better Auth deletes sessions stored only in `secondaryStorage` without database hooks (`internal-adapter.mjs` `deleteSession`). The plugin warns at startup in that setup. better-auth-cloudflare forces database sessions when geolocation tracking is on, and hosts like the example keep sessions in D1.
- **Tracking:** `sessionTracking = singleLogout.enabled || events.onSessionEnded`. `onSessionEnded` alone records participants, so hosts without SLO get the event.
- **Schema:** participant rows gain `userId` (indexed) and `endedAt`. D1 migration `0007` (test D1: `0006`). Ended rows stay until `expiresAt`. SLO ignores them. `sso` and `init` sweep them too when tracking is on.
- **`auth.api.samlIdpListSessionParticipants({ body: { userId } })`** lists a user's SP sessions, live or ended. It's `createAuthEndpoint.serverOnly`: no URL.
  - Checked: in Better Auth 1.7, `metadata.SERVER_ONLY` only hides a route from OpenAPI; a pathed endpoint would still have been routable.
  - The results are filtered by an exact `userId` match, as `findRow` is (R4-L8).
- **`sessionNotOnOrAfter`:** `false | "idp-session" | { maxSeconds }`, global and per SP (code and stored), default `false`. The value is `min(session expiry, now + maxSeconds)`. It's schema-valid on the AuthnStatement.
- **Deferred:** SOAP back-channel SLO. Only Shibboleth SP and SimpleSAMLphp accept it; build it when a named SP needs it.
- **Tests** (`test/integration/session-ended.test.ts`, both runtimes):
  - an out-of-band `deleteUserSessions` with no request, with both SPs, NameIDs and SessionIndexes, and no assertion afterwards;
  - ended rows kept and listed per user, isolated between users;
  - the listing not reachable by URL;
  - SLO not double-reporting;
  - `/sign-out` giving `signed-out`, audited;
  - an expired session giving `expired`, not audited;
  - a failing read not blocking the delete;
  - tracking without SLO;
  - the storage warning, and no warning when geolocation forces database sessions;
  - no event without participants;
  - SLO skipping ended rows;
  - `sessionNotOnOrAfter`: absent, `"idp-session"`, `maxSeconds` (capped, XSD-valid), a per-SP override, and stored-SP validation.
- **Mutation proof:** twelve mutations, each caught:
  1. the hook ignoring the SLO marker;
  2. SLO not marking;
  3. no `signed-out`;
  4. no `expired`;
  5. auditing `expired`;
  6. no try in the hook;
  7. SLO reading ended rows;
  8. tracking ignoring `onSessionEnded`;
  9. no cap at the session end;
  10. no per-SP override;
  11. `userId` not recorded;
  12. no storage warning.

## D-044: `authorize` can give a reason and ask for re-authentication (2026-09-27)

From the same review, to fit a host's policy gate that answers `{ allow } | { allow: false, reason, reauthenticate? }`. It lands before 1.0 because it widens a public return type. That's additive: `true` still works.

- **Return type:** `AuthorizeResult = boolean | { allow: true } | { allow: false; reason?; reauthenticate? }`. Only `true` and `{ allow: true }` allow. Truthy non-`true` values and malformed objects deny, as before.
- **`reason`:** appended to the denial detail. It's log-safe here, for the info line, and again in `fail()`, for events and logs.
- **`session`:** `authorize` now receives the session row re-read just before signing: the same read that proves the session still exists. So host fields such as `mfaCompletedAt` are current.
- **`reauthenticate: true`:**
  - IsPassive gets `Responder/NoPassive` to the ACS.
  - If this request already forced a fresh sign-in and the new session is still refused (`request.forceAuthn && session.createdAt >= request.createdAt`), the result is `ACCESS_DENIED`, with no loop.
  - Otherwise the request is re-parked with `forceAuthn: true, createdAt: now`, and the user goes to the login page with `prompt=login` (the existing ForceAuthn path). Resume refuses any session older than that (`REAUTHENTICATION_REQUIRED`), then `authorize` runs again.
- **Not done:** an SP `label` in `ServiceProviderInfo`. `id` serves as the label. Also not done: an opt-in to send the denial to the SP as `RequestDenied`.
- **Tests:**
  - `{ allow: true }`;
  - a reason in the event (with a newline);
  - reauthenticate going to login with `prompt=login`, the stale return refused, and the reason logged on one line;
  - a fresh sign-in completing the original request (`InResponseTo`);
  - the loop guard;
  - IsPassive giving NoPassive;
  - malformed verdicts denying.
- **Mutation proof:** seven mutations, each caught:
  1. `{ allow: true }` rejected;
  2. no reason;
  3. no `logSafe`. This survived until the log-line test was added: `fail()` sanitises events, but not the info log;
  4. no loop guard;
  5. no IsPassive branch;
  6. parking without `forceAuthn`;
  7. truthy values allowed.

## D-045: Identity broker verified: `@better-auth/sso` upstream, this plugin downstream (2026-09-27)

One Better Auth instance running both plugins, tested end to end in `test/interop/broker.test.ts` (Node and workerd):
- the upstream IdP is this plugin on the test host;
- the broker runs `@better-auth/sso`, with the upstream in `defaultSSO`, and `samlIdp` with its own key;
- the downstream SP is node-saml, with signed Response and Assertion required and `InResponseTo` validated.

The flow:
1. The app's AuthnRequest reaches the broker, and the broker parks it.
2. The login page's `signIn.sso({ callbackURL: <resume> })` goes upstream.
3. The upstream Response reaches the broker's ACS, which creates the session and redirects to the resume URL.
4. The broker issues to the app. node-saml validates it: the NameID is the upstream user's email, and the issuer is the broker.

- **Finding:** `@better-auth/sso` creates users with `emailVerified: false`, and its `mapping.emailVerified` only applies with the deprecated `trustEmailVerified`. So the broker's default account policy refuses them (`EMAIL_NOT_VERIFIED`), as a test pins.
  - Documented fix: `provisionUser` marks users verified for named, trusted providers only.
  - Tested alternative: `requireEmailVerified: false`, documented as the broader choice.
- **Test note:** node-saml requests `PasswordProtectedTransport` by default. The broker claims `unspecified`, since how the user authenticated was decided upstream. So the test app sets `disableRequestedAuthnContext`. A real broker should set `authnContextClassRef` to what its upstreams guarantee.
- The guide page `docs/guide/better-auth-sso.md` described the broker before this test existed. It now carries the tested recipe.

## D-046: Pre-release review (2026-09-27)

Before the first release candidate, two independent reviews ran over everything since the last review (4a44664): a security review and a docs/API consistency review. The mechanical checks alongside them:
- the packed tarball's contents;
- publint and Are the Types Wrong;
- a fresh-project install of the tarball with Better Auth 1.7.6: CLI keygen, a login verified by node-saml;
- `npm audit` of the runtime dependencies (0 vulnerabilities; 16 packages, all MIT);
- the full-history secret scan;
- a release dry run (workflow_dispatch: tests, pack and SBOM passed; publish skipped).

**Security review:** no Critical, High or Medium findings. Fixed:
- **L-1:** a logout whose session delete failed left the "ending by SLO" marker, so a later revoke of that session emitted no `session.ended` and left its rows looking live. Now the marker is cleared when the delete throws, and a marker over a minute old is ignored. Regression tests reproduce the reviewer's scenario.
- **L-2:** `requestSignatures: "ignore"` with a metadata URL makes logout rest on SessionIndex alone, since the metadata's signing certificates are never checked. This corrects D-040 decision 4's "same outcome as the old `mustSign`": the old rule forced signing whenever metadata was set. The combination is legitimate (metadata used only for the encryption certificate), so it gets a startup warning rather than an error.
- **L-3 (example):** the admin page now re-reads the user from the database, refuses impersonated sessions and bypasses the cookie cache, as the registry API does.
- **S-2:** the per-user participant list and `session.ended` were cut at 200 without saying so. Both now carry `truncated`; every row is still marked ended.
- **Info:**
  - `logSafe` also strips U+2028 and U+2029;
  - the admin `from-metadata` route checks Content-Length before parsing;
  - an inline style the admin CSP blocked was moved to a class.
- **S-1 (documented):** "signed in again" means a session newer than the request. Hosts with credential-less session minting (`device-authorization`, `bearer`) should have `authorize` check a field their real sign-in sets. This was already true of ForceAuthn.

**Also found by the checks:**
- CI had been red since the broker test: gitleaks flagged a fake test secret. The allow-list now covers the fixed test-secret pattern.
- samlify printed "missing endpoint of SingleLogoutService" on every IdP without SLO; that one message is now filtered during construction.
- The release workflow now tags pre-releases `next` and marks them as GitHub pre-releases.

**Docs/API review:** every must-fix was fixed (98bc59d):
- stale "waits for / requires better-auth-cloudflare 0.4" claims (the plugin doesn't depend on it; 0.3.1 works with verification and rate limits in the database);
- the release-candidate install instructions;
- a documented `serviceProviders.list` call that doesn't exist;
- snippets that didn't type-check;
- missing options in the README;
- schema reference gaps;
- the CHANGELOG, rewritten as first-release notes.

**Mutation proof:** five mutations for the fixes, each caught:
1. no unmark on failure;
2. no marker age check;
3. no L-2 warning;
4. no separators in `logSafe`;
5. no `truncated`.

## D-047: Step-up authentication (2026-09-27)

Roadmap D3 ("map RequestedAuthnContext to the host's 2FA state, as Keycloak does with levels of authentication"). The roadmap expected an upstream change: Better Auth sessions don't record how the user authenticated. Instead, the host says it: `authnContext: { levels, current }`.
- **`levels`:** AuthnContextClassRef URIs the host's sign-in can deliver, weakest first (1–10, unique). This is the ordering SAML itself lacks.
- **`current({ user, session })`:** the class this session achieved. It runs on the user and session re-read just before signing, and must return one of `levels`; anything else, or a throw, gives `INTERNAL_ERROR`.
- **Matching:** `satisfiesAuthnContext` implements SAML Core §3.3.2.2.1 on that order:
  - `exact`: the achieved class is listed;
  - `minimum`: at least as strong as a listed class;
  - `better`: stronger than a listed class;
  - `maximum`: no stronger than a listed class.

  Classes outside `levels` only match exactly, and DeclRefs never match. `stepUpTarget` is the weakest level that would satisfy the request.
- **Flow:**
  - **At request time:** a RequestedAuthnContext that no level can satisfy gets `NoAuthnContext` at once. Otherwise the request, with its context, is stored with the pending request.
  - **At issuance:** if the achieved class satisfies the request, the assertion states the achieved class. If not, but a level can:
    - `NoPassive` for IsPassive;
    - the loop guard (the request already forced a fresh sign-in, and the session is newer) gives `NoAuthnContext`;
    - otherwise the request is re-parked as ForceAuthn from now, and the user goes to `loginPage?…&prompt=login&acr_values=<target>` (OpenID Connect's parameter name, so login pages can share handling).

  This reuses the ForceAuthn and D-044 re-authentication path. Resume refuses sessions older than the re-park.
- **Exclusive with `authnContextClassRef`:** a fixed class keeps the previous behaviour exactly.
- **Caveat, documented:** a session only proves what `current` says. Better Auth's two-factor plugin creates sessions after the second factor, but "trust this device", or credential-less session minting (D-046 S-1), can bypass it. Hosts should record when the factor was actually completed.
- **Tests** (`test/integration/step-up.test.ts`, both runtimes):
  - the comparison table, including the equal-level boundaries;
  - step-up targets;
  - config validation;
  - end to end:
    - no request states the achieved class;
    - minimum MFA on a password session goes to login with `prompt=login` and `acr_values`, a stale return is refused, and after MFA it's issued as MFA;
    - an already sufficient session is issued at once;
    - the loop guard gives `NoAuthnContext`;
    - IsPassive gives `NoPassive`;
    - an unreachable class is refused before any sign-in round (signed out);
    - `current` returning an out-of-levels class, or throwing, gives `INTERNAL_ERROR`.
- **Mutation proof:** eleven mutations, each caught:
  1. minimum `>`;
  2. better `>=`;
  3. maximum `<`. This survived until the equal-level rows were added;
  4. unknown classes compared by level;
  5. no early refusal;
  6. no loop guard;
  7. no IsPassive branch;
  8. no `acr_values`;
  9. the achieved class not asserted;
  10. no levels check;
  11. no exclusivity check.

## D-048: Review 5 fixes (2026-09-28)

An external review of everything since 4a44664 (`docs/review/review-5-findings.md`, proof tests in `test/review5/`, kept as regression tests). It found no Critical or High issues, and confirmed the D-046 fixes. Two Medium step-up gaps: D-047 was new, and its own tests hadn't exercised a park before issuance.
- **R5-1 and R5-2 (Medium):** `acr_values` was only sent when step-up itself re-parked. The first park (no session), a ForceAuthn park and `authorize()`'s reauthenticate park didn't carry it. So a ForceAuthn + RequestedAuthnContext SP ended in `NoAuthnContext` after one uninformed password round, and after a reauthenticate round step-up was refused without its own round.
  - **Fix** (the reviewer's second option): `parkForLogin` computes the step-up target from the stored RequestedAuthnContext on every park, so the login page always hears the level. One round is enough for a page that honours `acr_values`, and the loop guard, which keys on "already sent to sign in for this request", stays fair.
  - The R5-2 proof test encoded the other option (step-up gets its own round even after an uninformed round). It was adapted to this fix: the reauthenticate redirect carries `acr_values`; a page that honours it gets the assertion in one round; a page that ignores it gets `NoAuthnContext`.
- **R5-3 (Low, privacy):** participant rows, with their NameID, outlived a deleted user until the old session's expiry. A `user.delete.after` hook now deletes them by `userId`, after the session hook has reported them; it's an observer. The personal-data note in `observability.md` names the table.
- **R5-4 (Low):** `Comparison="maximum"` below the achieved level sent the user to a sign-in round that can't lower what `current()` reports. It's now answered `NoAuthnContext` at once (the conservative reading).
- **R5-5 (Info):** RequestedAuthnContext is bounded before it's stored with the pending request: at most 16 class refs of at most 1024 characters (`INVALID_SAML_REQUEST`), as the Subject was bounded (R4-L2).
- **R5-6 (docs):**
  - `SECURITY.md` supported versions (release candidates on `next`);
  - the ci.yml Keycloak version;
  - `flows.md` on `acr_values` for every park, and on `maximum`;
  - `observability.md` personal data.
- **R5-7 (tests):** a Playwright spec, `e2e/browser/admin.spec.mjs`, opens the example's `/admin` in Chromium on workerd. It covers the non-admin refusal; IdP details; add from metadata, save, disable, delete; and no CSP violations. The e2e IdP gets `SAML_REGISTRY_ADMINS`.
- **R5-8 (admin page):** the registry update now also takes `{ id, enabled }` alone. It only flips the switch, with no re-validation, so an invalid row can be disabled, and its config is untouched. `serviceProvider` became optional on update, which is additive. The admin page's Enable/Disable uses it.
- **Mutation proof:** five mutations, each caught:
  1. `acr_values` only on the step-up park;
  2. parking for `maximum`;
  3. no user-delete cleanup;
  4. no class-ref cap;
  5. switch-only updates re-validating.


## D-049: CI runners pinned to ubuntu-24.04 (2026-09-28)

GitHub moves `ubuntu-latest` to Ubuntu 26 from 2026-10-19 (actions/runner-images#14748). Every job in every workflow now runs on `ubuntu-24.04`, which is what `ubuntu-latest` means today, so nothing changes now. The wasm reproducibility check (`wasm/xsd.wasm` rebuilt byte-for-byte), the e2e Docker stack and the release build should change image only deliberately. To move to Ubuntu 26: change all 13 `runs-on` lines together, run CI, the e2e and a release dry run, and record it here.

## D-050: OpenSSF Scorecard (2026-09-28)

The published Scorecard was 6.7. Fixed:
- **Pinned-Dependencies (8/10):** two npm installs weren't pinned by hash, both in `release.yml`.
  - The npm CLI for `npm stage` now installs with `npm ci` from `.github/npm-cli/package-lock.json`, verified by integrity. Dependabot watches that directory.
  - The SBOM tree is now `pnpm deploy --prod` from the repo's frozen lockfile, rather than a fresh `npm install` of the tarball.
- **Signed-Releases (0/10):** releases now carry a signed SLSA provenance of the tarball, `<tarball>.sigstore.json` (actions/attest-build-provenance, pinned by SHA). For 1.0.0-rc.1, npm's own provenance bundle was attached after the fact. Its signed subject digest equals the release tarball's sha512, from `release.yml` at `refs/tags/v1.0.0-rc.1` on a GitHub-hosted runner.
- **CII-Best-Practices (0/10):** needs the maintainer to claim the badge at bestpractices.dev. Answers are prepared in `docs/review/openssf-best-practices.md`.

**Out of reach for a single-maintainer project**, recorded rather than gamed:
- Code-Review needs approved pull requests from a second person.
- Contributors needs contributors from several organizations.
- Maintained scores 0 until the repository is 90 days old.
- Branch-Protection at maximum needs required reviews, which would block the only maintainer.
- Binary-Artifacts flags `wasm/xsd.wasm`: deliberate and checked, since CI rebuilds it byte-for-byte from source (wasm-reproducible.yml).

## D-051: Adapter matrix with Drizzle and Prisma; Bun and Deno (2026-09-28)

From the "Reach, trust and B2B" roadmap lane: prove the plugin on the stacks most Better Auth apps use.
- **Drizzle on Postgres and MySQL, and Prisma 6 on Postgres,** join the CI adapter matrix (`test/adapters`), running the same 10 database-dependent tests as Kysely and MongoDB:
  - a full sign-in;
  - replay under concurrency, and the unique key;
  - single-use resume;
  - the registry race and exact lookups;
  - participants;
  - organization memberships;
  - the sweep.
- **Schemas are built, not hand-written.** `test/adapters/orm-schemas.ts` turns Better Auth's `getAuthTables(options)` (core, admin and organization plugins, and this plugin) into Drizzle pg/mysql tables and a Prisma schema, as `npx auth generate` would. They follow any future table change automatically.
  - Tables are created by Better Auth's own migrator, and column types follow it (varchar(255) for keyed MySQL columns, timestamptz on Postgres).
  - Prisma's client is generated per run into `node_modules/.cache`, so it resolves the installed `@prisma/client`; Prisma 6 bundles its engine, so no install scripts are needed.
  - `prisma` and `@prisma/client` are dev dependencies only.
- **Verified locally:** against Postgres 17 and MySQL 8.4 containers, each of drizzle-postgres, drizzle-mysql and prisma-postgres passes 10/10, and plain postgres and mysql still do.
- **Bun and Deno:** `test/runtimes/smoke.mjs` is plain JavaScript on the built `dist/`. It runs the CLI's `keygen` on the same runtime, then Better Auth with the plugin on the memory adapter: metadata, sign-up, an SP-initiated HTTP-Redirect sign-in, and the Response signature verified with xml-crypto. It passes on Node 24, Bun 1.4.2 and Deno 2.9.6.
- **CI:** a `runtimes` job, bun and deno, with `oven-sh/setup-bun` and `denoland/setup-deno` pinned by SHA.
- **Scope:** a smoke test, not the whole suite. The suite needs Vitest's Node and workerd pools, and Better Auth's own runtime support is Bun's and Deno's Node compatibility.

## D-052: Multi-tenant IdP, phase 1: an IdP identity per organization under the shared key (2026-09-28)

The roadmap item "One IdP identity per organization", built as phase 1 of `docs/design/multi-tenant.md` (then `docs/review/multi-tenant-design.md`), on the maintainer's decisions in its §9: host administrators create tenants; membership is mandatory; `tenantKey` defaults to the organization id, may be chosen at creation, never changes; KMS/HSM deferred. Phases 2 (per-tenant keys) and 3 (delegation) are not built. Guide: `docs/guide/multi-tenant.md`.

**What it is.** `tenants: { enabled: true }`, off by default.
- A tenant is an organization with a `samlIdpTenant` row, created through the registry API (`/saml-idp/tenants/*`, the `samlTenant` access-control resource). Its entity ID is its metadata URL; its URLs are `/saml2/idp/{metadata,sso,slo}/<tenantKey>`. All tenants sign with `signing` (`keys: "shared"`, the only value).
- SPs join one with `tenant` (code or stored). `spId` stays globally unique, so replay keys, SessionIndexes, participants, pending requests and audit rows are unchanged; entity IDs are unique per tenant through `lookupKey` (a hash of tenant and entity ID, UNIQUE), so AWS or Google can be in several tenants.

**Isolation doesn't rest on the SP checking Issuer.**
- The URL decides the identity. An entity ID is looked up in the URL's tenant only: code SPs by `(tenant, entityId)`, stored SPs by `lookupKey`, then the loaded row must be of that tenant with exactly that entity ID (a hand-edited key can't cross tenants). The root URLs find root SPs only.
- Beyond the design: a request carries the tenant of the **URL** it came to (not of the SP found), and issuance refuses it when the SP's current tenant differs. A lookup that ever crossed tenants would still get nothing (a second layer; mutation 3 below shows the first layer is tested on its own).
- `Destination` is checked against the URL the request arrived at. A POST continuation re-entered at another tenant's URL, or the root's, is refused.
- A disabled or deleted tenant: its URLs answer like an unknown one; its SPs get nothing through any route (IdP-initiated included); Single Logout skips them (`PartialLogout`). Never the root identity instead.

**`IdpIdentity` (design §5.8).** `src/saml/identity.ts` builds `{ tenantId, tenantKey, entityId, signing, ssoUrl, sloUrl, metadataUrl }` for the root or a tenant. Responses, error Responses, logout messages and metadata take an identity, not `options`. `test/unit/identity-lint.test.ts` fails if any other source file reads `options.entityId` or the signing key (option resolution, the CLI and the SP-metadata importer's own `options.entityId` are allowed). It's internal: not exported.

**The rest of phase 1, as designed.**
- Membership of the tenant's organization is implied and can't be turned off; an `organization` rule on a tenant SP may only be `{ id: <its tenant>, roles? }` (a slug or another id is refused). Issuance also refuses a tenant SP whose rule is missing (defence in depth). Organization attributes without `only` then cover the tenant's organization only.
- Persistent NameIDs of tenant SPs: `HMAC(secret, "saml-idp:persistent\0" + tenantId + "\0" + entityId + "\0" + userId)`; the root's derivation is unchanged.
- SLO: each participant gets its LogoutRequest from its own tenant's identity, the originator its LogoutResponse from its own, and a participant's answer is checked against its own tenant's SLO URL (it may arrive at any SLO URL; the hop is in its RelayState).
- Startup errors: no organization plugin, no pinned base URL (samlIdp's or Better Auth's, including `BETTER_AUTH_URL`; with only Better Auth's, the plugin pins it), `tenants.delegation` (needs `keys: "per-tenant"`), `keys: "per-tenant"` (not available yet).
- The host-administrator overlap warning (design §5.1 c): an SP with the same entity ID **and** an ACS URL as an SP in another tenant or the root. At startup for code SPs; in the registry record's `warnings` and the log for stored ones.
- `tenantId` in `assertion.issued`, `denied` and `logout` events and each `session.ended` participant (absent for the root IdP, so root events are unchanged), an audit-log column, `ServiceProviderInfo.tenantId` (`null` for the root; `public-api.test.ts` updated deliberately), and registry records (only with tenants on). The login page gets `tenant=<tenantKey>` on the redirect from a tenant's request.
- Tenant metadata: 404 identical (status, content type, body) for an unknown key, a disabled tenant, an organization that isn't a tenant and a malformed key; no organization name or slug in the document.

**Byte-identical when off.** `test/integration/tenants-off.test.ts` was committed first (`edde4bf`), its snapshots recorded from the code before any tenant change: metadata (plain; signed with SLO; with a rotation certificate), the signed Response and its auto-POST page, the persistent NameID derivation, the POST binding's 303, the login redirect, a NoPassive Response, an error page, an IdP-initiated Response, a LogoutRequest to a POST participant and the LogoutResponse to the originator, and the plugin's schema and routes with every optional feature on and off. Only per-run values are normalised (certificates, random IDs, instants, digests, signature values, nonces, tokens); signatures are verified. They pass unchanged after every commit, on both runtimes, with `CI=true` (snapshots can't be rewritten).

**Choices the design left open, or where it was changed (the safer option each time).**
1. **Tenants need `registry.enabled`.** Tenants and their stored SPs live in the database and are managed through the registry API; the design didn't say. A startup error otherwise.
2. **`lookupKey` is required, not nullable.** Better Auth refuses a UNIQUE table-level index on an optional field, and without that index MongoDB doesn't enforce uniqueness (D-033). Checked: removing the index entry lets concurrent duplicates in on MongoDB. The cost: Better Auth's migrator won't add a required column to a populated table, so a registry with rows adds it nullable by hand, runs the migrator, backfills, then sets NOT NULL. Verified by hand on Postgres 17 and MySQL 8.4 containers, and by the SQLite tests.
3. **The backfill is a server-only endpoint, `auth.api.samlIdpBackfillServiceProviderKeys()`,** not D1 SQL plus a CLI helper as the design suggested: the key can't be computed in SQL (SHA-256 isn't in SQLite/D1, and Postgres text can't hold the NUL separator). Rows without a key are found by no lookup until then (no lazy dual path, as the design wanted), and their registry records say so.
4. **The old `UNIQUE(entityId)` stays** on databases that had the registry (the migrator never drops it), so a second tenant's copy of an entity ID gets 409: the safe direction, tested. The guide gives the SQL to drop it, with the constraint and index names Better Auth's migrator actually creates, checked on Postgres 17 and MySQL 8.4, and the D1 table rebuild, which `tenants-shared-entity.test.ts` applies. The test D1 keeps the constraint (tenants-off tests rely on it); migration `0007_tenants.sql` there also adds the organization plugin's tables, so tenant tests run on workerd.
5. **The overlap warning** needs the same entity ID and a shared ACS URL: with different ACS URLs no assertion can land at the other SP.
6. **Registry records carry `tenantId` only with tenants on**, to keep responses unchanged without them; `ServiceProviderInfo` always has it, as the design says.
7. **A code SP's tenant must exist (and be enabled)** in the database to be used; otherwise its sign-ins are refused.
8. **Not built from the design's lists:** `canManage` receiving `tenantId` (§5.4; for phase 3, and not knowable for every route before the row is loaded, which would turn 403s into an existence oracle), `keys` in `TenantRecord` (phase 2), the CLI's `--tenant` options (§6; not in §7's phase-1 list).

**Tests** (`test/integration/tenants.test.ts`, `tenants-shared-entity.test.ts`, `tenants-off.test.ts`, `test/unit/sp-directory.test.ts`, `identity-lint.test.ts`, `client.test.ts`; Node and workerd except the lint test):
- configuration and startup errors;
- one entity ID in tenants A and B (in code, and stored): each URL's Issuer, verified by samlify against that tenant's metadata; an SP pinned to A refusing B's assertion (`ERR_UNMATCH_ISSUER`: what the shared key leaves to the SP);
- lookups per tenant in each direction and at the root; `Destination` of A at B; replay per SP; unknown and disabled tenants; the POST binding at a tenant URL; the continuation at another URL; the login redirect's `tenant`; IdP-initiated; a request whose SP changed tenant before resume;
- membership, roles, attribute scoping, `authorize`'s `tenantId`;
- metadata (XSD-valid, signed, no organization name, identical 404s);
- SLO across A, B and the root, the participant Destination rule, a disabled participant's tenant, a LogoutRequest at another tenant's URL;
- events and audit rows; the tenant API (CRUD, immutability, refusals, 403 for non-managers and for the organization's own owner, the `samlTenant` permission); stored SPs (tenant, filtering, immutability, overlap warning); the upgrade and backfill path.
- **Adapter matrix:** a tenants block on a second fresh database (the `lookupKey` race, one entity ID in two tenants, per-tenant lookups, tenant booleans). Run locally against Postgres 17, MySQL 8.4, Drizzle on both, Prisma on Postgres and MongoDB 8.2: 11/11 each.
- **Full suite:** 139 files passed, 10 skipped; 1324 tests passed, 58 skipped (before: 132 files, 1218 passed, 54 skipped).

**Mutation proof** (each broken on purpose, a test failed, restored with `git checkout`):
1. stored lookup without the row-tenant re-check (unit test);
2. code-SP lookup ignoring the tenant (7 tests on Node, 4 on workerd);
3. a tenant URL falling back to root code SPs, and the root URL finding tenant SPs (unit tests: the flow tests pass because issuance's tenant check refuses both, see 4);
4. issuance's request-tenant check removed (resume after the SP changed tenant); with 3 as well, the root-URL test fails too;
5. implied membership removed (16 tests, via the issuance guard); with the guard removed too, non-members are admitted (3 tests). The guard alone removed: nothing fails, as expected of a second layer;
6. persistent NameID without the tenant; and the root's with it (tenants-off snapshot test);
7. participants' LogoutRequests from the root identity; 8. the originator answered from the root identity; 9. a participant's answer checked against the route's SLO URL;
10. a missing tenant resolving to the root identity: **survived at first** (issuance refuses anyway), then caught once the disabled-participant SLO test was added (Single Logout uses the identity directly);
11. the delegation gate; 12. the pinned-baseURL check; 13. the organization-plugin check;
14. disabled tenants treated as enabled (4 tests); 15. an SP's tenant changeable on update; 16. an SP in an organization that isn't a tenant;
17. the tenant update body not strict; 18. deleting a tenant that has SPs; 19. the continuation's route check;
20. no overlap warning; 21. the directory's tenant-column check; 22. the tenant lookup's exact-match check;
23. a hard-wired `state.options.entityId` in SLO (the identity lint test); 24. a slug rule on a tenant SP accepted;
25. the audit `tenantId` column dropped; 26. tenant routes checked against `samlServiceProvider`; 27. no manager check on tenant create;
28. SLO lookup crossing tenants; 29. `Destination` compared with the root SSO URL; 30. the `lookupKey` index entry removed (MongoDB matrix); 31. the SLO continuation's route check (a POST LogoutRequest re-entered at another tenant's SLO URL).

**Not verified:** a live interop run with real SPs in two tenants (design §8, "Interop, live"); the upgrade steps on a populated MongoDB collection.


## D-053: Review 6 fixes (2026-09-28)

An external review of multi-tenant phase 1 (D-052) and everything since 1.0.0-rc.1 (`docs/review/review-6-findings.md`, proof tests in `test/review6/`, kept as regression tests). Isolation between tenants held; the findings were at the edges of a tenant's life, the MongoDB upgrade, and release plumbing.
- **R6-1 (Medium):** a tenant was tied to an organization id only. A deleted organization's tenant stayed enabled, and with serial ids (SQLite, D1) the next organization created got the freed id and, with it, the tenant's identity and SPs.
  - **Fix:** the tenant row stores the organization's `createdAt` (`organizationCreatedAt`). Routing and issuance load the organization with the tenant (cached together) and treat the tenant as absent when the organization is gone, or its id now belongs to an organization with another `createdAt`. This covers an organization deleted straight in the database.
  - An after-hook on `/organization/delete` also disables the tenant, so the tenant list shows it. SPs and key stay for the administrators to remove. The guide points to `organizationHooks.beforeDeleteOrganization` to refuse such deletes instead.
  - `createdAt` is compared to the millisecond, after a round trip through the database; the adapter matrix signs in at tenant URLs on every database, which exercises it. Two organizations created in the same millisecond with the same id would still match; accepted.
- **R6-2 (Low):** deleting a tenant freed its key, and another organization's tenant could take it, with byte-identical entity ID and URLs that the first customer's SPs still trust.
  - **Fix:** keys are single-use. Deleting a tenant first records its key in a new table, `samlIdpRetiredTenantKey` (UNIQUE `tenantKey`, declared at table level for MongoDB), then deletes the row. Creating a tenant with a retired key is 409 `TENANT_KEY_RETIRED`, for any organization, the same one included: the simplest rule that can't be wrong, and a new key is one argument away.
  - The retired table is checked before the insert and again after it (a delete retires before it deletes, so a racing create is undone).
- **R6-3 (Low):** eight refusals naming a tenant SP left `tenantId` out of the `denied` event and the audit row. All now spread `tenantOf(sp)`; root output is unchanged. A lint-style unit test fails if any `fail(ctx, state, …, { spId })` in `src/` lacks it. The proof test's audit-row check was corrected: that refusal comes before the session is read, so it names no user and is never stored (R4-3); it now checks the row the event would make.
- **R6-4 (Medium):** the documented MongoDB upgrade couldn't work. The MongoDB adapter builds a model's indexes before its first write, and the UNIQUE `lookupKey` index can't be built while two documents lack the key, so the backfill's first write failed, and every later write of the registry with it.
  - **Fix:** a new export, `backfillMongoServiceProviderKeys(db, { collection? })`, writes the same keys through the driver (the host's `Db`, as given to `mongodbAdapter`), before tenants are turned on. It also recovers a registry where tenants were turned on first. The adapter exposes no raw collection, so a separate function was the only way; a mongosh script would have duplicated the key derivation.
  - The backfill endpoint no longer stops at the first failed write (see I-1), and names MongoDB's case in the log.
  - Proven against MongoDB 8.2: the review's proof test (both orders) and a new adapter-matrix case, which CI runs.
- **R6-5 (Medium, release):** `pnpm audit --prod` at the workspace root covered the examples' production dependencies (285 packages against the plugin's 17), so an advisory in Next.js would block every PR and the release. pnpm 10's audit has no `--filter`.
  - **Fix:** `scripts/audit-runtime.mjs` audits a copy of the lockfile with only the root importer. `dependencies.yml` and `release.yml` use it. The examples' audit is a separate job with `continue-on-error`: reported, never blocking.
- **R6-6 (Low, docs):** the databases guide's "✅ CI" for Drizzle and Prisma tables was inaccurate: CI creates the tables with Better Auth's migrator and uses Drizzle and Prisma as the query layer. The table and a new section now say so, and list the unique keys to check in a generated schema. A real check needs `npx auth generate`, which isn't a dependency here.
- **R6-7 (Low, example):** the Next.js sign-in page's `acr_values` branch couldn't be reached: without `authnContext.levels`, the IdP answers an unsatisfiable RequestedAuthnContext itself. The branch is removed, as in the Workers example, and the README, CHANGELOG and README roadmap corrected. The proof test now checks the corrected claim (NoAuthnContext without the sign-in page) and that the page has no such branch.
- **R6-8 (Low, docs):** the memory-adapter row is back inside the databases table.

**Info items fixed:**
- **I-1:** the backfill reads the table in pages of 500 (no cap) and reports rows whose write failed in `failed` (logged) instead of stopping. The guide says to drop the old `UNIQUE(entityId)` after the backfill on Postgres and MySQL too.
- **I-3:** a chosen `tenantKey` may not be another organization's id (400 `INVALID_TENANT`).
- **I-4:** a participant's LogoutResponse is matched by its RelayState before the URL's tenant is resolved, so one arriving at a tenant URL disabled since the chain started continues the chain. It's still checked against its own tenant's identity; a disabled one makes it `PartialLogout`.
- **I-5:** the guide says turning tenants off again isn't supported once tenant SPs exist (it fails closed).
- The Next.js README says not to deploy from a directory with the throwaway `.env.local`. The README roadmap no longer suggests Prisma is covered on MySQL. `release.yml` attests the tarball before staging it on npm, so a failed attestation leaves nothing staged. D-049's "13 `runs-on` lines" is now 16 (later jobs, and `examples-audit` here).

**Left open:**
- I-2: tenant administration goes to `logger.info`, not the audit log. That needs a new event type; later.
- Prisma's engines are downloaded at CI time, not pinned by the lockfile.
- The Bun and Deno versions in the runtimes job aren't pinned; acceptable for a smoke test.
- R6-6's real check (tables from generated Drizzle and Prisma schemas) waits until the schema generator can be a dev dependency.

**Tests:** `tenants.test.ts` (organization deleted through Better Auth and straight in the database; serial-id reuse on SQLite; retired keys; a key that is another organization's id; backfill paging and per-row failures; SLO answer at a disabled tenant URL), `sp-directory.test.ts` (the binding, with dates as Date, text and epoch), `identity-lint.test.ts` (R6-3), and the adapter matrix (retired keys on every database; the populated MongoDB upgrade). With tenants off, the snapshots pass unchanged.
- **Full suite:** 146 files passed, 15 skipped; 1350 tests passed, 72 skipped.
- **Adapter matrix, locally:** Postgres 17, MySQL 8.4, Drizzle on both and Prisma on Postgres 11/11 each; MongoDB 8.2 12/12. Every `test/review6/` test passes where it applies: Node and workerd, the SQL upgrade check on Postgres and MySQL, the MongoDB one on MongoDB.

**Mutation proof** (each broken on purpose, a test failed, restored with `git checkout`):
1. the organization's `createdAt` not compared (serial-id reuse; unit test);
2. the organization not checked at all (database delete, serial reuse);
3. no organization-delete hook (the tenant stays listed as enabled);
4. no retired-key checks (both proof and main tests; either check alone suffices);
5. a chosen key equal to another organization's id accepted;
6. one R6-3 site without `tenantOf` (lint test; proof test);
7. the MongoDB backfill writing nothing (matrix and proof);
8. the backfill endpoint throwing at the first failed write (I-1 test; MongoDB proof);
9. the backfill reading one page only;
10. the participant answer requiring an enabled route (I-4 test);
11. the audit script auditing the whole lockfile (285 dependencies instead of 17);
12. the old Next.js page restored (R6-7 check).

## D-054: AWS IAM Identity Center verified live (2026-09-28)

A new AWS organization as the SP, and the deployed Workers example as the IdP, updated to rc.2 first (migration 0008 applied).
- **Setup:** IAM Identity Center enabled as a multi-Region organization instance, primary Region Ohio (the console wouldn't offer N. Virginia as primary), N. Virginia added. Identity source changed to an external IdP with the live metadata (certificate CN "better-auth-saml-idp-example (rotation 3)").
- **Registry:** AWS was registered in the D1 registry from its downloaded dual-stack metadata on the admin page (`sp-from-metadata`):
  - entity ID `https://us-east-2.signin.aws.amazon.com/platform/saml/<directory id>`, one per directory (not `urn:amazon:webservices`, which is AWS IAM's SAML federation);
  - four ACS URLs: `us-east-2` and `us-east-1`, each on `signin.aws` and `sso.signin.aws`. The IPv4-only tab's ACS URL is one of them;
  - `AuthnRequestsSigned="false"`, so there was no request signature to verify; `WantAssertionsSigned="true"`; NameID format `emailAddress`.
- **User:** made with the AWS CLI: an Identity Center user whose username is the demo account's email, a `SamlIdpReadOnly` permission set (`ReadOnlyAccess`, 1-hour sessions) assigned on the account.
- **Checks:**
  - the access portal URL sent the browser to the IdP, and the maintainer landed in the portal with the account listed;
  - the audit log recorded `assertion.issued` for `aws-identity-center`, SP-initiated (`inResponseTo` AWS's request ID), posted to the Ohio `sso.signin.aws` ACS URL, NameID the email, not encrypted;
  - opening the account's permission set reached the AWS console as `SamlIdpReadOnly/<email>`, without another IdP sign-in;
  - signing out of the portal sent nothing to the IdP: Identity Center doesn't do SAML Single Logout with an external IdP.
- **No bugs found.** Traps hit on the way, now in the guide: opening the portal before changing the identity source shows AWS's own sign-in page, and right after the change the settings page shows "External identity provider configuration not available" in the panel for AWS's own details; sign-in worked regardless.

## D-055: Repository clean-up before 1.0.0 (2026-09-28)

The repository kept working material that no longer reflects the project. Everything removed is in git history (tag `v1.0.0-rc.2` has it all).
- **`docs/review/`:** the review reports (reviews 5 and 6), the review brief, the pre-release reviews and the OpenSSF badge notes are removed. Their findings and fixes are recorded here (D-039, D-046, D-048, D-053). The multi-tenant design moves to `docs/design/multi-tenant.md`, with a status note: phase 1 built, phases 2 and 3 not.
- **`test/review2` … `test/review6`:** the proof tests stay as regression tests, in `test/regression/`, named for what they guard (such as `slo-relaystate-limit`, `tenant-key-reuse`). Their test titles keep the finding IDs (R4-1, R6-2 …) that this log refers to.
- **`spike/` and `test/spike/`:** the Phase 0 spike is removed: the patched libxml2-wasm copy that reproduced the workerd blocker (D-003), the bundle-size and coexistence workers, and the samlify round-trip test that the interop tests have long covered. The workerd test host moves to `test/support/worker.ts`. The spike's two dev dependencies stay, because the wasm-validator benchmarks use them.
- **This file:** an index of entries at the top. Entries are unchanged, so references to them (D-0xx) in code and docs still work.

## D-056: 1.0.1, from running on CharDB (2026-09-29)

The plugin 1.0.0, with `tenants: { enabled: true }`, in a [CharDB](https://github.com/zpg6/chardb) app: Better Auth's tables in a Durable Object (CharDB's Catalog) through CharDB's own adapter, on Better Auth 1.7.6 (CharDB itself needed a small upgrade from 1.6, prepared separately).
- **What held.**
  - CharDB's `migrations generate` produced our tables as an additive migration, with every UNIQUE key: the replay key, `spId`, `lookupKey`, the tenant's `organizationId` and `tenantKey`, the retired `tenantKey`.
  - Root metadata was schema-valid; `smoke` passed every check (15), replays and single-use POST re-entry included.
  - A tenant made through the API; a second one for the same organization was refused (`TENANT_EXISTS`).
  - A member's SP-initiated sign-in at the tenant's URL: a signed Response and Assertion with the tenant's entity ID as Issuer. A replay was refused, and SPs were found only through their own IdP's URLs (a tenant SP at the root, and a root SP at the tenant, were both `UNKNOWN_SERVICE_PROVIDER`). A non-member got 403 `ACCESS_DENIED`.
- **Fixed: the types under `exactOptionalPropertyTypes`.**
  - CharDB's starter compiles with it, and `samlIdp()` wasn't assignable to `BetterAuthPlugin`. Our build didn't use the option, so the declarations gave conditionally mounted endpoints `?: Endpoint | undefined`, and `init()` could return `{ options?: undefined }`. `samlIdpClient()` failed the same way, and optional options refused an explicit `undefined`.
  - The package is now compiled with the option. Optional fields of the public types accept `undefined`, and the resolved types use `Defined<T>` in place of `Required<T>` so they stay exact.
  - `test/types/strict-host.ts` is a host with the option, compiled by `pack:check` against `dist/`. 1.0.0's declarations fail it with 5 errors.
  - better-auth-cloudflare 0.3.1's plugin types fail the same way; the one test that passes them straight to `betterAuth` casts.
- **Fixed: the CLI couldn't target a tenant.** `metadataUrl()` kept only URLs ending in `/metadata`, so a tenant's `…/metadata/<tenantKey>` got `/saml2/idp/metadata` appended (a 404). `smoke` derived the auth base from a root SSO URL only. Both now accept a tenant's URLs (the resume route is shared, at the root).
  - Verified against the CharDB tenant: every check passed.
  - `test/cli/cli.test.ts` runs `inspect` and `smoke` against a tenant in-process, and fails on 1.0.0's CLI.

## D-057: 1.0.2, the client plugin under TypeScript 5 (2026-09-29)

Found while checking the published 1.0.1 in a clean app: the strict host (D-056) compiled with TypeScript 5.9 failed on `createAuthClient({ plugins: [samlIdpClient()] })`. It passed with TypeScript 7, which the package is built and checked with, so `pack:check` hadn't seen it.
- **Isolated.** Better Auth 1.7.5 and 1.7.6 behave the same; only the TypeScript version matters. Better Auth's own client plugins (organization, admin, twoFactor, sso) pass under 5.9, so the fault was ours.
- **Cause.** The client plugin is typed with `satisfies BetterAuthClientPlugin`. Its declaration gives `getActions` a `$fetch` of `better-auth/client`'s `BetterFetch`, which TypeScript 5.9 doesn't equate with the core `BetterFetch` in `BetterAuthClientPlugin["getActions"]`.
- **Fix.** The parameters are typed from `Parameters<NonNullable<BetterAuthClientPlugin["getActions"]>>`, so they match under any compiler.
  - Verified in a clean app: Better Auth 1.7.5 and 1.7.6, each with TypeScript 5.9.3 and 7.0.2, zero errors.
- **Guard.** `pack:check` now runs the strict host with TypeScript 5.9 as well (the `typescript-5` dev dependency, `npm:typescript@5.9.3`). With 1.0.1's `dist/` it fails under 5.9 and passes under 7.
- **Lesson.** Type tests of published declarations run on the oldest TypeScript hosts are likely to use, not only on ours.

## D-058: Multi-tenant IdP, phase 2: a signing key per tenant (2026-09-29)

Phase 2 of `docs/design/multi-tenant.md`, opt-in with `tenants.keys: "per-tenant"`.
- **Maintainer decisions:**
  - Keys are encrypted with Better Auth's secret, with an optional `tenants.keyEncryptionSecret`.
  - Generated keys are RSA 3072.
  - Tenants made before keep the shared key until an administrator rotates their first own key in; new tenants get their own key at creation.
  - `minPublishedSeconds` defaults to 24 hours, with an audited `force`.
- **Checked first.**
  - Better Auth 1.7's `symmetricEncrypt` takes a versioned `SecretConfig`, and `ctx.context.secretConfig` gives it to the plugin, so rotating the key-encryption secret is Better Auth's own `secrets` rotation.
  - RSA key generation runs on workerd: `generateKeyPairSync` took about 190 ms and WebCrypto about 120 ms for RSA-2048 in the local runtime.
- **Storage.** A `samlIdpTenantKey` row per key: `next | active | previous | retired`, with a UNIQUE `stateKey` (a hash of tenant and state for next and active), so a tenant has at most one of each on every database.
  - The cipher (XChaCha20-Poly1305) has no associated data. So the sealed plaintext is JSON naming its purpose, tenant and kid, and it must match the row. A ciphertext copied into another tenant's row, or anything else Better Auth encrypts with the same secret, is refused.
  - The limit, documented: it protects backups, dumps and read-only leaks, not a compromised Worker.
- **Signing.** Every signature and metadata document already comes from an `IdpIdentity` (D-052, §5.8). A tenant's identity now gets its signing configuration from `TenantKeyStore`, cached per isolate for `cacheSeconds`, with decrypted keys cached by row.
  - The shared key is used only by a tenant that has never had a key of its own. Once it has had one, a missing or unusable active key throws `TenantKeyError`: sign-in and the tenant SLO URL answer `INTERNAL_ERROR`, metadata a 500, and Single Logout skips that SP (PartialLogout).
  - That also covers the moment inside `activate` between moving the old key aside and promoting the next.
  - The samlify IdP cache is keyed by the certificates too, so a rotated key gets a fresh IdP.
- **Rotation**, the three steps of D-019 per tenant:
  - `rotate` publishes a next key, generated or uploaded, with the pair checked;
  - `activate` promotes it after `minPublishedSeconds`, or with `force`, which is recorded. For a tenant's first own key, the shared certificate is kept published in a `previous` row with kid `"shared"` and no private key. An older previous is retired;
  - `retire` stops publishing the previous and erases its private key;
  - deleting a tenant deletes its keys;
  - the routes exist only with per-tenant keys, under the manager with `update` (`read` to list) on `samlTenant`.
- **Review 6 I-2.** A new `tenant.changed` event (`events.onTenantChanged`) goes into the audit log for tenant create, enable, disable and delete, and key rotate, activate (with `forced`) and retire, with the acting user.
- **Tests.** `test/integration/tenant-keys.test.ts` runs on Node and workerd, 15 tests each. It covers:
  - the round trip, and a swapped or foreign ciphertext refused;
  - RSA 3072;
  - own keys verifying and the shared or another tenant's not;
  - the full rotation;
  - the wait and `force`, and uploads;
  - access;
  - a damaged key, a copied key and an activation cut short all refusing;
  - moving from the shared key;
  - secret rotation through `secrets`, and `keyEncryptionSecret`;
  - deletion;
  - the per-isolate cache.

  The adapter matrix gains concurrent rotations: exactly one of five wins through the UNIQUE `stateKey`. It passed on Postgres, MySQL, MongoDB 8.2, Drizzle on Postgres and MySQL, and Prisma on Postgres.
- **Mutation proof.** Each of these, removed in turn, fails at least one test:
  - the tenant and kid binding;
  - the never-fall-back rule;
  - the `minPublishedSeconds` guard;
  - the tenant identity using its own key;
  - keeping the shared certificate published;
  - erasing a retired key.
- **Not in this phase:** delegation (phase 3), and keys outside the database (a KMS/HSM callback, deferred until a host needs it). Live CPU on a deployed Worker is still to measure.

## D-059: Multi-tenant IdP, phase 3: delegated administration (2026-09-29)

Phase 3 of `docs/design/multi-tenant.md` (§5.4), opt-in with `tenants.delegation`, allowed only with `keys: "per-tenant"` (startup enforces it: under a shared key only the Issuer tells tenants apart, §5.1). The design's defaults were taken as they stood: roles `owner` and `admin`, user fields `email`, `name` and `id`, and no `metadata.url`.
- **Who.** One `access()` check serves every registry route.
  - A host manager (`canManage` and/or `permissions`, both when both are set) may do everything.
  - Otherwise, with `delegated` routes, the user's memberships are read from the member table on every request (`loadMemberships`, never the session's active organization), and each one holding a delegation role in an **enabled** tenant (the directory's check, D-053) adds that tenant to the actor's scope. No tenant means 403.
  - The existing rules hold for both: the user is re-read (R4-L3), not banned, and impersonation is refused. A demotion therefore takes effect at the next request.
  - `manager()` stays for host-only routes: tenant create, update and delete, and keys.
- **Scope, per route** (§5.4's list):
  - **list:** filtered by `tenantId` in the query (required with several tenants; another tenant's, or the root's, is 403).
  - **get, update and delete:** load the row and compare its tenant. Otherwise it's 404, so another tenant's SP, or the root's, looks absent, because `spId` is global.
  - **create:** needs `tenant` in scope (403).
  - `tenant` stays immutable (D-052).
  - A tenant's administrator may read its own tenant record and certificate list; everything else under `/tenants` is 403.
- **Config limits** (400 `INVALID_SERVICE_PROVIDER`, with `issues`):
  - attribute sources (a string or `{ field }`) and `nameId.field` only from `userFields`; otherwise a tenant administrator could export any user column for their members;
  - `metadata` only with `allowMetadataUrl`: D-029 accepted server-side fetches to internal hosts only because the registry was admin-only.
  - ACS and SLO URLs are navigated by the browser, not fetched, so they aren't limited.
- **No leaks.**
  - Overlap warnings (D-052) are computed only for host managers: they name another tenant's SP.
  - `SERVICE_PROVIDER_EXISTS` on create still tells a tenant administrator that an `id` is taken somewhere. That's accepted: `id` is a global name, it reveals nothing about the SP, and the alternative (tenant-prefixed ids) would burden everyone.
- **Auditing** (§5.5).
  - A `service-provider.changed` event (`events.onServiceProviderChanged`, and the audit log) for each registry create, update, enable, disable and delete, with the acting user and `delegated`. Until now registry changes only went to `logger.info`.
  - `GET /saml-idp/audit` reads the log newest first, paged with `before`, filtered by `tenantId` in the query. Tenant administrators see only their tenants'.
  - The route list with every feature on gains that one route; its snapshot was updated for exactly that line.
- **Mounting.** The registry API is mounted with delegation alone, for tenant administrators only.
- **Tests.** `test/integration/tenant-delegation.test.ts`: 16 on Node, 15 on workerd (the cross-tenant-warning test needs one entity ID in two tenants, which the D1 test schema's `UNIQUE(entityId)` refuses; Node covers it). They cover:
  - list scoping, and IDOR on get, update and delete for another tenant's SP and the root's, with nothing changed;
  - create outside the tenant, and the immutable tenant;
  - disallowed fields as attributes and as NameID, allowed fields and constants, and a widened allow-list;
  - `metadata.url` refused and then allowed;
  - no cross-tenant warning;
  - a plain member refused, a demotion, a disabled tenant, impersonation, and custom roles;
  - tenant and key routes staying host-only, with read access to its own tenant;
  - the startup error without per-tenant keys, and delegation-only mounting;
  - the audit view scoped by tenant;
  - a delegated SP's sign-in signed under the tenant's own key.
- **Mutation proof.** Each of 12 gates, removed in turn, fails at least one test:
  - scope on get, update, delete, list, tenant read and audit;
  - the delegated config check, the field allow-list and the metadata-URL refusal;
  - the role check, and the enabled-tenant check;
  - the warning suppression.
- **Before release:** reviewed in D-060 (review 7).

## D-060: Review 7, phases 2 and 3 before release (2026-09-29)

The design (§8) asks for a review of phases 2 and 3 before they ship. Done in the open, reading the diff since 1.0.2 adversarially: key handling first, then the delegation boundary. Six findings, each fixed with a test that failed first (the failure matching the finding), on Node and workerd.
- **R7-5 (High): delegation of a tenant still on the shared key.** Per-tenant keys leave tenants made before them on the shared key until rotated (D-058). `access()` counted any enabled tenant, so such a tenant's administrator could register an SP with a root SP's entity ID and ACS URL and get assertions signed with the root key: the §5.1 attack that delegation was meant to wait for.
  - Fix: a tenant counts only when it has an active key of its own.
  - Test: an owner of a keyless tenant gets 403, then 200 once the host rotates and activates its first key.
- **R7-4 (High): cross-organization disclosure through `only`.** Organization attributes get all of the user's memberships, and `only` selects among them by id or slug, so a delegated SP with `{ organization: "slugs", only: [otherOrg] }` told its administrator which members also belong to another organization.
  - Fix: delegated SPs can't use `only`. Without it, a tenant SP's scope is the tenant (phase 1).
  - Host managers keep it.
- **R7-1 (Medium): unbounded key rows, bounded reads.** Every rotation left a retired row, while the store read at most 50 rows unsorted, the admin routes 100, and the list a global cap. After enough rotations the active row could fall outside the read, and the never-fall-back rule would then refuse every sign-in.
  - Fix: `activate` and `retire` keep only the five newest retired rows (the audit log keeps the history), and reads are newest first, so a tenant has at most nine rows.
  - Tested with 8 rotations, and in the adapter matrix with 7 rotations and a retire on every database.
- **R7-2 (Low): no expiry warning for tenant certificates** (the design's phase 2 list had one).
  - Fix: tenant records carry `warnings` for their own certificates that expire within 30 days or have expired, and loading such a key logs it once per isolate.
- **R7-3 (Low): the tenant list read every key row with a global cap.** Tenants past the cap could show no keys and `signing: "shared"`.
  - Fix: filtered with `tenantId in (…)` in the query.
  - Test: 160 unrelated rows written first.
- **R7-6 (Low): a tenant-existence oracle.** A delegated create naming an organization got 400 "no tenant" before the scope check, and 403 for a tenant.
  - Fix: the scope check runs first, and every organization outside the actor's tenants gets the same 403.
- **Checked and fine:**
  - the never-fall-back rule across `activate`'s intermediate states;
  - key-cache keying by row;
  - the ciphertext binding and its purpose label;
  - the IdP cache keyed by certificates;
  - SLO skipping an SP whose key can't load;
  - tenant metadata refusing rather than publishing another key;
  - the audit route's session middleware and tenant filter;
  - host-only tenant routes;
  - ACS and SLO URLs set by tenant administrators, which are browser-navigated, not fetched.
- **Accepted:**
  - switching the host back to `keys: "shared"` makes every tenant sign with the shared key again. That's a deliberate host configuration, and delegation is then a startup error;
  - a host can upload the same key pair for two tenants, or the root's. That's host-only, and its own choice.
- The full suite (1,415 tests) and the adapter matrix on Postgres, MySQL, MongoDB 8.2, Drizzle on Postgres and MySQL, and Prisma on Postgres passed.

## D-061: Review 8, a fresh look before 1.1.0 (2026-09-29)

Before tagging 1.1.0: first a check for new advisories and alerts, then a fresh read of the diff since 1.0.2 (phases 2 and 3 and the review 7 fixes).

**Advisories and alerts:**
- No new Better Auth advisory since July; 1.7.6 (2026-09-24) isn't a security release. The shipped XML dependencies are on the patched `@xmldom/xmldom` (0.9.12 and 0.8.15; GHSA-c7q8-3ch8-vqpv and its two siblings, 2026-09-08). No open Dependabot alerts.
- OSV-Scanner: undici 7.29.0 (GHSA-3wwx-pv8p-q78v, moderate), development only, under `@cloudflare/vitest-pool-workers` through miniflare, which pins it exactly even in its newest release. Fix: a pnpm override to 7.29.1.
- CodeQL: four polynomial-regex alerts on `/\/+$/` in `src/index.ts` and `src/saml/idp.ts`, the pattern D-037 replaced in the client. The inputs are configuration and Better Auth's own base URL (a Host header has no `/`), so this is tidiness: one loop helper, `src/url.ts`, now trims trailing slashes everywhere.

**Findings:**
- **R8-1 (Medium): `IN (…)` lookups over D1's 100 bound parameters.** D1 refuses a statement with more than 100 bound parameters ("too many SQL variables"; miniflare enforces the same). Two lookups put every id in one `IN`:
  - the tenant list's key rows (R7-3's fix): `GET /saml-idp/tenants` failed with per-tenant keys and 100 or more tenants;
  - a user's organizations (`loadMemberships`, since D-031): sign-in to an SP with organization attributes, and every delegated registry request, failed for a user in 100 or more organizations.
  - Fix: `findManyIn` reads in batches of 50, with the exact-match filter (R4-L8).
  - Test: 120 tenants, and a user in 120 organizations, on Node and workerd (D1); both failed on workerd first.
- **R8-2 (Low): a tenant certificate's CN could exceed 64 characters.** It is `saml-idp tenant <tenantKey>`, and a tenant key may be 64 characters: up to 80, past RFC 5280's ub-common-name, which strict X.509 parsers enforce.
  - Fix: the CN is cut to 64 characters (`selfSignedCertificate`, so the CLI's `keygen` too).
  - Test: a 64-character tenant key's certificate.
- **R8-3 (Low): `rotate` generated an RSA 3072 key before checking for an existing next key,** so a refused rotation still spent the CPU (hundreds of milliseconds, more on Workers).
  - Fix: the check comes first.
- **Checked and fine:**
  - `hostManager` with neither `canManage` nor `permissions` (delegation alone) is false, not true;
  - every caller of a tenant's identity handles an unusable key (SSO, SLO, metadata, issuance);
  - `activate` and `rotate` racing each other: the UNIQUE state slots decide, and no intermediate state falls back to the shared key;
  - the tenant delete removes its key rows after retiring its tenant key;
  - uploaded keys: RSA of at least 2048 bits, matching the certificate, encrypted PEM refused.
- **Info, not changed:** a tenant's audit view shows `denied` rows for users outside its organization who were sent to its SSO URL (their user id, IP address and user agent). The request came to the tenant's own IdP, and the rows hold opaque ids, no email.
- The full suite (1,421 tests) passed.
- **Live CPU for per-tenant keys** (the design asked for it; measured after 1.1.0 on the demo Worker with `wrangler tail`, one sample): a rotation that generates an RSA 3072 key took 488 ms of CPU (1.2 s wall); an activation 43 ms; activations refused by `minPublishedSeconds` 24 ms; the tenant list 22 ms. Key generation runs only when a tenant is created or a key rotated, never on sign-in: fine on Workers Paid, over the Free plan's 10 ms. RSA generation time varies with the prime search.

## D-062: RelayState cap 4096, for Cloudflare Access (2026-10-02)

A new deployment's first Cloudflare Access sign-in failed with `RELAY_STATE_TOO_LONG`. Cloudflare's RelayState is now 1069 bytes: a hex digest, then base64 of URL-encoded JSON holding the auth domain, nonce, attempt, replay and SAML ids. It was about 200 bytes when D-016 tested it, and the cap since then has been 1024 (D-016's reasoning: the spec's 80 is too small for real SPs).

- **Fix:** the default and hard cap `relayStateMaxBytes` is now 4096. RelayState is opaque to us, length-checked, and always HTML-escaped where it's echoed. The real limit on its size is the URL's, and at 4096 there's still room for a Redirect-binding URL under common 8 KB limits. Hosts that want the spec's 80 can still set it.
- **Test:** a 1069-byte RelayState shaped like Cloudflare's is accepted by default. The test fails with the old cap, and the over-the-cap and smoke checks now use 4097 bytes.
- **Impact:** every Cloudflare Access sign-in through 1.1.0 or earlier fails, so this is a patch release.
- **Lesson:** an SP's opaque values drift. Live checks against real SPs belong in the regular routine, not only at first integration.
