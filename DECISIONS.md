# DECISIONS

A running log of the non-obvious choices, with the options considered and the evidence behind each one (SPEC §11).

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
| 3 | AWS IAM Identity Center | Pending; needs a sandbox AWS account. Guide: `docs/sp-aws-iam-identity-center.md` |
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
`{"email":"mmcintosh@infowall.ai","name":"Mark McIntosh","givenName":"Mark","surName":"McIntosh","saml_attributes":{"email":"mmcintosh@infowall.ai"}}`.
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
- **Docs.** `docs/better-auth/saml-idp.mdx` follows Better Auth's plugin-page format (Steps, `package-install`, migrate/generate tabs). `docs/better-auth/community-plugin-entry.ts` is the proposed entry for their Community Plugins list, which currently has no SAML plugin. It hasn't been submitted.

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

