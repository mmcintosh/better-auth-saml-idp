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
- The build is reproducible: two builds gave the same wasm sha256, `d116cf5d…7750`.

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
- **Signed AuthnRequests.** HTTP-Redirect only, verified over the raw query octets (`SAMLRequest`, `RelayState`, `SigAlg`, as received) using `node:crypto` and the SP certificate. This has no XML-signature surface and so no XSW exposure. **POST-binding signed requests aren't supported in v1:** an SP that requires signing and posts is rejected with `UNSIGNED_SAML_REQUEST`. This matches SPEC §9's stretch list. SHA-1 `SigAlg` is refused unless `allowInsecureSha1` is set.
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
| 3 | Cloudflare Access, AWS IAM Identity Center | **Pending, needs the owner's accounts.** Guides: `docs/sp-cloudflare-access.md`, `docs/sp-aws-iam-identity-center.md` |
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
