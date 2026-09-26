# Review brief: third review (whole project)

This is the brief for an independent review of **better-auth-saml-idp** ahead of its 1.0 release. It's written for a reviewer with no prior context, human or model. It's public on purpose: the threat model and past findings are public too, and anyone is welcome to use it.

**Baseline:** tag `review-3-baseline`. Findings refer to that commit.

## What this is

A [Better Auth](https://www.better-auth.com) plugin that makes a Better Auth server a **SAML 2.0 Identity Provider**. Users who signed in with Better Auth get signed SAML assertions for third-party service providers (SPs), such as Okta, Auth0 and Cloudflare Access, verified live. It runs on Node and Cloudflare Workers.

An IdP asserts identity to other systems, so its bugs are other systems' breaches. The review should be adversarial.

## Trust boundaries

| Input | Who controls it | Reaches |
|---|---|---|
| `/saml2/idp/sso`, `/slo` (GET and POST), `/init`, `/resume` | **Anyone** (unauthenticated, cross-site) | `src/endpoints/{sso,slo,init,resume}.ts`, then `src/saml/*` |
| The browser session (cookies) | The user, and other sites through the browser | The same endpoints, and `/saml2/idp/logout` |
| An SP's metadata URL | **The SP operator**, or whoever compromises that host | `src/saml/sp-metadata-refresh.ts` |
| Registry API (`/saml2/idp/service-providers/*`) | Admins (by `canManage` or admin-plugin permissions) | `src/endpoints/registry.ts`, `src/access.ts` |
| User records (name, email, additional fields) | Users, partly (their own profile) | Issuance: `src/endpoints/issue.ts`, `src/attributes.ts`, `src/saml/response.ts` |
| Plugin options, the database, the Better Auth secret | The host (trusted) | Everywhere |

## Code map

| Path | Role |
|---|---|
| `src/index.ts` | Plugin assembly: endpoints, schema, `init` (database hooks), exports |
| `src/options.ts`, `src/types.ts` | Option validation (zod) and resolution; public types |
| `src/endpoints/sso.ts` | SP-initiated SSO: both bindings, the POST re-entry, validation, then sign-in or issuance |
| `src/endpoints/resume.ts` | Resuming a parked request after sign-in (single-use, browser-bound) |
| `src/endpoints/init.ts` | IdP-initiated SSO (opt-in per SP) |
| `src/endpoints/issue.ts` | Issuance: re-reads, account policy, organizations, `authorize`, NameID, attributes, signing; `fail()` |
| `src/endpoints/slo.ts` | Single Logout, both directions, and the logout chain |
| `src/endpoints/registry.ts`, `src/access.ts` | The SP registry API and its permissions |
| `src/events.ts` | Observability callbacks and the audit log |
| `src/saml/request.ts` | Inbound decoding, limits, Redirect query parsing, AuthnRequest parsing, signature policy |
| `src/saml/xml.ts` | Strict parsing (the linear pre-scan, then xmldom) |
| `src/saml/xmldsig.ts` | The enveloped-signature verifier with XSW defences |
| `src/saml/response.ts`, `encrypt.ts`, `logout.ts` | Building, signing and encrypting outbound messages |
| `src/saml/validator.ts`, `src/saml/wasm/` | XSD validation (libxml2 compiled to WebAssembly) |
| `src/saml/sp-metadata*.ts`, `sp-directory.ts`, `sp-registry.ts` | SP metadata import and refresh; code and stored SPs |
| `src/storage/*` | Pending requests, replay keys, logout participants, the expiry sweep |
| `src/cli/*` | `npx better-auth-saml-idp`: inspect, decode, request, smoke, keygen, … |

## Already reviewed: build on it, don't repeat it

- **Two earlier reviews:** [DECISIONS.md](../../DECISIONS.md) D-029 and D-030. They list every finding and fix, and everything tried and rejected: XSW variants, XPath injection through the Reference URI, comment truncation, Redirect signature octet tricks, `returnTo` open redirects, logout-state forgery, registry bypass and mass assignment, prototype pollution, XML injection, CSRF.
- **Regression tests:** `test/review2/` and `test/review3/`.
- **Fuzzing** (D-036) and **CodeQL** (D-037) have run since.

A new angle on an old area is welcome. Please say what's new about it.

## Changed since the last review: look here first

| Decision | What changed | Files |
|---|---|---|
| D-031 | Organization-scoped SPs and organization attributes; registry permissions through the admin plugin's access control | `organizations.ts`, `access.ts`, `endpoints/issue.ts`, `endpoints/registry.ts` |
| D-032 | Background work through `runInBackground` / `waitUntil` | `saml/sp-metadata-refresh.ts` |
| D-033 | Named table-level unique indexes (replay protection on MongoDB) | `schema.ts` |
| D-035 | `ProtocolBinding=HTTP-Redirect` tolerated and answered over POST | `saml/request.ts` |
| D-036 | Characters XML can't carry are removed from attribute values, line endings normalised, such NameIDs refused | `saml/response.ts`, `endpoints/issue.ts` |
| D-037 | The strict-parse pre-scan rewritten as a linear, depth-limited scanner | `saml/xml.ts` |
| D-038 | Event callbacks and an audit-log table; `fail()` emits `denied` | `events.ts`, every endpoint |

## Questions we'd most like answered

1. **Scanner vs parsers (D-037).** Can the new scanner and xmldom (0.9 in the plugin, 0.8 inside xml-crypto) or libxml2 disagree about a document's attributes or structure in a way that matters? Examples: an attribute the scanner doesn't see, a duplicate expanded name that slips through, a construct it skips that a parser reads.
2. **What SPs read vs what we signed (D-036).** Can any user-controlled field produce an assertion that an SP reads differently from what we signed, or that one SP accepts and another rejects? Think of any character, any length, and attribute values versus the NameID.
3. **Organizations and permissions (D-031).** Role matching (comma lists, whitespace, case), organization lookups by slug or id, failing closed without the plugin, `permissions` combined with `canManage`, `adminUserIds`, impersonation.
4. **Observability (D-038).**
   - Can events or audit rows leak secrets (session tokens, keys, Better Auth secrets), or carry log injection (User-Agent, detail)?
   - Can someone grow the audit table without being an SP or a user?
   - Can a handler affect the flow?
5. **Replay and single use under concurrency,** on every adapter (`test/adapters/`), including MongoDB (D-033).
6. **Metadata refresh (D-026/D-032):** stuck refreshes, cache keys, what a hostile metadata host can make the IdP do.
7. **Anything that makes the docs wrong.** Claims in the README and `docs/guide/` ("verified", "tested", "mutation-checked", numbers and limits) that the code or tests don't back up.

## The whole project, beyond security

We'd also value a verdict on:
- **API design:** the options, events, error codes, client plugin and exports. What will we regret after 1.0 makes them hard to change? See [Versioning and support](../guide/versioning.md).
- **Tests:** do they test what their names claim? Are there tests that can't fail?
- **Docs:** could a Better Auth user set this up from the [guide](../guide/README.md) alone?
- **Maintainability:** dead code, duplication, surprising coupling.
- **CI and supply chain:** workflow permissions and injection (`.github/workflows/`), the release path ([release.yml](../../.github/workflows/release.yml)), and what ships in the package (`pnpm pack`).

## How to run it

See [CONTRIBUTING.md](../../CONTRIBUTING.md#checks). In short:

```sh
pnpm install
pnpm test            # Node and workerd (D1)
pnpm test:wasm       # the validator
FUZZ_RUNS=3000 npx vitest run --project node test/fuzz
```

## Rules

- **Isolation:** work on your own branch or worktree from `review-3-baseline`, and don't change `src/`.
- **Proof per finding:**
  - Each security or correctness finding comes with a **failing test** in `test/review4/` that passes once fixed.
  - Docs, API and CI findings may be written up instead.
- **No real secrets or live systems:** use the keys the tests generate. Don't touch live SPs or the example deployment.
- **Record what you tried and rejected,** so the next review can build on it.

## Deliverable

A list of findings. For each:

| Field | Content |
|---|---|
| ID | `R4-<n>` |
| Severity | Critical / High / Medium / Low / Info, and why: who can do what to whom |
| Where | File and line at the baseline |
| Finding | What's wrong, in two or three sentences |
| Proof | The test file, or exact steps |
| Suggested fix | Optional |

Then a **tried and rejected** list, and the answers to the project questions above.
