# xsd.wasm: libxml2 XML Schema validator for Node and Cloudflare Workers

This is a minimal XSD validator. It is libxml2 compiled to a standalone
WebAssembly module, with a small hand-written TypeScript loader. It is the
follow-up to DECISIONS.md D-003: a replacement for `node-xmllint` that runs
on workerd without runtime code generation.

There is exactly one loader and one binary, and both ship in the package:

- `../src/saml/wasm/validator.ts`: the loader (`createWasmValidator`).
- `../wasm/xsd.wasm` (+ `xsd.wasm.sha256`): the binary. `build.sh` writes it there directly.

This directory holds only the build inputs (`c/xsdv.c`, build scripts), the
test suite and the benchmarks. The tests and benchmarks import the shipped
loader and load the shipped binary through the plugin's own
`src/saml/wasm/load.node.ts` / `load.workerd.ts`, so they can't drift from
what's published.

```ts
import wasmModule from "../wasm/xsd.wasm";                          // workerd: precompiled WebAssembly.Module
import { createWasmValidator } from "../src/saml/wasm/validator";
const validator = createWasmValidator(wasmModule);                 // Node: pass the bytes (see load.node.ts)
await validator.validate(xml, "protocol");                         // { valid: true } | { valid: false, errors: string[] }
```

## Pinned inputs

| Input | Version / pin |
|---|---|
| libxml2 | **2.15.4**: `https://download.gnome.org/sources/libxml2/2.15/libxml2-2.15.4.tar.xz`, sha256 `98087fd181d9070724f3fbc65c7377db03038eb92bd882374daff44940138821` (checked in `build-in-container.sh`) |
| Toolchain | `emscripten/emsdk:6.0.10@sha256:e077d54e2b8970575ebc4f185ac1de0b95c05f2b266134d4ba27449af7aebf65` |
| Schemas | `../src/saml/schemas.generated.ts` (`SCHEMAS`), passed in from JS when the module is instantiated |
| Output | `../wasm/xsd.wasm`, 404,861 bytes, sha256 in `../wasm/xsd.wasm.sha256` (a test checks the two agree) |

The build is reproducible. Two consecutive `./build.sh` runs produced
byte-identical output, sha256
`cfef04b645a346fddb73bacb730e2644519fa97db868f8a8848aa4e153960103`.

## Build

```sh
wasm-validator/build.sh    # docker + network (the tarball is cached in wasm-validator/.cache/)
```

`build.sh` runs `build-in-container.sh` in the pinned image. That script does
four things:

1. Downloads the tarball and verifies its sha256.
2. Builds libxml2 as a static library with `emcmake cmake -Oz -flto`, turning
   off everything validation doesn't need. The following are all **OFF**: HTTP,
   threads (and thread alloc/TLS), iconv, ICU, ISO8859X, zlib, HTML, catalog,
   XInclude, modules, legacy, debug, C14N, XPath, XPointer, Schematron,
   RelaxNG, reader, writer, push, SAX1, DTD validation, output (serialization),
   Python, programs, tests and docs. Only schemas, pattern and regexps are
   **ON**. lzma no longer exists in 2.15. `HAVE_DECL_GETENTROPY=1` is forced
   because CMake's check fails under emscripten. Without it, libxml2 seeds its
   hash tables from `time()` instead of `getentropy()`.
3. Links `c/xsdv.c` with `--no-entry -sSTANDALONE_WASM -sFILESYSTEM=0
   -sSUPPORT_LONGJMP=0 -sALLOW_TABLE_GROWTH=0 -sALLOW_MEMORY_GROWTH=1
   -sINITIAL_MEMORY=4MB -sSTACK_SIZE=1MB`.
4. Writes `../wasm/xsd.wasm` (mounted into the container as `/out`) and its
   sha256. There is no other output location.

Consumers don't need Docker because `wasm/xsd.wasm` is checked in.

## Design

**No emscripten JS glue.** The module is a WASI reactor. Its complete import
list is below, and a test asserts it matches exactly:

| Import | Implementation in `src/saml/wasm/validator.ts` |
|---|---|
| `wasi.random_get` | `crypto.getRandomValues`, used for libxml2's hash seed. It runs lazily inside the first `validate()`, never at global scope. |
| `wasi.clock_time_get` | `Date.now()` |
| `wasi.fd_write` | Discarded, but the bytes are counted (`stats().stdioBytes`, which the tests assert is 0) |
| `wasi.fd_read`, `fd_seek`, `fd_close` | Return `EBADF` |
| `env.emscripten_notify_memory_growth` | No-op. Views are re-created from `memory.buffer` on every access. |

The loader calls `WebAssembly.instantiate(module, imports)` once per validator
and then `_initialize()`. On Node, a `BufferSource` goes through
`WebAssembly.compile` first. A failed compile is not cached: the next call
retries. There is no `eval`, `new Function`, `addFunction`,
table growth or worker thread anywhere.

**No callbacks into JS.** Every function pointer given to libxml2 is a C
function in `c/xsdv.c`: the error collector, the resource loaders, the I/O
callbacks and the DOCTYPE SAX hook. The wasm table is therefore fixed at link
time.

**Schema resolution happens entirely in C, from an in-memory registry.**
- JS calls `xv_register_file(name, data)` once for each entry in `SCHEMAS`.
- `xv_compile(kind, entry)` compiles a set with `xmlSchemaNewParserCtxt(entry)`
  and `xmlSchemaSetResourceLoader(registry_loader)`.
- In `ensure_init()`, libxml2's default file I/O callbacks are removed
  (`xmlCleanupInputCallbacks`), and registry-only callbacks are installed with
  `xmlRegisterInputCallbacks`. This step is needed because of a libxml2 2.15.4
  bug (see Open issues).
- Any name that isn't in the registry fails, whether it's `http://…`,
  `file:///etc/passwd`, `/etc/passwd` or a relative path. A test covers this.

**Each schema set is compiled once per instance and reused.** There are two
sets: `protocol` (entry `saml-schema-protocol-2.0.xsd`) and `metadata` (entry
`saml-schema-metadata-2.0.xsd`). Each set compiles lazily on its first use,
or eagerly through `ready()`.

**Instance documents** are parsed with `xmlCtxtReadMemory(..., "UTF-8",
XML_PARSE_NONET | XML_PARSE_NO_XXE | XML_PARSE_NOERROR | XML_PARSE_NOWARNING |
XML_PARSE_NOCDATA)`. Three settings apply:
- NOENT, DTDLOAD and DTDATTR are not set.
- A deny-all resource loader is set on the parser context.
- UTF-8 is forced because JS has already decoded the string, so a stale
  `encoding=` declaration can't cause mis-decoding.

A document must be both well-formed (`ctxt->wellFormed`) and
namespace-well-formed (`ctxt->nsWellFormed`). libxml2 only clears
`nsWellFormed` for namespace errors (unbound prefix, the same expanded
attribute name via two prefixes, `xml`/`xmlns` prefix misuse, `xmlns:p=""`)
and still returns a tree, so without this check such a document could pass
schema validation inside a lax wildcard.

DOCTYPE is rejected in C in two ways:
1. A SAX `internalSubset` hook calls `xmlStopParser` as soon as
   `<!DOCTYPE name …` is read, before any internal subset is parsed.
2. After parsing, the tree is checked for `intSubset`, `extSubset` or any
   `XML_DTD_NODE`.

Either way the result is `["DOCTYPE is not allowed"]`.

**Errors** come from libxml2's structured errors. They are collected into a
16 KB static C buffer (at most 32 messages, then a "(N more errors omitted)"
line) as NUL-separated `line N: message` strings. They are never printed.

**Traps** fail closed. If the wasm traps, `validate()` returns `{ valid: false,
errors: ["validator internal error: …"] }` and the next call gets a fresh
instance.

## Files

| Path | What |
|---|---|
| `c/xsdv.c` | C glue: registry, resolvers, error collection, DOCTYPE rejection, exports |
| `build.sh`, `build-in-container.sh` | Reproducible Docker build |
| `../wasm/xsd.wasm` (+ `.sha256`) | Built module, checked in, shipped in the package. The only copy. |
| `../src/saml/wasm/validator.ts` | The loader, shipped in the package. Exports `createWasmValidator(wasm, schemas = SCHEMAS)`, the interface types, and `EXPECTED_IMPORTS`. |
| `../src/saml/wasm/load.node.ts`, `load.workerd.ts` | Shipped binary loaders (`#xsd-wasm`), also used by the tests |
| `test/validator.test.ts`, `test/load.ts` | Vitest suite, run under Node and workerd against the shipped loader and binary |
| `vitest.config.ts`, `wrangler.jsonc` | Test config. Reuses `../test/support/global-setup.ts` for keys. |
| `bench/run.sh`, `bench/worker.ts` | workerd benchmark (`wrangler dev`, timed with curl from outside) |
| `bench/node-bench.sh`, `bench/node-bench.ts` | Node benchmark |
| `bench/minimal*.ts` | Minimal workers for `wrangler deploy --dry-run` size numbers |

## Tests

```sh
pnpm test:wasm                                                     # from the repo root
npx tsc -p wasm-validator                                          # typecheck: clean
```

Results (vitest 4.1.11, @cloudflare/vitest-pool-workers 0.22.0, workerd 1.20260923.1):

```
 Test Files  2 passed (2)
      Tests  83 passed | 3 skipped (86)
node:    42 passed, 1 skipped (the workerd-only "codegen is forbidden here" check)
workerd: 41 passed, 2 skipped (the Node-only sha256-file and compile-retry checks)
[node]    800 validations: heapUsed 816256 -> 816256 B, linear memory 4194304 -> 4194304 B, stdio bytes 0
[workerd] 800 validations: heapUsed 816256 -> 816256 B, linear memory 4194304 -> 4194304 B, stdio bytes 0
```

The suite is mutation-checked against the shipped files: removing
`x.xv_free(ptr)` from `src/saml/wasm/validator.ts` fails the leak test in both
runtimes (heapUsed 954200 -> 1114840 B), and removing the compile-failure
reset fails the compile-retry test.

What the suite covers, identically in both runtimes:

- **Module shape**
  - The exact import set.
  - (Node) `wasm/xsd.wasm` hashes to the value in `wasm/xsd.wasm.sha256`.
  - (Node) A failed `WebAssembly.compile` isn't cached; the next call
    retries and succeeds.
  - Invalid wasm bytes reject on every call, with no instance created.
  - Under workerd, a check that `WebAssembly.compile` of even an empty module
    throws "Wasm code generation disallowed by embedder". This proves every
    other test ran with codegen forbidden.
  - Concurrent first calls share one instance.
  - Schema imports resolve only from the registry: http, file, absolute and
    relative paths all fail, and a registered name resolves.
  - Prototype keys (`toString`) are rejected as kinds.
- **Protocol schema**
  - A valid AuthnRequest is accepted.
  - A single schema error (bad `xs:dateTime`) gives exactly one message.
  - An unexpected child element is rejected.
  - A missing required `ID` is rejected.
  - An invalid `xs:ID` is rejected.
  - The wrong schema kind is rejected in both directions.
  - An unknown kind is rejected.
  - A document declaring `ISO-8859-1` that contains non-ASCII characters is
    accepted (UTF-8 is forced).
- **Non-well-formed input**: empty string, plain text, truncated document,
  mismatched tag, unbound prefix, two roots, NUL byte.
- **Namespace well-formedness**: inside `samlp:Extensions` (a lax `##other`
  wildcard, so the schema alone would accept them): an unbound attribute
  prefix, `a:x` and `b:x` with the same namespace URI, `xmlns:xml` bound to a
  wrong URI, a declared `xmlns:xmlns`, and `xmlns:p=""` are all rejected. A
  well-formed control document is accepted. All five were accepted before the
  `nsWellFormed` check was added.
- **DOCTYPE and entities**: internal entity, XXE `SYSTEM file:///etc/passwd`,
  billion laughs, parameter entity, external DTD and bare DOCTYPE all return
  `["DOCTYPE is not allowed"]`. Also covered:
  - An undeclared entity is rejected.
  - An `xsi:schemaLocation` hint is ignored.
  - 5,000-deep nesting is rejected without a trap, and the same instance keeps
    working.
- **samlify interop**
  - The validator is plugged into `samlify.setSchemaValidator`, so the IdP
    validates the AuthnRequest with it.
  - A samlify-signed Response is accepted, and a strict SP parses it.
  - A Bogus-child variant is rejected.
  - IdP and SP metadata are accepted on `metadata` and rejected on `protocol`.
- **Leaks**: 200 rounds of 4 validations each (valid, schema-invalid,
  malformed, DOCTYPE). malloc'd bytes, linear memory size and stdio output are
  all unchanged.

## Benchmarks

The input is the same 290-byte AuthnRequest used in `spike/validator-bench.ts`.
In the tables, "xmllint" means `@authenio/samlify-node-xmllint` 2.0.0
(node-xmllint 1.0.0). Both validators ran in the same run.

### workerd (`wrangler dev` 4.139.0, local), timed by curl from outside

`wasm-validator/bench/run.sh 3`. Each round starts a fresh `wrangler dev`, so
each isolate is fresh. The steps are:

1. One noop request.
2. The first validation (cold): instantiate the module, register the schemas,
   compile the protocol set.
3. A second request.
4. One request that runs 200 validations (warm). Its time minus a noop request
   is divided by 200.

| | Cold first call, net of noop (3 rounds) | 2nd request (total) | Warm, per validation |
|---|---|---|---|
| **xsd.wasm** | 41.7 / 55.0 / 41.2 ms | 4.3 / 5.5 / 5.1 ms | **0.087 / 0.073 / 0.099 ms** |
| xmllint | 720 / 1921 / 828 ms | 209 / 657 / 161 ms | 65.5 / 68.3 / 94.7 ms |

An earlier run, which compiled both schema sets eagerly on the first call,
measured 63–76 ms cold and 0.08–0.15 ms warm. The xmllint numbers in that run
were in the same range as above.

### Node 24.12.0

`wasm-validator/bench/node-bench.sh` runs 3 processes. The machine was shared
with other work, so there is noise between runs.

| | `WebAssembly.compile` | Cold first call (instantiate + register + compile protocol + validate) | Warm, per validation |
|---|---|---|---|
| **xsd.wasm**, final build (lazy compile, load avg ≈ 6.5) | 1.7–1.9 ms | **29–35 ms** | **0.034–0.053 ms** (n=2000) |
| xmllint, same run | – | 339–360 ms | 21.6–26.1 ms (n=50) |
| **xsd.wasm**, busier machine (load avg > 10) | 5.7–9.4 ms | 58–136 ms | 0.09–0.16 ms |
| xmllint, same run | – | 853–1162 ms | 62–79 ms |

Warm validation is roughly 400–700× faster than xmllint. The cold call is
roughly 10–15× faster.

## Sizes

| | Raw | gzip -9 |
|---|---|---|
| `wasm/xsd.wasm` | 404,861 B (395 KiB) | 157,460 B (154 KiB) |
| Minimal worker using it: `wrangler deploy --dry-run --config wasm-validator/bench/minimal.wrangler.jsonc`, which includes the 76 KB JS bundle with the SAML schemas | 469.74 KiB | **169.02 KiB** |
| The same minimal worker with node-xmllint (`bench/minimal-xmllint.wrangler.jsonc`) | 9662.13 KiB | 1028.84 KiB |

## Open issues

1. **Cold start is about 40–55 ms of CPU on workerd.** Almost all of it is
   libxml2 compiling the protocol schema set. The metadata set is compiled
   separately and only when first used. On the Workers Free plan (10 ms CPU)
   that first request per isolate would still exceed the limit. Warm requests
   are far below it. libxml2 can't serialize a compiled `xmlSchema`, so the
   only ways to cut this are:
   - Trim the schemas, for example by dropping the xenc and metadata imports
     from the protocol set.
   - Snapshot linear memory after compilation at build time: embed the
     post-`xv_compile` heap as a data segment (Wizer-style). That's feasible
     but not done here.
2. **libxml2 2.15.4 bug.** `xmlSchemaParseNewDoc()` (xmlschemas.c ~9925)
   creates a nested parser context for each imported schema but doesn't copy
   `resourceLoader`/`resourceCtxt`. As a result, `<import>`s inside imported
   schemas bypass `xmlSchemaSetResourceLoader`. Two things cover this here:
   the global input callbacks are replaced with registry-only ones, and the
   default file callbacks are removed. It's worth reporting upstream. The
   registry test would catch any regression.
3. **No input size cap** inside the validator. The caller, the plugin, should
   limit request body size. Memory can grow: `ALLOW_MEMORY_GROWTH`, starting at
   4 MB. Each instance keeps its peak.
4. **The trap path isn't exercised by a test.** No input tried here makes
   libxml2 trap. Deep nesting hits libxml2's depth limit and returns an error.
5. **Error text includes element names and values from the input**, for
   example `'yesterday' is not a valid value…`. Per SPEC §7 logging rules the
   plugin should route it through its logger and not echo it to clients
   verbatim.
6. The build downloads the tarball from download.gnome.org. It's cached in
   `.cache/` and its sha256 is verified. The emsdk image is pinned by digest.
7. The Sizes and Benchmarks numbers were measured on the build before the
   `nsWellFormed` check (404,849 B). The check adds 12 bytes and doesn't
   change the hot path, so they weren't re-run.
