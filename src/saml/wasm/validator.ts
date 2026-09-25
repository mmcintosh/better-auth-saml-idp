// Minimal hand-written loader for wasm/xsd.wasm (libxml2 + wasm-validator/c/xsdv.c, built with
// -sSTANDALONE_WASM). No emscripten JS glue, no eval, no runtime wasm codegen,
// no addFunction/table growth: the module is instantiated once from a
// precompiled WebAssembly.Module (workerd) or from bytes (Node), with a handful
// of WASI imports implemented below.
import { SCHEMAS } from "../schemas.generated";
import type { SchemaKind, SchemaValidationResult, SchemaValidator } from "../validator";

/** Schema set entry points. Slot numbers are the `kind` argument of xv_compile/xv_validate. */
const ENTRY: Record<SchemaKind, { slot: number; file: string }> = {
  protocol: { slot: 0, file: "saml-schema-protocol-2.0.xsd" },
  metadata: { slot: 1, file: "saml-schema-metadata-2.0.xsd" },
};

/** The exact import set of wasm/xsd.wasm. Anything else is a build regression. */
export const EXPECTED_IMPORTS = [
  "env.emscripten_notify_memory_growth",
  "wasi_snapshot_preview1.clock_time_get",
  "wasi_snapshot_preview1.fd_close",
  "wasi_snapshot_preview1.fd_read",
  "wasi_snapshot_preview1.fd_seek",
  "wasi_snapshot_preview1.fd_write",
  "wasi_snapshot_preview1.random_get",
] as const;

interface Exports {
  memory: WebAssembly.Memory;
  _initialize(): void;
  xv_malloc(n: number): number;
  xv_free(p: number): void;
  xv_errors_ptr(): number;
  xv_errors_len(): number;
  xv_errors_count(): number;
  xv_errors_dropped(): number;
  xv_heap_used(): number;
  xv_register_file(name: number, nameLen: number, data: number, dataLen: number): number;
  xv_compile(kind: number, entry: number, entryLen: number): number;
  xv_validate(kind: number, xml: number, xmlLen: number): number;
}

export interface WasmValidatorStats {
  /** Bytes written to stdout/stderr by the wasm module (should always be 0). */
  stdioBytes: number;
  /** Current linear memory size in bytes. */
  memoryBytes: number;
  /** Bytes currently allocated by malloc inside the module. */
  heapUsed: number;
  /** Number of times the instance was (re)created. */
  instantiations: number;
}

export interface WasmValidator extends SchemaValidator {
  /** Instantiate and compile the given schema sets (default: both) now instead of on first use. */
  ready(kinds?: SchemaKind[]): Promise<void>;
  stats(): WasmValidatorStats;
}

const WASI_EBADF = 8;
const enc = new TextEncoder();
const dec = new TextDecoder();

type Instance = { x: Exports; compiled: Set<SchemaKind> };

export function createWasmValidator(
  wasm: WebAssembly.Module | BufferSource,
  schemas: Record<string, string> = SCHEMAS,
): WasmValidator {
  let modulePromise: Promise<WebAssembly.Module> | undefined;
  let current: Promise<Instance> | undefined;
  let stdioBytes = 0;
  let instantiations = 0;
  let live: Instance | undefined;

  // A failed compile is not cached: the next call retries.
  const getModule = () => {
    if (!modulePromise) {
      const p = wasm instanceof WebAssembly.Module ? Promise.resolve(wasm) : WebAssembly.compile(wasm);
      modulePromise = p;
      p.catch(() => { if (modulePromise === p) modulePromise = undefined; });
    }
    return modulePromise;
  };

  async function instantiate(): Promise<Instance> {
    const mod = await getModule();
    let mem: WebAssembly.Memory | undefined;
    const u8 = () => new Uint8Array(mem!.buffer);
    const dv = () => new DataView(mem!.buffer);
    const imports = {
      env: {
        emscripten_notify_memory_growth: (_index: number) => {},
      },
      wasi_snapshot_preview1: {
        clock_time_get: (_id: number, _precision: bigint, out: number) => {
          dv().setBigUint64(out, BigInt(Date.now()) * 1_000_000n, true);
          return 0;
        },
        random_get: (ptr: number, len: number) => {
          for (let off = 0; off < len; off += 65536)
            crypto.getRandomValues(u8().subarray(ptr + off, ptr + Math.min(len, off + 65536)));
          return 0;
        },
        fd_write: (_fd: number, iovs: number, iovsLen: number, nwritten: number) => {
          // Never forwarded anywhere; counted so tests can assert it stays 0.
          const view = dv();
          let n = 0;
          for (let i = 0; i < iovsLen; i++) n += view.getUint32(iovs + i * 8 + 4, true);
          stdioBytes += n;
          view.setUint32(nwritten, n, true);
          return 0;
        },
        fd_read: () => WASI_EBADF,
        fd_seek: () => WASI_EBADF,
        fd_close: () => WASI_EBADF,
      },
    };
    const instance = await WebAssembly.instantiate(mod, imports);
    const x = instance.exports as unknown as Exports;
    mem = x.memory;
    x._initialize();
    instantiations++;

    const inst: Instance = { x, compiled: new Set() };
    for (const [name, text] of Object.entries(schemas)) {
      withBytes(x, enc.encode(name), (np, nl) =>
        withBytes(x, enc.encode(text), (dp, dl) => {
          if (x.xv_register_file(np, nl, dp, dl) !== 0) throw new Error(`xsd.wasm: cannot register ${name}`);
        }),
      );
    }
    live = inst;
    return inst;
  }

  // Each schema set is compiled on first use (once per instance), so a Worker
  // that only validates protocol messages never pays for the metadata set.
  function compile(inst: Instance, kind: SchemaKind) {
    if (inst.compiled.has(kind)) return;
    const { x } = inst;
    const { slot, file } = ENTRY[kind];
    withBytes(x, enc.encode(file), (p, l) => {
      if (x.xv_compile(slot, p, l) !== 0)
        throw new Error(`xsd.wasm: compiling ${kind} schemas failed: ${readErrors(x).join("; ")}`);
    });
    inst.compiled.add(kind);
  }

  function getInstance(): Promise<Instance> {
    if (!current) {
      current = instantiate();
      current.catch(() => { current = undefined; });
    }
    return current;
  }

  return {
    async ready(kinds: SchemaKind[] = ["protocol", "metadata"]) {
      const inst = await getInstance();
      for (const k of kinds) compile(inst, k);
    },
    stats() {
      return {
        stdioBytes,
        instantiations,
        memoryBytes: live ? live.x.memory.buffer.byteLength : 0,
        heapUsed: live ? live.x.xv_heap_used() : 0,
      };
    },
    async validate(xml: string, kind: SchemaKind): Promise<SchemaValidationResult> {
      const entry = Object.hasOwn(ENTRY, kind) ? ENTRY[kind] : undefined;
      if (!entry) return { valid: false, errors: [`unknown schema kind: ${String(kind)}`] };
      if (typeof xml !== "string") return { valid: false, errors: ["input is not a string"] };
      const inst = await getInstance();
      const { x } = inst;
      compile(inst, kind); // throws (rejects) if the bundled schemas do not compile
      let rc: number;
      try {
        rc = withBytes(x, enc.encode(xml), (p, l) => x.xv_validate(entry.slot, p, l));
      } catch (e) {
        // A trap leaves the instance in an unknown state: drop it, fail closed.
        current = undefined;
        live = undefined;
        return { valid: false, errors: [`validator internal error: ${String(e)}`] };
      }
      if (rc === 0) return { valid: true };
      const errors = readErrors(x);
      return { valid: false, errors: errors.length ? errors : ["document is not schema-valid"] };
    },
  };
}

function withBytes<T>(x: Exports, bytes: Uint8Array, fn: (ptr: number, len: number) => T): T {
  const ptr = x.xv_malloc(Math.max(bytes.length, 1));
  if (ptr === 0) throw new Error("xsd.wasm: out of memory");
  try {
    new Uint8Array(x.memory.buffer, ptr, bytes.length).set(bytes);
    return fn(ptr, bytes.length);
  } finally {
    x.xv_free(ptr);
  }
}

function readErrors(x: Exports): string[] {
  const len = x.xv_errors_len();
  if (len === 0) return [];
  const raw = new Uint8Array(x.memory.buffer, x.xv_errors_ptr(), len);
  const out = dec.decode(raw).split("\0").filter((s) => s.length > 0);
  const dropped = x.xv_errors_dropped();
  if (dropped > 0) out.push(`(${dropped} more errors omitted)`);
  return out;
}
