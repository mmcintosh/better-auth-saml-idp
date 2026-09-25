/** Which XSD a document is validated against. */
export type SchemaKind = "protocol" | "metadata";

export type SchemaValidationResult = { valid: true } | { valid: false; errors: string[] };

/**
 * Pluggable XSD validator. The plugin calls it explicitly on every inbound SAML
 * message; it does not rely on samlify's process-global validator (DECISIONS.md D-006).
 */
export interface SchemaValidator {
  validate(xml: string, kind: SchemaKind): Promise<SchemaValidationResult>;
}

/** Checks that apply before any XML reaches a parser, whatever the engine. */
export function precheckXml(xml: string, maxBytes: number): string[] {
  const errors: string[] = [];
  if (new TextEncoder().encode(xml).byteLength > maxBytes) errors.push(`document exceeds ${maxBytes} bytes`);
  // SAML messages never need a DTD; refusing it outright removes entity-expansion and
  // XXE classes of attack regardless of how the parser is configured.
  if (/<!DOCTYPE/i.test(xml)) errors.push("DOCTYPE is not allowed");
  if (/<!ENTITY/i.test(xml)) errors.push("ENTITY declarations are not allowed");
  return errors;
}

export interface Libxml2ValidatorOptions {
  /** Reject documents larger than this before parsing. Default 128 KiB. */
  maxBytes?: number;
  /**
   * The compiled `xsd.wasm` (a `WebAssembly.Module`) or its bytes. By default it is
   * loaded from this package: a bundled module on Workers, read from disk on Node.
   */
  wasm?: WebAssembly.Module | Uint8Array;
}

/**
 * Default validator: libxml2 2.15 compiled to a standalone wasm module (`wasm-validator/`),
 * with the SAML 2.0 XSDs from `schemas/`. Runs on Node and Cloudflare Workers
 * (DECISIONS.md D-009).
 */
export function libxml2Validator(options: Libxml2ValidatorOptions = {}): SchemaValidator {
  const maxBytes = options.maxBytes ?? 128 * 1024;
  let inner: Promise<SchemaValidator> | undefined;
  const load = () =>
    (inner ??= (async () => {
      const [{ createWasmValidator }, wasm] = await Promise.all([
        import("./wasm/validator"),
        options.wasm ?? import("#xsd-wasm").then((m) => m.loadXsdWasm()),
      ]);
      return createWasmValidator(wasm as WebAssembly.Module | BufferSource);
    })().catch((e) => {
      inner = undefined; // let the next call retry a failed load
      throw e;
    }));

  return {
    async validate(xml, kind) {
      const pre = precheckXml(xml, maxBytes);
      if (pre.length) return { valid: false, errors: pre };
      return (await load()).validate(xml, kind);
    },
  };
}

let shared: SchemaValidator | undefined;

/**
 * The process/isolate-wide default validator. Hosts that build `betterAuth()` per request
 * (common on Workers) would otherwise re-instantiate the wasm and recompile the schemas on
 * every request.
 */
export function defaultSchemaValidator(): SchemaValidator {
  return (shared ??= libxml2Validator());
}
