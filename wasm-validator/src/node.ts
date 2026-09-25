// Node convenience entry: reads dist/xsd.wasm from disk and compiles it.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { createWasmValidator, type WasmValidator } from "./index";

export * from "./index";

export const WASM_PATH = fileURLToPath(new URL("../dist/xsd.wasm", import.meta.url));

export function createNodeWasmValidator(schemas?: Record<string, string>): WasmValidator {
  return createWasmValidator(readFileSync(WASM_PATH), schemas);
}
