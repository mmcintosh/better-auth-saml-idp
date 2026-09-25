// workerd / wrangler: bundlers turn this import into a precompiled WebAssembly.Module,
// which is the only way Workers can instantiate wasm (no runtime code generation).
import xsdWasm from "../../../wasm/xsd.wasm";

export async function loadXsdWasm(): Promise<WebAssembly.Module | Uint8Array> {
  return xsdWasm;
}
