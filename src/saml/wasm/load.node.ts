// Node: read the bytes from the package; they are compiled once per validator.
export async function loadXsdWasm(): Promise<WebAssembly.Module | Uint8Array> {
  const { readFile } = await import("node:fs/promises");
  return new Uint8Array(await readFile(new URL("../../../wasm/xsd.wasm", import.meta.url)));
}
