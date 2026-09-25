export const isWorkerd = typeof navigator !== "undefined" && navigator.userAgent === "Cloudflare-Workers";

/**
 * Loads wasm/xsd.wasm through the plugin's own shipped loaders, so these tests
 * exercise exactly what the package ships:
 *  - workerd: src/saml/wasm/load.workerd.ts (static .wasm import -> precompiled WebAssembly.Module)
 *  - Node:    src/saml/wasm/load.node.ts (reads the bytes from disk)
 */
export async function loadWasm(): Promise<WebAssembly.Module | Uint8Array<ArrayBuffer>> {
  const m = isWorkerd
    ? await import("../../src/saml/wasm/load.workerd")
    : await import("../../src/saml/wasm/load.node");
  // load.node.ts copies the file into a fresh (non-shared) ArrayBuffer.
  return (await m.loadXsdWasm()) as WebAssembly.Module | Uint8Array<ArrayBuffer>;
}
