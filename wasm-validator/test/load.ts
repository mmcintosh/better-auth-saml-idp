export const isWorkerd = typeof navigator !== "undefined" && navigator.userAgent === "Cloudflare-Workers";

/** workerd: the precompiled module from a static import; Node: raw bytes from disk. */
export async function loadWasm(): Promise<WebAssembly.Module | Uint8Array<ArrayBuffer>> {
  if (isWorkerd) return (await import("../dist/xsd.wasm")).default as WebAssembly.Module;
  const { readFile } = await import("node:fs/promises");
  return new Uint8Array(await readFile(new URL("../dist/xsd.wasm", import.meta.url)));
}
