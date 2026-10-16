// Node: read the bytes from the package; they are compiled once per validator.
export async function loadXsdWasm(): Promise<WebAssembly.Module | Uint8Array> {
  return readXsdWasm(new URL("../../../wasm/xsd.wasm", import.meta.url));
}

// A bundler that rewrites the URL above leaves something Node can't read: Next.js with Turbopack
// turns it into a relative web path (/_next/static/media/…) when the plugin is bundled. Say what to
// do, instead of a TypeError on every SAML request.
export async function readXsdWasm(url: URL): Promise<Uint8Array> {
  if (url.protocol !== "file:") {
    throw new Error(
      `better-auth-saml-idp: can't read its XSD validator (wasm/xsd.wasm) from "${String(url)}": the package was bundled. ` +
        `Leave it out of the server bundle; in Next.js, add serverExternalPackages: ["better-auth-saml-idp"] to next.config.`,
    );
  }
  const { readFile } = await import("node:fs/promises");
  return new Uint8Array(await readFile(url));
}
