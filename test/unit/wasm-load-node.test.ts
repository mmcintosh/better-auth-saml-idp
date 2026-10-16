import { describe, expect, it } from "vitest";
import { loadXsdWasm, readXsdWasm } from "../../src/saml/wasm/load.node";
import { isWorkerd } from "../support/host";

// What Turbopack hands the loader when Next.js bundles the plugin: an object on URL's prototype
// with an empty protocol and a relative href (its relativeURL helper defines them the same way).
function turbopackUrl(path: string): URL {
  const url = Object.create(URL.prototype);
  for (const [key, value] of Object.entries({ href: path, pathname: path, protocol: "", origin: "", toString: () => path })) {
    Object.defineProperty(url, key, { enumerable: true, configurable: true, value });
  }
  return url;
}

// The Node loader reads from the file system, which workerd doesn't have (it imports the module).
describe.skipIf(isWorkerd)("Node wasm loader", () => {
  it("reads the validator from the package", async () => {
    const bytes = (await loadXsdWasm()) as Uint8Array;
    expect([...bytes.subarray(0, 4)]).toEqual([0x00, 0x61, 0x73, 0x6d]); // "\0asm"
  });

  it("says what to do when a bundler rewrote the URL", async () => {
    await expect(readXsdWasm(turbopackUrl("/_next/static/media/xsd.3qqees7z7q6jq.wasm"))).rejects.toThrow(
      /serverExternalPackages: \["better-auth-saml-idp"\]/,
    );
  });
});
