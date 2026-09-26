// Adds libxml2, compiled into wasm/xsd.wasm, to a CycloneDX SBOM. No scanner can see inside the
// wasm, yet it is the component whose CVEs matter most. Version and source hash come from the
// build script, so they can't drift from what was built.
//   node scripts/sbom-add-libxml2.mjs <sbom.cdx.json>
import { readFileSync, writeFileSync } from "node:fs";

const file = process.argv[2];
if (!file) throw new Error("usage: sbom-add-libxml2.mjs <sbom.cdx.json>");
const build = readFileSync(new URL("../wasm-validator/build-in-container.sh", import.meta.url), "utf8");
const get = (name) => {
  const m = new RegExp(`^${name}=(\\S+)$`, "m").exec(build);
  if (!m) throw new Error(`${name} not found in wasm-validator/build-in-container.sh`);
  return m[1];
};
const version = get("LIBXML2_VERSION");
const sha256 = get("LIBXML2_SHA256");
const [major, minor] = version.split(".");
const url = `https://download.gnome.org/sources/libxml2/${major}.${minor}/libxml2-${version}.tar.xz`;

const sbom = JSON.parse(readFileSync(file, "utf8"));
// Drop the scratch project the tarball was installed into (and its lockfile), which aren't
// part of the package, then (re)add libxml2.
sbom.components = (sbom.components ?? []).filter((c) => c.name !== "libxml2" && c.name !== "sbom-root" && !c.name.startsWith("/"));
sbom.components.push({
  type: "library",
  "bom-ref": `pkg:generic/libxml2@${version}`,
  name: "libxml2",
  version,
  description: "Compiled to WebAssembly in wasm/xsd.wasm (XSD validation); built from source by wasm-validator/.",
  licenses: [{ license: { id: "MIT" } }],
  purl: `pkg:generic/libxml2@${version}?download_url=${encodeURIComponent(url)}`,
  cpe: `cpe:2.3:a:xmlsoft:libxml2:${version}:*:*:*:*:*:*:*`,
  externalReferences: [{ type: "distribution", url, hashes: [{ alg: "SHA-256", content: sha256 }] }],
});
writeFileSync(file, `${JSON.stringify(sbom, null, 2)}\n`);
console.log(`added libxml2 ${version} to ${file}`);
