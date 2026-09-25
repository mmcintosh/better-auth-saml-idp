// Build the published package: ESM JavaScript bundled per entry point (dependencies stay
// external), plus .d.ts files from tsc. Output: dist/.
//
// The `#xsd-wasm` subpath import stays external and is resolved by the consumer's runtime or
// bundler through package.json "imports" (workerd -> precompiled module, else read from disk).
// Both loaders reference ../../../wasm/xsd.wasm, i.e. the package's wasm/ directory.
import { execFileSync } from "node:child_process";
import { readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { build } from "esbuild";

const root = new URL("..", import.meta.url).pathname;
const dist = join(root, "dist");
rmSync(dist, { recursive: true, force: true });

await build({
  absWorkingDir: root,
  entryPoints: ["src/index.ts", "src/client.ts", "src/cli/bin.ts", "src/saml/wasm/load.node.ts", "src/saml/wasm/load.workerd.ts"],
  outbase: "src",
  outdir: "dist",
  bundle: true,
  splitting: true,
  format: "esm",
  platform: "neutral",
  target: "es2022",
  packages: "external",
  external: ["#xsd-wasm", "*.wasm", "node:*"],
  chunkNames: "chunks/[name]-[hash]",
  sourcemap: true,
  legalComments: "inline",
  logLevel: "warning",
});

execFileSync("npx", ["tsc", "-p", "tsconfig.build.json"], { cwd: root, stdio: "inherit" });

// Sources use extensionless relative imports (moduleResolution "Bundler"). Consumers on
// "NodeNext" need explicit extensions in declaration files, so add them.
const walk = (d) => readdirSync(d).flatMap((f) => (statSync(join(d, f)).isDirectory() ? walk(join(d, f)) : [join(d, f)]));
for (const file of walk(dist).filter((f) => f.endsWith(".d.ts"))) {
  const src = readFileSync(file, "utf8");
  const out = src.replace(/(from\s+|import\()(["'])(\.{1,2}\/[^"']+)\2/g, (m, pre, q, spec) => {
    if (/\.(js|mjs|cjs|json|wasm)$/.test(spec)) return m;
    const base = join(dirname(file), spec);
    const target = (() => {
      try {
        if (statSync(base).isDirectory()) return `${spec}/index.js`;
      } catch {}
      return `${spec}.js`;
    })();
    return `${pre}${q}${target}${q}`;
  });
  if (out !== src) writeFileSync(file, out);
}
console.log("built dist/");
