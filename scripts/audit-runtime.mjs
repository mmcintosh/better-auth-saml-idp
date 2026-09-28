// Audits what `npm install better-auth-saml-idp` brings in: the package's production dependencies,
// at the versions pinned in pnpm-lock.yaml, and nothing else (review 6 R6-5, D-053).
//   node scripts/audit-runtime.mjs [pnpm audit options, e.g. --audit-level low]
//
// At the root of this workspace, `pnpm audit --prod` also covers the examples' production
// dependencies (Next.js, Hono, …), and pnpm 10's audit has no --filter. So this copies
// package.json and the lockfile, keeping only the root importer ("."), into a temporary directory
// and audits there. The examples are audited separately, without blocking (dependencies.yml).
import { spawnSync } from "node:child_process";
import { copyFileSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

/** The lockfile with every importer but the root removed (their packages are then unreachable). */
export function rootImporterOnly(lockfile) {
  const out = [];
  let inImporters = false;
  let skipping = false;
  for (const line of lockfile.split("\n")) {
    if (/^\S/.test(line)) {
      inImporters = line === "importers:";
      skipping = false;
    } else if (inImporters && /^ {2}\S/.test(line)) {
      skipping = line !== "  .:";
    }
    if (!(inImporters && skipping)) out.push(line);
  }
  return out.join("\n");
}

const dir = mkdtempSync(join(tmpdir(), "saml-idp-audit-"));
try {
  const lockfile = readFileSync("pnpm-lock.yaml", "utf8");
  if (!lockfile.includes("\nimporters:\n")) throw new Error("pnpm-lock.yaml has no importers section: has the lockfile format changed?");
  copyFileSync("package.json", join(dir, "package.json"));
  writeFileSync(join(dir, "pnpm-lock.yaml"), rootImporterOnly(lockfile));
  const result = spawnSync("pnpm", ["audit", "--prod", ...process.argv.slice(2)], { cwd: dir, stdio: "inherit" });
  process.exitCode = result.status ?? 1;
} finally {
  rmSync(dir, { recursive: true, force: true });
}
