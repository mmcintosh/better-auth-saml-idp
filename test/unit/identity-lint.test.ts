// Multi-tenant IdP (D-052, design §5.8): everything the IdP signs or advertises comes from an
// IdpIdentity. A source file reading the root entity ID or the signing key directly would issue a
// tenant's message under the root identity (or the wrong key), so only the module that builds
// identities may. Option resolution and the CLI (a developer tool that reports the configuration)
// read them for their own purposes. Node only: it reads the source tree.
import { readdirSync, readFileSync } from "node:fs";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { isWorkerd } from "../support/host";

const SRC = fileURLToPath(new URL("../../src", import.meta.url));
// sp-metadata.ts: its own `options.entityId` picks an SP out of an EntitiesDescriptor.
const ALLOWED = new Set(["saml/identity.ts", "options.ts", "saml/sp-metadata.ts"]);
/** The root entity ID, or the signing key (anything under `signing` but the request-checking and default-parts settings). */
const HARD_WIRED = /\boptions\.entityId\b|\boptions\.signing\b(?!\.(?:allowInsecureSha1|sign)\b)/;

function sources(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((e) => {
    const path = join(dir, e.name);
    if (e.isDirectory()) return sources(path);
    return e.name.endsWith(".ts") && !e.name.endsWith(".d.ts") ? [path] : [];
  });
}

describe.skipIf(isWorkerd)("IdpIdentity is the only source of the IdP's entity ID and signing key", () => {
  it("the pattern catches what it should, and nothing it shouldn't", () => {
    for (const bad of ["issuer: state.options.entityId", "sign(xml, options.signing)", "options.signing.keyObject", "options.signing.privateKey"]) expect(bad).toMatch(HARD_WIRED);
    for (const ok of ["options.signing.allowInsecureSha1", "parts = options.signing.sign", "identity.signing", "sp.entityId", "config.entityId"]) expect(ok).not.toMatch(HARD_WIRED);
  });

  it("no source file outside identity.ts (and option resolution, and the CLI) reads them", () => {
    const offenders = sources(SRC)
      .map((path) => relative(SRC, path).split("\\").join("/"))
      .filter((rel) => !ALLOWED.has(rel) && !rel.startsWith("cli/"))
      .flatMap((rel) =>
        readFileSync(join(SRC, rel), "utf8")
          .split("\n")
          .flatMap((line, i) => (HARD_WIRED.test(line) ? [`${rel}:${i + 1}: ${line.trim()}`] : [])),
      );
    expect(offenders).toEqual([]);
  });
});

// Review 6 R6-3 (D-053): a refusal that names an SP also names its tenant, so its `denied` event and
// audit row aren't read as the root IdP's. Every `fail(ctx, state, …, { spId: … })` spreads tenantOf.
const FAIL_WITH_SP = /\bfail\(ctx, state,[^;]*?\{ spId:([^}]*)\}/g;

describe.skipIf(isWorkerd)("refusals naming an SP carry its tenant", () => {
  it("the pattern finds a call with spId and no tenantOf, and accepts one with it", () => {
    const bad = 'return fail(ctx, state, "X", `SP ${sp.id}`, { spId: sp.id });';
    const good = 'return fail(ctx, state, "X", `SP ${sp.id}`, { spId: sp.id, ...tenantOf(sp) });';
    expect([...bad.matchAll(FAIL_WITH_SP)].filter((m) => !m[1]!.includes("tenantOf"))).toHaveLength(1);
    expect([...good.matchAll(FAIL_WITH_SP)].filter((m) => !m[1]!.includes("tenantOf"))).toHaveLength(0);
  });

  it("every such call in src/ spreads tenantOf", () => {
    const offenders = sources(SRC).flatMap((path) =>
      [...readFileSync(path, "utf8").matchAll(FAIL_WITH_SP)].filter((m) => !m[1]!.includes("tenantOf")).map((m) => `${relative(SRC, path)}: ${m[0]}`),
    );
    expect(offenders).toEqual([]);
  });
});
