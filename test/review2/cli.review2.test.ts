// Second adversarial review: CLI proofs of concept (Node only).
import { mkdtempSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { run } from "../../src/cli/main";
import { isWorkerd } from "../support/host";

describe("review2 cli", () => {
  it.skipIf(isWorkerd)("R2-CLI-1: keygen --force writes the private key with mode 0600 even over an existing world-readable file", async () => {
    const dir = mkdtempSync(join(tmpdir(), "saml-r2-"));
    const key = join(dir, "idp.key");
    const cert = join(dir, "idp.crt");
    writeFileSync(key, "placeholder", { mode: 0o644 }); // e.g. left over from a previous run / touch
    const r = await run(["keygen", "--cert-out", cert, "--key-out", key, "--force"]);
    expect(r.code).toBe(0);
    expect(r.stderr + r.stdout).toContain("mode 0600"); // what the tool tells the user
    expect((statSync(key).mode & 0o777).toString(8), "private key left group/world-readable").toBe("600");
  });
});
