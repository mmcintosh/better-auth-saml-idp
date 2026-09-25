// R3-6: D-023 / --help: "keygen writes the key to --key-out with mode 0600". writeFileSync's
// `mode` only applies when the file is created. With --force onto an existing file the previous
// mode is kept, so a private key can land in a world-readable file.
import { mkdtempSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { isWorkerd } from "../support/host";

describe("CLI keygen: private key file mode", () => {
  it.skipIf(isWorkerd)("--force onto an existing world-readable file still ends with mode 0600", async () => {
    const { keygen } = await import("../../src/cli/keygen");
    const dir = mkdtempSync(join(tmpdir(), "r3-keygen-"));
    const keyOut = join(dir, "idp.key");
    const certOut = join(dir, "idp.crt");
    writeFileSync(keyOut, "old", { mode: 0o644 });
    keygen({ commonName: "t", days: 1, bits: 2048, keyOut, certOut, force: true });
    expect(statSync(keyOut).mode & 0o777).toBe(0o600);
  });
});
