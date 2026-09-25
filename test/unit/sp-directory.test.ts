import { describe, expect, it } from "vitest";
import { resolveOptions } from "../../src/options";
import { SpDirectory } from "../../src/saml/sp-directory";
import { baseOptions } from "../support/config";

const log = { error: () => {} };
const row = { id: "r1", spId: "s", entityId: "https://sp.example/md", config: JSON.stringify({ id: "s", entityId: "https://sp.example/md", acsUrls: ["https://sp.example/acs"] }), enabled: true, createdAt: new Date(), updatedAt: new Date() };

describe("SpDirectory lookups", () => {
  it("only returns a stored SP for exactly the requested value (case-insensitive / PAD SPACE collations)", async () => {
    const options = resolveOptions(baseOptions({ serviceProviders: [], registry: { enabled: true, cacheSeconds: 0 } }));
    // An adapter that matches case-insensitively and ignores trailing spaces, like some MySQL collations.
    const adapter = { findOne: async (a: any) => (String(a.where[0].value).trim().toLowerCase() === row.entityId.toLowerCase() || a.where[0].value === "s" ? row : null) };
    const dir = new SpDirectory([], options);
    expect(await dir.byEntityId(adapter, "https://sp.example/md", log)).toMatchObject({ id: "s" });
    expect(await dir.byEntityId(adapter, "HTTPS://SP.EXAMPLE/MD", log)).toBeUndefined();
    expect(await dir.byEntityId(adapter, "https://sp.example/md ", log)).toBeUndefined();
  });
});
